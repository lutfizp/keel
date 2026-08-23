from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator

from keel.adapters.base import CommandResult
from keel.errors import AdapterFailed

_PROJECTDISCOVERY = {"httpx", "nuclei"}
_REQUIRED_FLAGS = {
    "httpx": {
        "-json",
        "-silent",
        "-timeout",
        "-threads",
        "-retries",
        "-rate-limit",
        "-delay",
        "-response-size-to-read",
        "-response-size-to-save",
        "-config",
        "-auth",
        "-no-color",
    },
    "nuclei": {
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-disable-update-check",
        "-disable-unsigned-templates",
        "-no-interactsh",
        "-disable-redirects",
        "-auth",
        "-config",
        "-type",
        "-exclude-tags",
        "-concurrency",
        "-bulk-size",
        "-payload-concurrency",
        "-probe-concurrency",
        "-retries",
        "-timeout",
        "-max-host-error",
        "-response-size-read",
        "-response-size-save",
        "-severity",
        "-rate-limit",
        "-rate-limit-duration",
        "-template-id",
        "-project",
        "-project-path",
    },
}
_RETRY_AFTER = re.compile(r"(?i)retry[- ]after\s*[:=]?\s*(\d+(?:\.\d+)?)")
_THROTTLE = re.compile(
    r"(?i)(too many requests|rate[- ]?limit(?:ed|ing)?|http(?:/\S+)?\s+429|"
    r"status(?:_code)?[\"']?\s*[:=]\s*429)"
)
_NETWORK_ENV_KEYS = {
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "PROJECTDISCOVERY_API_KEY",
}


@contextmanager
def isolated_scanner_config() -> Iterator[Path]:
    """Yield an empty config so user-global scanner settings cannot widen a wave."""
    with tempfile.TemporaryDirectory(prefix="keel-scanner-") as directory:
        path = Path(directory) / "config.yaml"
        path.write_text("{}\n", encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
        yield path


def _candidate_executables(binary: str) -> list[Path]:
    candidates: list[Path] = []
    seen: set[Path] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        found = shutil.which(binary, path=directory)
        if not found:
            continue
        candidate = Path(found).resolve()
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _is_projectdiscovery(candidate: Path, binary: str) -> bool:
    try:
        completed = subprocess.run(
            [str(candidate), "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    markers = {
        "httpx": ("projectdiscovery.io", "current version:"),
        "nuclei": ("nuclei engine version:",),
    }
    return all(marker in output for marker in markers[binary])


def resolve_projectdiscovery(binary: str) -> str:
    if binary not in _PROJECTDISCOVERY:
        raise AdapterFailed(f"unsupported ProjectDiscovery binary: {binary}")

    env_name = f"KEEL_{binary.upper()}_BIN"
    configured = os.environ.get(env_name)
    if configured:
        found = shutil.which(configured)
        candidate = Path(found or configured).expanduser().resolve()
        if not candidate.is_file():
            raise AdapterFailed(f"{env_name} does not point to a file: {candidate}")
        if not _is_projectdiscovery(candidate, binary):
            raise AdapterFailed(f"{env_name} is not ProjectDiscovery {binary}: {candidate}")
        return str(candidate)

    for candidate in _candidate_executables(binary):
        if _is_projectdiscovery(candidate, binary):
            return str(candidate)

    hint = (
        f"ProjectDiscovery {binary} is not installed or is not on PATH. "
        f"Set {env_name} to its absolute path."
    )
    if binary == "httpx":
        hint += " The Python httpx command installed with this package is a different program."
    raise AdapterFailed(hint)


def validate_projectdiscovery_capabilities(binary: str, executable: str) -> None:
    if binary not in _PROJECTDISCOVERY:
        raise AdapterFailed(f"unsupported ProjectDiscovery binary: {binary}")
    try:
        completed = subprocess.run(
            [executable, "-h"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterFailed(f"cannot inspect ProjectDiscovery {binary} capabilities") from exc
    output = f"{completed.stdout}\n{completed.stderr}"
    missing = sorted(flag for flag in _REQUIRED_FLAGS[binary] if flag not in output)
    if completed.returncode != 0 or missing:
        detail = ", ".join(missing[:8])
        if len(missing) > 8:
            detail += f", and {len(missing) - 8} more"
        raise AdapterFailed(
            f"ProjectDiscovery {binary} is incompatible with Keel; missing flags: {detail}"
        )


def run_cli(argv: list[str], timeout: int = 120) -> CommandResult:
    binary = argv[0]
    if binary in _PROJECTDISCOVERY:
        argv = [resolve_projectdiscovery(binary), *argv[1:]]
        binary = argv[0]
    if shutil.which(binary) is None:
        raise AdapterFailed(f"{binary} is not installed")
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_scanner_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterFailed(f"{binary} timed out") from exc
    blob = completed.stdout + "\n" + completed.stderr
    throttled = bool(_THROTTLE.search(blob))
    retry_match = _RETRY_AFTER.search(blob)
    retry_after = float(retry_match.group(1)) if retry_match else None
    return CommandResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        throttled=throttled,
        retry_after_seconds=retry_after,
    )


def _scanner_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in _NETWORK_ENV_KEYS and not key.upper().startswith("PDCP_")
    }
