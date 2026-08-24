from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from keel.adapters.base import CommandResult, ProgressCallback
from keel.errors import AdapterFailed, OperationCancelled
from keel.paths import bin_dir

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
        f"ProjectDiscovery {binary} is not installed. Run `keel-pentest setup` to "
        f"auto-install it, or set {env_name} to its absolute path."
    )
    if binary == "httpx":
        hint += " The Python httpx command installed with this package is a different program."
    raise AdapterFailed(hint)


def _candidate_executables(binary: str) -> list[Path]:
    candidates: list[Path] = []
    seen: set[Path] = set()
    for source in _candidate_dirs():
        found = shutil.which(binary, path=source)
        if not found:
            continue
        candidate = Path(found).resolve()
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _candidate_dirs() -> list[str]:
    # The Keel-managed bin directory wins over PATH so a provisioned scanner is
    # found even when a GUI MCP client launches Keel with a reduced environment.
    dirs: list[str] = []
    try:
        managed = str(bin_dir())
        if managed:
            dirs.append(managed)
    except OSError:
        pass
    dirs.extend(part for part in os.environ.get("PATH", "").split(os.pathsep) if part)
    return dirs


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


def run_cli(
    argv: list[str],
    timeout: int = 120,
    cancel_event: threading.Event | None = None,
    progress_callback: ProgressCallback | None = None,
) -> CommandResult:
    binary = argv[0]
    if binary in _PROJECTDISCOVERY:
        argv = [resolve_projectdiscovery(binary), *argv[1:]]
        binary = argv[0]
    if shutil.which(binary) is None:
        raise AdapterFailed(f"{binary} is not installed")
    if cancel_event is None and progress_callback is None:
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
        return _command_result(
            argv, completed.returncode, completed.stdout, completed.stderr
        )
    return _run_managed(
        argv,
        binary,
        timeout,
        cancel_event or threading.Event(),
        progress_callback,
    )


def _run_managed(
    argv: list[str],
    binary: str,
    timeout: int,
    cancel_event: threading.Event,
    progress_callback: ProgressCallback | None,
) -> CommandResult:
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_scanner_environment(),
        )
    except OSError as exc:
        raise AdapterFailed(f"cannot start {binary}: {exc}") from exc
    started = time.monotonic()
    while True:
        if cancel_event.is_set():
            _stop_process(process)
            raise OperationCancelled(f"{binary} execution cancelled")
        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            _stop_process(process)
            raise AdapterFailed(f"{binary} timed out")
        if progress_callback is not None:
            try:
                progress_callback(
                    min(85.0, 10.0 + (elapsed / max(timeout, 1)) * 75.0),
                    "scanner_running",
                )
            except Exception as exc:
                _stop_process(process)
                raise AdapterFailed(
                    f"{binary} stopped because progress state could not be persisted"
                ) from exc
        try:
            stdout, stderr = process.communicate(timeout=min(0.25, timeout - elapsed))
            break
        except subprocess.TimeoutExpired:
            continue
    if cancel_event.is_set():
        raise OperationCancelled(f"{binary} execution cancelled")
    return _command_result(argv, process.returncode or 0, stdout, stderr)


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        return
    try:
        process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            return
        process.communicate()


def _command_result(
    argv: list[str], returncode: int, stdout: str, stderr: str
) -> CommandResult:
    blob = stdout + "\n" + stderr
    throttled = bool(_THROTTLE.search(blob))
    retry_match = _RETRY_AFTER.search(blob)
    retry_after = float(retry_match.group(1)) if retry_match else None
    return CommandResult(
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        throttled=throttled,
        retry_after_seconds=retry_after,
    )


def _scanner_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in _NETWORK_ENV_KEYS and not key.upper().startswith("PDCP_")
    }
