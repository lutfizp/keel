"""Fetch pinned ProjectDiscovery scanners into a managed bin directory.

This lets a plain ``pip``/``pipx`` install obtain ``httpx`` and ``nuclei`` without
a git clone, a package manager, or manual PATH edits. Binaries land in
:func:`keel.paths.bin_dir`, which the scanner resolver searches before PATH, so a
GUI MCP client with a stripped environment still finds them.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from keel.paths import bin_dir

_TOOLS = ("httpx", "nuclei")


class ProvisionError(RuntimeError):
    pass


def provision_scanners(tools: tuple[str, ...] = _TOOLS) -> list[Path]:
    """Download the requested scanners into the managed bin directory."""
    dest = bin_dir()
    dest.mkdir(parents=True, exist_ok=True)
    windows = platform.system().lower() == "windows"
    arch = _github_arch()
    os_label = "windows" if windows else ("macOS" if _is_macos() else "linux")
    installed: list[Path] = []
    for tool in tools:
        archive_url, checksums_url = _latest_asset_urls(
            f"projectdiscovery/{tool}", os_label, arch
        )
        archive = _download(archive_url)
        checksums = _download(checksums_url)
        try:
            _verify_checksum(archive, checksums, Path(urlparse(archive_url).path).name)
            binary = _extract_binary(archive, dest, tool, windows)
        finally:
            archive.unlink(missing_ok=True)
            checksums.unlink(missing_ok=True)
        installed.append(binary)
    _refresh_nuclei_templates(dest)
    return installed


def _is_macos() -> bool:
    return platform.system().lower() == "darwin"


def _github_arch() -> str:
    machine = platform.machine().lower()
    return "arm64" if machine in {"arm64", "aarch64"} else "amd64"


def _latest_asset_urls(repo: str, os_label: str, arch: str) -> tuple[str, str]:
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    request = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode())
    except (OSError, ValueError) as exc:
        raise ProvisionError(f"cannot query the latest {repo} release: {exc}") from exc
    needle = f"{os_label}_{arch}".lower()
    archive_url = ""
    checksums_url = ""
    for asset in payload.get("assets", []):
        name = str(asset.get("name", "")).lower()
        if "checksums" in name and name.endswith(".txt"):
            checksums_url = str(asset["browser_download_url"])
        if needle in name.replace("aarch64", "arm64") and name.endswith(
            (".zip", ".tgz", ".tar.gz")
        ):
            archive_url = str(asset["browser_download_url"])
    if not archive_url or not checksums_url:
        raise ProvisionError(
            f"the latest {repo} release has no binary or checksum for {os_label} {arch}"
        )
    return archive_url, checksums_url


def _verify_checksum(archive: Path, checksums: Path, asset_name: str) -> None:
    expected = ""
    for line in checksums.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1].lstrip("*") == asset_name:
            expected = fields[0].lower()
            break
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ProvisionError(f"release checksum is missing for {asset_name}")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ProvisionError(f"release checksum mismatch for {asset_name}")


def _download(url: str) -> Path:
    path = urlparse(url).path
    suffix = ".tar.gz" if path.endswith(".tar.gz") else Path(path).suffix
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".bin")
    handle.close()
    try:
        urllib.request.urlretrieve(url, handle.name)
    except OSError as exc:
        Path(handle.name).unlink(missing_ok=True)
        raise ProvisionError(f"download failed for {url}: {exc}") from exc
    return Path(handle.name)


def _extract_binary(archive: Path, dest: Path, name: str, windows: bool) -> Path:
    binary_name = f"{name}.exe" if windows else name
    target = dest / binary_name
    if archive.suffix == ".zip" or zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            member = next(
                item for item in bundle.namelist()
                if Path(item).name in {name, binary_name}
            )
            with bundle.open(member) as src, target.open("wb") as out:
                out.write(src.read())
    else:
        with tarfile.open(archive) as bundle:
            member = next(
                item for item in bundle.getmembers() if Path(item.name).name == name
            )
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise ProvisionError(f"archive for {name} has no extractable binary")
            target.write_bytes(extracted.read())
    target.chmod(target.stat().st_mode | stat.S_IEXEC)
    return target


def _refresh_nuclei_templates(dest: Path) -> None:
    for candidate in (dest / "nuclei", dest / "nuclei.exe"):
        if candidate.is_file():
            subprocess.run(
                [str(candidate), "-update-templates", "-disable-update-check"],
                check=False,
                capture_output=True,
            )
            return
