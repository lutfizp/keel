from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MIN_PY = (3, 10)
PD_TOOLS = ("httpx", "nuclei")


class BootstrapError(RuntimeError):
    pass


def main(argv: list[str]) -> int:
    kind = argv[1] if len(argv) > 1 else "all"
    if kind not in {"all", "python", "tools"}:
        print("usage: bootstrap.py [all|python|tools]", file=sys.stderr)
        return 2
    os_id = detect_os()
    print(f"os={os_id} arch={platform.machine()}")
    if kind in {"all", "python"}:
        install_python_env(os_id)
    if kind in {"all", "tools"}:
        install_probe_tools(os_id)
    print("done")
    return 0


def detect_os() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    if system == "linux":
        if Path("/etc/debian_version").exists():
            return "debian"
        if Path("/etc/redhat-release").exists() or Path("/etc/fedora-release").exists():
            return "rhel"
        return "linux"
    raise BootstrapError(f"unsupported system {system}")


def install_python_env(os_id: str) -> None:
    python = resolve_python(os_id)
    version = python_version(python)
    if version < MIN_PY:
        raise BootstrapError(
            f"{python} is {'.'.join(map(str, version))}; Keel needs Python {MIN_PY[0]}.{MIN_PY[1]}+"
        )
    print(f"using interpreter {python} ({version[0]}.{version[1]})")
    venv = ROOT / ".venv"
    venv_py = venv_python(os_id)
    stale = True
    if venv_py.exists():
        try:
            stale = python_version(venv_py) < MIN_PY
        except (OSError, subprocess.CalledProcessError, ValueError):
            stale = True
    if stale:
        if venv.exists():
            print(f"replacing {venv} (needs Python {MIN_PY[0]}.{MIN_PY[1]}+)")
            shutil.rmtree(venv)
        run([str(python), "-m", "venv", str(venv)])
    run([str(venv_python(os_id)), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    run([str(venv_python(os_id)), "-m", "pip", "install", "-e", f"{ROOT}[dev]"])


def resolve_python(os_id: str) -> Path:
    if os_id == "windows":
        launcher = shutil.which("py")
        if launcher:
            for tag in ("-3.12", "-3.13", "-3.11", "-3.10"):
                try:
                    out = subprocess.check_output(
                        [launcher, tag, "-c", "import sys; print(sys.executable)"],
                        text=True,
                    )
                    return Path(out.strip())
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
    names = ["python3.13", "python3.12", "python3.11", "python3.10"]
    extra = [
        Path("/opt/homebrew/bin/python3.13"),
        Path("/opt/homebrew/bin/python3.12"),
        Path("/opt/homebrew/bin/python3.11"),
        Path("/opt/homebrew/bin/python3.10"),
        Path("/usr/local/bin/python3.13"),
        Path("/usr/local/bin/python3.12"),
        Path("/usr/local/bin/python3.11"),
        Path("/usr/local/bin/python3.10"),
    ]
    if os_id == "windows":
        names.append("python")
    else:
        names.append("python3")
    found: list[Path] = []
    for candidate in extra:
        if candidate.exists():
            ver = python_version(candidate)
            if ver >= MIN_PY:
                return candidate
    for name in names:
        path = shutil.which(name)
        if not path:
            continue
        candidate = Path(path)
        ver = python_version(candidate)
        if ver >= MIN_PY:
            return candidate
        found.append(candidate)
    installed = ensure_python(os_id)
    if installed is not None and python_version(installed) >= MIN_PY:
        return installed
    detail = ", ".join(str(item) for item in found) or "none"
    raise BootstrapError(
        "no Python 3.10+ on PATH "
        f"(saw {detail}). Install Python 3.12, then re-run this script. "
        "On macOS, Apple python3 is often 3.9 and cannot install the mcp package."
    )


def ensure_python(os_id: str) -> Path | None:
    if os_id == "macos" and shutil.which("brew"):
        run(["brew", "install", "python@3.12"])
        for candidate in (
            Path("/opt/homebrew/bin/python3.12"),
            Path("/usr/local/bin/python3.12"),
        ):
            if candidate.exists():
                return candidate
        which = shutil.which("python3.12")
        return Path(which) if which else None
    if os_id == "debian" and shutil.which("apt-get") and os.geteuid() == 0:
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "python3.12", "python3.12-venv", "python3-pip"])
        which = shutil.which("python3.12") or shutil.which("python3")
        return Path(which) if which else None
    if os_id == "rhel" and shutil.which("dnf") and os.geteuid() == 0:
        run(["dnf", "install", "-y", "python3.12"])
        which = shutil.which("python3.12") or shutil.which("python3")
        return Path(which) if which else None
    if os_id == "windows" and shutil.which("winget"):
        run(["winget", "install", "-e", "--id", "Python.Python.3.12", "--accept-package-agreements", "--accept-source-agreements"])
        which = shutil.which("python")
        return Path(which) if which else None
    return None


def install_probe_tools(os_id: str) -> None:
    if os_id == "macos" and shutil.which("brew"):
        run(["brew", "install", "nuclei", "httpx"])
        refresh_nuclei_templates()
        return
    if shutil.which("go"):
        env = os.environ.copy()
        gobin = Path.home() / "go" / "bin"
        gobin.mkdir(parents=True, exist_ok=True)
        env["GOBIN"] = str(gobin)
        run(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], env=env)
        run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], env=env)
        print(f"ensure {gobin} is on PATH")
        nuclei_name = "nuclei.exe" if os_id == "windows" else "nuclei"
        refresh_nuclei_templates(gobin / nuclei_name)
        return
    if os_id == "windows" and shutil.which("winget"):
        run(["winget", "install", "-e", "--id", "GoLang.Go", "--accept-package-agreements", "--accept-source-agreements"])
        raise BootstrapError("Go was installed; open a new terminal and re-run: python scripts/bootstrap.py tools")
    nuclei = install_pd_from_github(os_id)
    refresh_nuclei_templates(nuclei)


def install_pd_from_github(os_id: str) -> Path:
    dest = Path.home() / ".keel" / "bin"
    dest.mkdir(parents=True, exist_ok=True)
    arch = github_arch()
    os_label = {"macos": "macOS", "windows": "windows", "debian": "linux", "rhel": "linux", "linux": "linux"}[os_id]
    for tool in PD_TOOLS:
        repo = f"projectdiscovery/{tool}"
        url, checksums_url = latest_asset_urls(repo, os_label, arch)
        archive = download(url)
        checksums = download(checksums_url)
        try:
            verify_release_checksum(
                archive,
                checksums,
                Path(urlparse(url).path).name,
            )
            extract_binary(archive, dest, tool, os_id == "windows")
        finally:
            archive.unlink(missing_ok=True)
            checksums.unlink(missing_ok=True)
        print(f"installed {dest / tool}")
    print(f"ensure {dest} is on PATH")
    return dest / ("nuclei.exe" if os_id == "windows" else "nuclei")


def github_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return "amd64"


def latest_asset_urls(repo: str, os_label: str, arch: str) -> tuple[str, str]:
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    with urllib.request.urlopen(api, timeout=30) as response:
        payload = json.loads(response.read().decode())
    return release_asset_urls(payload, repo, os_label, arch)


def release_asset_urls(
    payload: dict, repo: str, os_label: str, arch: str
) -> tuple[str, str]:
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
        raise BootstrapError(
            f"release for {repo} lacks a binary or checksum for {os_label} {arch}"
        )
    return archive_url, checksums_url


def verify_release_checksum(archive: Path, checksums: Path, asset_name: str) -> None:
    expected = ""
    for line in checksums.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1].lstrip("*") == asset_name:
            expected = fields[0].lower()
            break
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise BootstrapError(f"release checksum is missing for {asset_name}")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise BootstrapError(f"release checksum mismatch for {asset_name}")


def download(url: str) -> Path:
    suffix = Path(urlparse(url).path).suffix
    if urlparse(url).path.endswith(".tar.gz"):
        suffix = ".tar.gz"
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".bin")
    handle.close()
    urllib.request.urlretrieve(url, handle.name)
    return Path(handle.name)


def extract_binary(archive: Path, dest: Path, name: str, windows: bool) -> None:
    binary_name = f"{name}.exe" if windows else name
    target = dest / binary_name
    if archive.suffix == ".zip" or zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            member = next(item for item in bundle.namelist() if Path(item).name in {name, binary_name})
            with bundle.open(member) as src, target.open("wb") as out:
                out.write(src.read())
    else:
        with tarfile.open(archive) as bundle:
            member = next(item for item in bundle.getmembers() if Path(item.name).name == name)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise BootstrapError(f"missing {name} in archive")
            target.write_bytes(extracted.read())
    target.chmod(target.stat().st_mode | stat.S_IEXEC)
    archive.unlink(missing_ok=True)


def refresh_nuclei_templates(executable: Path | None = None) -> None:
    nuclei = str(executable) if executable and executable.is_file() else shutil.which("nuclei")
    if nuclei:
        run([str(nuclei), "-update-templates"], check=False)


def venv_python(os_id: str) -> Path:
    if os_id == "windows":
        return ROOT / ".venv" / "Scripts" / "python.exe"
    return ROOT / ".venv" / "bin" / "python"


def python_version(python: Path) -> tuple[int, int]:
    if python.name == "py":
        out = subprocess.check_output([str(python), "-3", "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"], text=True)
    else:
        out = subprocess.check_output([str(python), "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"], text=True)
    major, minor = out.split()
    return int(major), int(minor)


def run(argv: list[str], env: dict[str, str] | None = None, check: bool = True) -> None:
    print("+", " ".join(argv))
    subprocess.run(argv, check=check, env=env)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
