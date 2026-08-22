from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MIN = (3, 10)


def main() -> None:
    python = choose_python()
    os.execv(str(python), [str(python), "-m", "keel", *sys.argv[1:]])


def choose_python() -> Path:
    forced = os.environ.get("KEEL_PYTHON")
    if forced:
        path = Path(forced)
        if path.exists():
            return path
    roots = candidate_roots()
    for root in roots:
        python = venv_interpreter(root)
        if python is not None and version_ok(python):
            return python
    searched = " ".join(str(item) for item in roots) or "(none)"
    sys.stderr.write(
        "Keel launcher could not find a Python 3.10+ venv. "
        f"Looked next to: {searched}. Run sh scripts/bootstrap.sh inside keel.\n"
    )
    raise SystemExit(1)


def candidate_roots() -> list[Path]:
    roots: list[Path] = []
    env_root = os.environ.get("KEEL_ROOT")
    if env_root:
        roots.append(Path(env_root))
    here = Path(__file__).resolve().parent.parent
    roots.append(here)
    cwd = Path.cwd().resolve()
    roots.append(cwd)
    roots.append(cwd / "keel")
    for parent in (cwd, *cwd.parents):
        roots.append(parent)
        roots.append(parent / "keel")
        if parent.parent == parent:
            break
    unique: list[Path] = []
    seen: set[Path] = set()
    for item in roots:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def venv_interpreter(root: Path) -> Path | None:
    unix = root / ".venv" / "bin" / "python"
    windows = root / ".venv" / "Scripts" / "python.exe"
    if unix.exists():
        return unix
    if windows.exists():
        return windows
    return None


def version_ok(python: Path) -> bool:
    try:
        out = subprocess.check_output(
            [str(python), "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    major, minor = out.split()
    return (int(major), int(minor)) >= MIN


if __name__ == "__main__":
    main()
