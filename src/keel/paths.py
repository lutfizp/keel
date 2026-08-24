from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """Return a writable engagement-data directory for source and installed runs."""
    configured = os.environ.get("KEEL_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()

    source_root = Path(__file__).resolve().parents[2]
    if (source_root / "pyproject.toml").is_file() and (source_root / "src" / "keel").is_dir():
        return source_root / ".data" / "engagements"

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "Keel" / "engagements"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Keel" / "engagements"

    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "keel" / "engagements"
    return Path.home() / ".local" / "state" / "keel" / "engagements"


def bin_dir() -> Path:
    """Return the managed directory that holds Keel-provisioned scanners.

    Searched before PATH by the scanner resolver, so a plain pip/pipx install can
    provide httpx and nuclei without the user editing PATH or setting KEEL_*_BIN.
    """
    configured = os.environ.get("KEEL_BIN_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home() / ".keel" / "bin"
