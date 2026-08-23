from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest


BOOTSTRAP = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap.py"


def _module():
    spec = importlib.util.spec_from_file_location("keel_bootstrap", BOOTSTRAP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_asset_selection_requires_checksum() -> None:
    bootstrap = _module()
    payload = {
        "assets": [
            {
                "name": "nuclei_3.11.1_linux_amd64.zip",
                "browser_download_url": "https://example/nuclei.zip",
            },
            {
                "name": "nuclei_3.11.1_checksums.txt",
                "browser_download_url": "https://example/checksums.txt",
            },
        ]
    }

    assert bootstrap.release_asset_urls(
        payload, "projectdiscovery/nuclei", "linux", "amd64"
    ) == ("https://example/nuclei.zip", "https://example/checksums.txt")

    with pytest.raises(bootstrap.BootstrapError, match="lacks a binary or checksum"):
        bootstrap.release_asset_urls(
            {"assets": payload["assets"][:1]},
            "projectdiscovery/nuclei",
            "linux",
            "amd64",
        )


def test_release_checksum_is_verified(tmp_path: Path) -> None:
    bootstrap = _module()
    archive = tmp_path / "nuclei.zip"
    archive.write_bytes(b"reviewed release bytes")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(f"{digest}  nuclei.zip\n")

    bootstrap.verify_release_checksum(archive, checksums, "nuclei.zip")

    archive.write_bytes(b"tampered")
    with pytest.raises(bootstrap.BootstrapError, match="checksum mismatch"):
        bootstrap.verify_release_checksum(archive, checksums, "nuclei.zip")
