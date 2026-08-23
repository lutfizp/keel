import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from keel.adapters import process
from keel.errors import AdapterFailed


def test_resolver_skips_python_httpx(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    python_cli = tmp_path / "venv" / "httpx"
    pd_cli = tmp_path / "projectdiscovery" / "httpx"
    locations = {
        str(python_cli.parent): str(python_cli),
        str(pd_cli.parent): str(pd_cli),
    }
    monkeypatch.setenv("PATH", os.pathsep.join(locations))
    monkeypatch.delenv("KEEL_HTTPX_BIN", raising=False)
    monkeypatch.setattr(
        process.shutil,
        "which",
        lambda binary, path=None: locations.get(path) if binary == "httpx" else None,
    )
    monkeypatch.setattr(
        process,
        "_is_projectdiscovery",
        lambda candidate, binary: candidate == pd_cli.resolve() and binary == "httpx",
    )

    assert process.resolve_projectdiscovery("httpx") == str(pd_cli.resolve())


def test_httpx_and_nuclei_version_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = {
        "httpx": "projectdiscovery.io\nCurrent Version: v1.10.0",
        "nuclei": "Nuclei Engine Version: v3.11.1",
    }

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        return SimpleNamespace(stdout=outputs[Path(argv[0]).name], stderr="")

    monkeypatch.setattr(process.subprocess, "run", fake_run)

    assert process._is_projectdiscovery(Path("httpx"), "httpx")
    assert process._is_projectdiscovery(Path("nuclei"), "nuclei")


def test_env_override_rejects_non_projectdiscovery_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wrong_cli = tmp_path / "httpx"
    wrong_cli.write_text("not ProjectDiscovery")
    monkeypatch.setenv("KEEL_HTTPX_BIN", str(wrong_cli))
    monkeypatch.setattr(process, "_is_projectdiscovery", lambda *_: False)

    with pytest.raises(AdapterFailed, match="not ProjectDiscovery httpx"):
        process.resolve_projectdiscovery("httpx")


def test_scanner_capability_check_accepts_required_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flags = "\n".join(sorted(process._REQUIRED_FLAGS["nuclei"]))
    monkeypatch.setattr(
        process.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(returncode=0, stdout=flags, stderr=""),
    )

    process.validate_projectdiscovery_capabilities("nuclei", "/bin/nuclei")


def test_scanner_capability_check_rejects_old_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(returncode=0, stdout="-jsonl", stderr=""),
    )

    with pytest.raises(AdapterFailed, match="missing flags"):
        process.validate_projectdiscovery_capabilities("nuclei", "/bin/nuclei")
