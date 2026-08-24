from pathlib import Path

from keel.paths import bin_dir, data_dir


def test_data_dir_env_override(monkeypatch, tmp_path: Path) -> None:
    configured = tmp_path / "keel-state"
    monkeypatch.setenv("KEEL_DATA_DIR", str(configured))

    assert data_dir() == configured.resolve()


def test_bin_dir_env_override(monkeypatch, tmp_path: Path) -> None:
    configured = tmp_path / "keel-bin"
    monkeypatch.setenv("KEEL_BIN_DIR", str(configured))

    assert bin_dir() == configured.resolve()

