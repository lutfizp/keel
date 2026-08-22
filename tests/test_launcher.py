from pathlib import Path
import importlib.util

LAUNCHER = Path(__file__).resolve().parents[1] / "scripts" / "keel_mcp.py"


def _mod():
    spec = importlib.util.spec_from_file_location("keel_mcp", LAUNCHER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_venv_interpreter_unix(tmp_path: Path) -> None:
    python = tmp_path / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("")
    found = _mod().venv_interpreter(tmp_path)
    assert found == python
