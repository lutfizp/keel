import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _project_version() -> str:
    in_project = False
    for line in (ROOT / "pyproject.toml").read_text().splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            break
        if in_project and stripped.startswith("version ="):
            return stripped.split("=", 1)[1].strip().strip('"')
    raise AssertionError("missing [project].version")


def test_registry_metadata_matches_python_distribution() -> None:
    document = json.loads((ROOT / "server.json").read_text())
    project_version = _project_version()

    assert document["version"] == project_version
    assert len(document["packages"]) == 1
    package = document["packages"][0]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "keel-pentest"
    assert package["version"] == project_version
