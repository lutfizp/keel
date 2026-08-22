# Install

Names (easy to mix up):

| Role | Name |
|------|------|
| pip / PyPI project | `keel-pentest` |
| Console script (MCP stdio) | `keel-pentest` |
| Import / `python -m` | `keel` |
| MCP client server id | `keel` |
| MCP Registry | `io.github.lutfizp/keel` |
| GitHub repo | `https://github.com/lutfizp/keel` |

Do **not** run `pip install keel`. That is a different project. Install **`keel-pentest`**.

Python **3.10+**. Apple `/usr/bin/python3` is often 3.9; `mcp` has no 3.9 wheels (`No matching distribution found for mcp>=1.9`).

`execute_wave` shells ProjectDiscovery **`httpx`** and **`nuclei`**. Those CLIs are not on PyPI. The Python library `httpx` (a dependency of `keel-pentest`) is not the CLI.

---

## Path A — PyPI (no git clone)

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install keel-pentest
```

[uv](https://docs.astral.sh/uv/):

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install keel-pentest
```

[pipx](https://pipx.pypa.io/) (global `keel-pentest` on PATH):

```bash
pipx install keel-pentest
```

Check:

```bash
python -c "import keel; print('ok')"
command -v keel-pentest || where keel-pentest
```

Do not run `keel-pentest` or `python -m keel` in a normal terminal to “try it”. Both are the MCP stdio server and wait on stdin. Point the client at them.

MCP command (use the **absolute** path from `command -v keel-pentest`):

```json
{
  "mcpServers": {
    "keel": {
      "command": "/ABS/path/to/.venv/bin/keel-pentest",
      "env": { "PYTHONUNBUFFERED": "1" }
    }
  }
}
```

Equivalent:

```json
{
  "mcpServers": {
    "keel": {
      "command": "/ABS/path/to/.venv/bin/python",
      "args": ["-m", "keel"],
      "env": { "PYTHONUNBUFFERED": "1" }
    }
  }
}
```

Then install probe CLIs ([below](#probe-clis-required-for-every-path)). Snippets: [clients/README.md](clients/README.md).

---

## Path B — Local clone (launcher + in-repo MCP configs)

```bash
git clone https://github.com/lutfizp/keel.git
cd keel
sh scripts/bootstrap.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

Bootstrap creates `.venv`, runs `pip install -e ".[dev]"` (still the **`keel-pentest`** project from `pyproject.toml`), then installs `httpx` and `nuclei`.

```bash
sh scripts/bootstrap.sh python   # venv + package only
sh scripts/bootstrap.sh tools    # nuclei + httpx only
```

MCP command:

```text
python3 scripts/keel_mcp.py
```

The launcher finds `.venv` with Python 3.10+ and execs `python -m keel`. Env: `KEEL_PYTHON`, `KEEL_ROOT`.

Configs already in the repo: `opencode.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`.

Editable without bootstrap (after you created a 3.10+ venv yourself):

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

That is the same distribution as PyPI (`name = "keel-pentest"`). After install you also get `.venv/bin/keel-pentest`.

---

## Probe CLIs (required for every path)

| Binary | Wave |
|--------|------|
| ProjectDiscovery `httpx` | `probe_alive` |
| ProjectDiscovery `nuclei` | `template_scan` |

**macOS**

```bash
brew install python@3.12 nuclei httpx
nuclei -update-templates
```

**Ubuntu / Debian** (package + tools via Go or bootstrap)

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip golang-go unzip
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install keel-pentest
# clone only:
# git clone ... && cd keel && sh scripts/bootstrap.sh tools
```

If you cloned: `sh scripts/bootstrap.sh tools` (Homebrew, `go install`, or GitHub archives into `~/.keel/bin`). Put `~/go/bin` and `~/.keel/bin` on `PATH`.

**Fedora / RHEL**

```bash
sudo dnf install -y python3.12 golang unzip
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install keel-pentest
```

**Windows**

1. [Python 3.12](https://www.python.org/downloads/) with **Add python.exe to PATH**.
2. New PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install keel-pentest
```

From a clone, tools: `powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 tools`. Add `%USERPROFILE%\.keel\bin` and `%USERPROFILE%\go\bin` to PATH.

---

## Check

```bash
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -c "import mcp, keel; print('keel ok')"
python -c "import importlib.metadata as m; print(m.version('keel-pentest'))"
httpx -version
nuclei -version
```

MCP Registry clients install identifier **`keel-pentest`** from PyPI (see `server.json`). You still need Python 3.10+ and the probe CLIs.
