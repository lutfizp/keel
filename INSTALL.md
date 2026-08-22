# Install Keel and probe tools

Keel needs **Python 3.10 or newer**. The `mcp` package is not published for Apple’s Command Line Tools `python3` (often 3.9). That is why `pip install -e ".[dev]"` reports `No matching distribution found for mcp>=1.9`.

Integrated binaries (used by `execute_wave`):

| Binary | Purpose |
|--------|---------|
| ProjectDiscovery `httpx` | Alive / HTTP probe |
| ProjectDiscovery `nuclei` | Template scan |

The Python library `httpx` is a dependency of Keel and is **not** the same as the `httpx` CLI.

## One command (recommended)

From the `keel` directory:

**macOS / Linux**

```bash
sh scripts/bootstrap.sh
```

**Windows (PowerShell)**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

The script detects the OS, prefers Python 3.12/3.11/3.10, creates `.venv`, upgrades pip, installs Keel, then installs `httpx` and `nuclei` (Homebrew on macOS, `go install` if Go is present, otherwise GitHub release archives into `~/.keel/bin`).

Partial runs:

```bash
sh scripts/bootstrap.sh python   # venv + Keel only
sh scripts/bootstrap.sh tools    # nuclei + httpx only
```

## macOS

1. Install Homebrew if needed: https://brew.sh
2. Install a current Python (do not use `/usr/bin/python3` if it is 3.9):

```bash
brew install python@3.12
```

3. From `keel`:

```bash
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

On Intel Macs, Python may live at `/usr/local/bin/python3.12`.

4. Probe tools:

```bash
brew install nuclei httpx
nuclei -update-templates
```

Or:

```bash
sh scripts/bootstrap.sh
```

5. Point OpenCode at `.venv/bin/python` as in `opencode.json.example`.

## Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip golang-go unzip
cd keel
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
sh scripts/bootstrap.sh tools
```

If `python3.12` is missing, enable the deadsnakes PPA or use [pyenv](https://github.com/pyenv/pyenv). Add `~/go/bin` or `~/.keel/bin` to `PATH`.

## Fedora / RHEL

```bash
sudo dnf install -y python3.12 golang unzip
cd keel
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
sh scripts/bootstrap.sh tools
```

## Windows

1. Install [Python 3.12](https://www.python.org/downloads/) and tick **Add python.exe to PATH**.
2. Open a **new** PowerShell:

```powershell
cd path\to\keel
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 tools
```

Install Go from https://go.dev if GitHub fallback is not enough, then reopen the terminal so `go` is on `PATH`.

Add `%USERPROFILE%\.keel\bin` and `%USERPROFILE%\go\bin` to the user PATH.

## Check

```bash
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -c "import mcp, keel; print('keel ok')"
httpx -version
nuclei -version
```

Then copy `opencode.json`. Use `python3 scripts/keel_mcp.py`. The launcher selects the 3.10+ `.venv` automatically.
