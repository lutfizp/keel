# Install Keel

Keel is a Python stdio MCP server plus two external scanner dependencies. Keep these names separate:

| Role | Name |
|---|---|
| PyPI distribution | `keel-pentest` |
| Executable / MCP command | `keel-pentest` |
| Python module | `keel` |
| MCP server id | `keel` |
| MCP Registry name | `io.github.lutfizp/keel` |

Do not run `pip install keel`; that is a different PyPI project.

## Requirements

- Python 3.10 or newer.
- A local MCP client that supports the stdio transport.

ProjectDiscovery `httpx` and `nuclei` are installed by `keel-pentest setup` into `~/.keel/bin`. You do not need Homebrew, Go, or `PATH` edits for a first run. The PyPI library named `httpx` is unrelated; Keel refuses that binary.

## Recommended — pipx + setup

`pipx` is not part of macOS. Install it, then install Keel. Apple's `/usr/bin/python3` is often 3.9 and will reject the package.

```bash
brew install pipx python@3.12
pipx ensurepath
# new terminal
pipx install keel-pentest
keel-pentest setup
keel-pentest doctor
```

Then point the MCP client at `keel-pentest`. Windows: `py -m pip install --user pipx`, then the same `setup` / `doctor` commands.

On Windows PowerShell:

```powershell
py --version
py -m pip install --user pipx
py -m pipx ensurepath
pipx install keel-pentest
where.exe keel-pentest
keel-pentest --version
```

Open a new terminal after `pipx ensurepath` if the command is not found.

## Option B — [uv tool](https://docs.astral.sh/uv/guides/tools/)

```bash
uv tool install keel-pentest
keel-pentest setup
keel-pentest doctor
```

Open a new terminal after `uv tool update-shell` when necessary. `uv pip install` is intended for a virtual environment; `uv tool install` is the clearer choice for a persistent MCP executable.

## Option C — pip in a virtual environment

Do not install Keel into an externally managed system Python. Create a dedicated virtual environment and give the MCP client the **absolute** executable path.

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install keel-pentest
keel-pentest setup
keel-pentest doctor
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install keel-pentest
python -c "import keel; print('keel import ok')"
where.exe keel-pentest
keel-pentest --version
```

If the environment is not activated when the coding client starts, configure the client with `.venv/bin/keel-pentest` or `.venv\Scripts\keel-pentest.exe` as an absolute path. An equivalent command is the environment's Python executable with arguments `-m`, `keel`.

## Option D — local clone

Use this path for development or for the checked-in client configurations:

```bash
git clone https://github.com/lutfizp/keel.git
cd keel
sh scripts/bootstrap.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

The bootstrap creates `.venv`, installs the project editable with its development dependencies, and installs the ProjectDiscovery tools. Homebrew and Go are preferred; the direct GitHub-release fallback verifies the downloaded archive against the release SHA-256 checksum before extraction. Partial runs are available:

```bash
sh scripts/bootstrap.sh python
sh scripts/bootstrap.sh tools
```

The in-repo MCP command is:

```text
python3 scripts/keel_mcp.py
```

The launcher finds the repository's Python 3.10+ virtual environment and runs `python -m keel`. `KEEL_PYTHON` can select a specific interpreter and `KEEL_ROOT` can select a clone.

## Install the ProjectDiscovery tools

`keel-pentest setup` is the default path. It downloads release binaries into `~/.keel/bin` (override with `KEEL_BIN_DIR`). Keel searches that directory before `PATH`.

Manual install is optional:

macOS: `brew install httpx nuclei && nuclei -update-templates`

Linux/Windows with Go: `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` and the nuclei equivalent, then put `~/go/bin` on the MCP client's `PATH`.

A clone can still run `sh scripts/bootstrap.sh tools`.

## Optional team policy files

Default mode is self-attested: `begin_engagement` is the authorization. Rate limits, one-wave-per-host, and sanitized evidence still apply.

Set `KEEL_APPROVAL_FILE` only when a team wants a pinned manifest (scope, template IDs, proof targets, expiry). Proofs that need sessions also need `KEEL_CREDENTIALS_FILE` (mode 0600) mapping names such as `tester-a` to Authorization or Cookie — never paste secrets into prompts.

```bash
install -m 600 examples/engagement-approval.json /safe/operator/path/keel-approval.json
install -m 600 examples/credentials.example.json /safe/operator/path/keel-credentials.json
export KEEL_APPROVAL_FILE=/safe/operator/path/keel-approval.json
export KEEL_CREDENTIALS_FILE=/safe/operator/path/keel-credentials.json
```

Edit placeholders before use. An empty `nuclei_template_ids` list means no template wave; Keel does not run the entire template pack.

## Verify the complete installation

```bash
keel-pentest --version
keel-pentest doctor
```

`doctor` checks Python, the MCP SDK, the data directory, and both scanners. Missing scanners: run `keel-pentest setup`. A GUI client with a thin `PATH` still finds `~/.keel/bin`. Optional overrides: `KEEL_HTTPX_BIN`, `KEEL_NUCLEI_BIN`. Pointing `KEEL_HTTPX_BIN` at the Python `httpx` command is rejected.

## Engagement data location

| Run mode | Default directory |
|---|---|
| Source checkout | `<repo>/.data/engagements` |
| macOS package install | `~/Library/Application Support/Keel/engagements` |
| Linux package install | `$XDG_STATE_HOME/keel/engagements`, otherwise `~/.local/state/keel/engagements` |
| Windows package install | `%LOCALAPPDATA%\Keel\engagements` |

Set `KEEL_DATA_DIR` in the MCP server environment to override the location.

For a security engagement, prefer an operator-controlled `KEEL_DATA_DIR` outside the AI-writable project. Keel persists request reservations, pending/terminal waves, background job results, cooldowns, semantic cards, policies, and audit events there so safety state survives a restart. A job that was running during process termination is restored as `interrupted`; its wave remains retryable only when attempts and engagement budget remain.

## Connect a client

Use the absolute path printed by `command -v keel-pentest` (Windows: `where.exe keel-pentest`) when possible. GUI applications often do not inherit shell initialization files.

Exact commands and file formats for Claude Code, Codex, Cursor, OpenCode, Hermes, Gemini CLI, Antigravity, VS Code/GitHub Copilot, Windsurf, Cline, and Roo are in [clients/README.md](clients/README.md).

Do not run bare `keel-pentest` to test the MCP transport: without `--version` or `doctor`, it correctly waits for JSON-RPC on stdin.

## MCP Registry

`server.json` publishes the discovery name `io.github.lutfizp/keel` and maps it to the PyPI distribution `keel-pentest`. The Registry is metadata; automatic installation depends on the client. If a client has no Registry installation flow, install with `pipx`, `uv tool`, or a virtual environment and configure the stdio executable directly.

## Upgrade or remove

```bash
pipx upgrade keel-pentest
pipx uninstall keel-pentest
```

```bash
uv tool upgrade keel-pentest
uv tool uninstall keel-pentest
```

For a virtual environment, activate it and use `python -m pip install --upgrade keel-pentest`, or remove the dedicated environment directory when it is no longer needed.
