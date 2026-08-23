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
- ProjectDiscovery `httpx` for `probe_alive`.
- ProjectDiscovery `nuclei` for `template_scan` and `second_look`.
- A local MCP client that supports the stdio transport.
- An operator-owned approval manifest for any real network traffic.
- A mode-`0600` credential-reference file when running proof playbooks.

The PyPI dependency named `httpx` is a Python HTTP library. Its optional `httpx` console script is **not** the ProjectDiscovery scanner. Keel detects and skips that name collision.

## Option A — [pipx](https://pipx.pypa.io/stable/installation/) (recommended)

`pipx` installs command-line applications in isolated environments while keeping their executable on `PATH`.

```bash
python3 --version
pipx install keel-pentest
command -v keel-pentest
keel-pentest --version
```

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
uv tool update-shell
command -v keel-pentest
keel-pentest --version
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
python -c "import keel; print('keel import ok')"
command -v keel-pentest
keel-pentest --version
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

These binaries are required regardless of how the Python package was installed.

macOS:

```bash
brew install httpx nuclei
nuclei -update-templates
```

Linux with Go installed:

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

Add `$HOME/go/bin` to the environment inherited by the MCP client. From a clone, `sh scripts/bootstrap.sh tools` can use Homebrew, Go, or ProjectDiscovery release archives.

Windows PowerShell with Go installed:

```powershell
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

Add `%USERPROFILE%\go\bin` to the client process's `PATH`. The clone bootstrap can alternatively place downloaded binaries under `%USERPROFILE%\.keel\bin`.

## Create the operator policy files

Keel denies network traffic unless the process can read an approval manifest. Create these files outside any workspace the AI client can modify.

macOS / Linux:

```bash
install -m 600 examples/engagement-approval.json /safe/operator/path/keel-approval.json
install -m 600 examples/credentials.example.json /safe/operator/path/keel-credentials.json
```

For a package install without a clone, download or copy the structures shown in [examples/engagement-approval.json](examples/engagement-approval.json) and [examples/credentials.example.json](examples/credentials.example.json). On Windows, create equivalent files in a user-only directory and restrict them with the account's ACL.

Edit the manifest before use. It binds all of the following to one `engagement_id`:

- exact/wildcard scope and exclusions;
- maximum RPS, parallel hosts, wave duration, wave requests, engagement requests, response bytes, and proof requests;
- reviewed Nuclei template IDs, expiry, allowed proof playbooks, and credential-reference names;
- optional proof targets: exact URL, canary SHA-256, owner/peer credential refs, and allowed playbooks.

The credential file contains the actual tester-only `Authorization` or `Cookie` values. Do not put production-user credentials in it. MCP calls receive reference names such as `tester-a`, never raw headers.

Set these variables in the environment of the MCP server process:

```bash
export KEEL_APPROVAL_FILE=/safe/operator/path/keel-approval.json
export KEEL_CREDENTIALS_FILE=/safe/operator/path/keel-credentials.json
```

To prepare a cross-account proof, manually place a unique, non-secret canary in a disposable resource owned by tester A and calculate the manifest hash:

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'REPLACE_WITH_RANDOM_CANARY').hexdigest())"
```

Do not leave the sample template ID, URL, hash, credentials, or expiry unchanged. An empty `nuclei_template_ids` selection intentionally produces no template wave; Keel never treats every installed signed template as implicitly approved. `KEEL_ALLOW_UNAPPROVED_RECON=1` bypasses the manifest only for isolated development/tests and must not be used against a real target.

Path-bounded URL rules are enforced for exact reachability and brokered proofs. Keel intentionally does not draft an external Nuclei template wave for a path-bounded scope or matching path exclusion, because it cannot yet mediate every template-internal request. Do not widen the manifest to a whole host unless that whole host is genuinely authorized.

## Verify the complete installation

Use the built-in checks instead of starting the stdio server in a normal terminal:

```bash
keel-pentest --version
keel-pentest doctor
```

`doctor` checks the Python version, MCP SDK API, writable data directory, both ProjectDiscovery binaries and every CLI flag Keel relies on, plus any configured policy files. It exits nonzero if a required scanner is missing or too old, the wrong `httpx` executable is selected, or a configured policy file is invalid. An unconfigured approval/credential file is reported as a notice so installation can be checked before an engagement is prepared; network tools still fail closed.

If a GUI client has a reduced `PATH`, provide explicit scanner paths in that client's server environment:

```json
{
  "env": {
    "KEEL_HTTPX_BIN": "/absolute/path/to/projectdiscovery/httpx",
    "KEEL_NUCLEI_BIN": "/absolute/path/to/nuclei",
    "KEEL_APPROVAL_FILE": "/safe/operator/path/keel-approval.json",
    "KEEL_CREDENTIALS_FILE": "/safe/operator/path/keel-credentials.json"
  }
}
```

The executable overrides are validated; pointing `KEEL_HTTPX_BIN` at the Python `httpx` command is rejected.

## Engagement data location

| Run mode | Default directory |
|---|---|
| Source checkout | `<repo>/.data/engagements` |
| macOS package install | `~/Library/Application Support/Keel/engagements` |
| Linux package install | `$XDG_STATE_HOME/keel/engagements`, otherwise `~/.local/state/keel/engagements` |
| Windows package install | `%LOCALAPPDATA%\Keel\engagements` |

Set `KEEL_DATA_DIR` in the MCP server environment to override the location.

For a security engagement, prefer an operator-controlled `KEEL_DATA_DIR` outside the AI-writable project. Keel persists request reservations, pending waves, cooldowns, semantic cards, policies, and audit events there so safety state survives a restart.

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
