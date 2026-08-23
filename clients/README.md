# Connect Keel to coding clients

Keel is one local stdio MCP process. Install the PyPI distribution `keel-pentest` with [pipx, uv tool, or a dedicated virtual environment](../INSTALL.md), then resolve its executable:

```bash
KEEL_COMMAND="$(command -v keel-pentest)"
test -n "$KEEL_COMMAND"
"$KEEL_COMMAND" --version
"$KEEL_COMMAND" doctor
```

On Windows, use `where.exe keel-pentest` and copy the full `.exe` path into the client. Prefer an absolute path for GUI applications because they often inherit a smaller `PATH` than an interactive shell.

The generic [mcpServers.json](mcpServers.json), [codex.toml](codex.toml), and [hermes.yaml](hermes.yaml) examples use `keel-pentest` for readability. Replace it with the resolved absolute path when the client cannot find the command. Add operator-file paths to the server environment before starting a real engagement; never paste credential values into the client configuration or a prompt.

## Compatibility summary

| Client / surface | Configuration shape | Keel example |
|---|---|---|
| Claude Code | `.mcp.json`, top-level `mcpServers` | repository [.mcp.json](../.mcp.json) or CLI below |
| Codex CLI | `~/.codex/config.toml`, tables under `mcp_servers` | [codex.toml](codex.toml) or CLI below |
| Cursor | `.cursor/mcp.json`, top-level `mcpServers` | repository [.cursor/mcp.json](../.cursor/mcp.json) |
| OpenCode 1.x | flat server entries under `mcp` | [opencode.pypi.json.example](../opencode.pypi.json.example) |
| OpenCode v2 | server entries under `mcp.servers` | [opencode.v2.json.example](../opencode.v2.json.example) |
| Hermes Agent | `~/.hermes/config.yaml`, top-level `mcp_servers` | [hermes.yaml](hermes.yaml) or CLI below |
| Gemini CLI | `.gemini/settings.json`, top-level `mcpServers` | generic JSON or CLI below |
| Antigravity CLI (`agy`) | managed by `agy mcp` | CLI below |
| VS Code / Copilot Chat | `.vscode/mcp.json`, top-level `servers` | repository [.vscode/mcp.json](../.vscode/mcp.json) |
| GitHub Copilot CLI | workspace `.mcp.json` or `~/.copilot/mcp-config.json`, top-level `mcpServers` | repository [.mcp.json](../.mcp.json) |
| Claude Desktop / Windsurf / Cline / Roo | client-specific file, top-level `mcpServers` | generic JSON below |

The configuration syntax is client-specific; a single JSON file is not valid for every host. In particular, VS Code uses `servers`, Hermes uses `mcp_servers`, and OpenCode v2 uses `mcp.servers`.

## [Claude Code](https://code.claude.com/docs/en/mcp)

```bash
claude mcp add --scope user --transport stdio keel -- "$KEEL_COMMAND"
claude mcp get keel
```

For a clone, the checked-in `.mcp.json` starts `python3 scripts/keel_mcp.py`. Claude Code asks you to approve project-scoped servers before starting them.

## [Codex CLI](https://developers.openai.com/codex/mcp/)

```bash
codex mcp add keel -- "$KEEL_COMMAND"
codex mcp get keel
```

The equivalent TOML is:

```toml
[mcp_servers.keel]
command = "/absolute/path/to/keel-pentest"
startup_timeout_sec = 30
tool_timeout_sec = 300

[mcp_servers.keel.env]
PYTHONUNBUFFERED = "1"
```

The clone's `.codex/config.toml` uses the repository launcher and a repository-relative working directory.

## [Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md)

Gemini takes the name, executable, and optional executable arguments as positional values:

```bash
gemini mcp add --scope user --transport stdio keel "$KEEL_COMMAND"
gemini mcp list
```

Do not insert Claude/Codex's `--` separator before the executable; Gemini's command shape is different. A manual `.gemini/settings.json` entry uses the generic `mcpServers` object.

## Antigravity CLI

Antigravity requires flags before the server name:

```bash
agy mcp add --env PYTHONUNBUFFERED=1 keel "$KEEL_COMMAND"
agy mcp list
```

## [Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md)

Hermes takes the server name first, followed by `--command`:

```bash
hermes mcp add keel --command "$KEEL_COMMAND"
hermes mcp test keel
```

This ordering is invalid: `hermes mcp add --command keel-pentest keel`.

An equivalent `~/.hermes/config.yaml` block is:

```yaml
mcp_servers:
  keel:
    command: /absolute/path/to/keel-pentest
    env:
      PYTHONUNBUFFERED: "1"
```

Use `/reload-mcp` in an existing Hermes session after changing the file.

## [OpenCode](https://opencode.ai/v2/docs/mcp-servers)

OpenCode 1.x and v2 use different schemas. Use only the form that matches your installed release.

OpenCode 1.x (also the format validated with OpenCode 1.18.21):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "keel": {
      "type": "local",
      "command": ["/absolute/path/to/keel-pentest"],
      "enabled": true,
      "timeout": 300000
    }
  }
}
```

OpenCode v2:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "timeout": {
      "startup": 30000,
      "catalog": 30000,
      "execution": 300000
    },
    "servers": {
      "keel": {
        "type": "local",
        "command": ["/absolute/path/to/keel-pentest"],
        "environment": {
          "PYTHONUNBUFFERED": "1"
        },
        "disabled": false
      }
    }
  }
}
```

V2 uses `environment` rather than `env`, `disabled` rather than `enabled`, and timeout objects rather than one numeric timeout. Verify with `opencode mcp list`.

## [Cursor](https://cursor.com/docs/mcp)

Create `.cursor/mcp.json` in the target project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "keel": {
      "type": "stdio",
      "command": "/absolute/path/to/keel-pentest",
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

Cursor's current stdio schema requires `type: "stdio"`. The checked-in project config uses `${workspaceFolder}` to resolve the clone launcher.

## [VS Code](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) and [GitHub Copilot](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference)

VS Code / Copilot Chat uses `.vscode/mcp.json` with `servers`:

```json
{
  "servers": {
    "keel": {
      "type": "stdio",
      "command": "/absolute/path/to/keel-pentest",
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

GitHub Copilot CLI's portable format instead uses `mcpServers` in a workspace `.mcp.json` or user `~/.copilot/mcp-config.json`. The repository `.mcp.json` is usable by both Claude Code and Copilot CLI. Verify Copilot CLI with `copilot mcp list`.

## Claude Desktop, Windsurf, Cline, and Roo

These clients accept the same basic local-server object, but store it in different locations:

- Claude Desktop: edit its MCP settings or desktop config.
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/mcp): `~/.codeium/windsurf/mcp_config.json`.
- [Cline](https://docs.cline.bot/mcp/mcp-overview) CLI: `~/.cline/mcp.json`; the IDE extension also exposes an MCP configuration UI.
- [Roo Code](https://roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo/): project `.roo/mcp.json` or its global `mcp_settings.json`.

```json
{
  "mcpServers": {
    "keel": {
      "command": "/absolute/path/to/keel-pentest",
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

## Local clone configuration

After `sh scripts/bootstrap.sh`, these checked-in files use `python3 scripts/keel_mcp.py`:

| Client | File |
|---|---|
| Claude Code and Copilot CLI | `.mcp.json` |
| Codex | `.codex/config.toml` |
| Cursor | `.cursor/mcp.json` |
| VS Code / Copilot Chat | `.vscode/mcp.json` |
| OpenCode 1.x | `opencode.json` |

They assume this repository is the workspace root. For a configuration stored elsewhere, use an absolute path to `scripts/keel_mcp.py`.

## Operator files, scanner paths, and data directory

All clients must expose the operator approval file and ProjectDiscovery `httpx`/`nuclei` to the Keel subprocess. Proof playbooks additionally need the credential-reference file. If `keel-pentest doctor` succeeds in a terminal but waves fail in a GUI client, the GUI probably did not inherit the same environment. Add absolute paths to that client's server environment:

```json
{
  "KEEL_HTTPX_BIN": "/absolute/path/to/projectdiscovery/httpx",
  "KEEL_NUCLEI_BIN": "/absolute/path/to/nuclei",
  "KEEL_DATA_DIR": "/absolute/operator-controlled/path/for/keel",
  "KEEL_APPROVAL_FILE": "/safe/operator/path/keel-approval.json",
  "KEEL_CREDENTIALS_FILE": "/safe/operator/path/keel-credentials.json"
}
```

Use the equivalent `env` table/object for the selected client (`environment` on OpenCode v2). Keep approval, credentials, and preferably state outside the AI-writable workspace. `KEEL_ALLOW_UNAPPROVED_RECON=1` is a development-only escape hatch, not a client setup shortcut.

## What was actually validated

Audit date: 2026-08-23.

- A clean wheel completed MCP initialize and `tools/list` handshakes with both Python MCP SDK 1.9.0 and 2.0.0; both exposed all ten Keel tools.
- OpenCode 1.18.21 started the repository configuration and reported Keel connected.
- Claude Code 2.1.181, Codex CLI 0.144.1, Gemini CLI 0.55.1, and Antigravity CLI 1.1.16 command syntax/config discovery were checked locally. Codex loaded the checked-in server entry; Claude still requires normal project trust approval.
- Cursor, VS Code/GitHub Copilot, Hermes, Windsurf, Cline, and Roo formats were checked against their current official documentation because those executables were not installed in the audit environment.

That distinction matters: Keel's stdio protocol and package were exercised directly, but no repository can truthfully guarantee every future release of every host. The files above follow each host's current schema and include a direct verification command where the host provides one.
