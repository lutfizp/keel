# Connect Keel to any MCP client

Keel is a **stdio MCP server** for pentest and bug bounty copilots. Clone **https://github.com/lutfizp/keel** and spawn:

```text
python3 scripts/keel_mcp.py
```

The launcher picks a Python 3.10+ `.venv` (see `scripts/bootstrap.sh`). Set `PYTHONUNBUFFERED=1` so JSON-RPC is not buffered.

When this directory is the Git repo root, these files are already in place:

| Host | File |
|------|------|
| OpenCode | `opencode.json` |
| Claude Code | `.mcp.json` |
| Cursor | `.cursor/mcp.json` |
| VS Code / Copilot | `.vscode/mcp.json` |
| Codex CLI / IDE | `.codex/config.toml` |

Restart the client after `sh scripts/bootstrap.sh`.

## Claude Code

```bash
cd /path/to/keel
claude mcp add --scope project --transport stdio keel -- python3 scripts/keel_mcp.py
```

User-wide: `claude mcp add --scope user ...` (writes `~/.claude.json`).

## Claude Desktop / Cursor / Windsurf / Cline / Roo / Continue

Use the `mcpServers` object (Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS).

Copy `clients/mcpServers.json` and replace `REPLACE_WITH_REPO` with the absolute path to the **keel** repo.

## Codex

```bash
codex mcp add keel -- python3 /ABS/keel/scripts/keel_mcp.py
```

Or merge `clients/codex.toml` into `~/.codex/config.toml`.

## Hermes

Merge `clients/hermes.yaml` into `~/.hermes/config.yaml`:

```bash
hermes mcp add --command python3 --args /ABS/keel/scripts/keel_mcp.py keel
```

Reload with `/reload-mcp` if the session is already open.

## Gemini CLI / Antigravity (`agy`)

Add the same `mcpServers.keel` block as Claude Desktop to Gemini / Antigravity MCP settings (often `~/.gemini/settings.json`). Point `agy` at Keel’s stdio command.

## OpenCode

```json
{
  "mcp": {
    "servers": {
      "keel": {
        "type": "local",
        "command": ["python3", "scripts/keel_mcp.py"]
      }
    }
  }
}
```

## Check

`keel` should expose `begin_engagement`, `draft_waves`, `execute_wave`, `query_cards`, `second_look`, `state_impact`, `draft_proof`, `execute_proof`, `engagement_health`.
