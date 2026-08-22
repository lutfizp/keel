# Connect Keel to an MCP client

The MCP server id is **`keel`**. The PyPI package and console script are **`keel-pentest`**. The Python module is **`keel`**.

Set `PYTHONUNBUFFERED=1` so JSON-RPC is not buffered.

## PyPI (`pip` / `pipx` / `uv`)

Install: `python -m pip install keel-pentest` (see [INSTALL.md](../INSTALL.md)). Then point the client at the script from that environment. Resolve it with `command -v keel-pentest` (Windows: `where keel-pentest`).

Claude Desktop / Cursor / Windsurf / Cline / Roo / Continue / Gemini — copy [mcpServers.pypi.json](mcpServers.pypi.json) and replace `REPLACE_WITH_KEEL_PENTEST` with that absolute path:

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

Claude Code:

```bash
claude mcp add --scope user --transport stdio keel -- /ABS/path/to/.venv/bin/keel-pentest
```

Codex — merge [codex.pypi.toml](codex.pypi.toml) or:

```bash
codex mcp add keel -- /ABS/path/to/.venv/bin/keel-pentest
```

OpenCode (user or project config; use the venv script, not a random `python3`):

```json
{
  "mcp": {
    "keel": {
      "type": "local",
      "command": ["/ABS/path/to/.venv/bin/keel-pentest"],
      "enabled": true
    }
  }
}
```

Hermes — merge [hermes.pypi.yaml](hermes.pypi.yaml), or:

```bash
hermes mcp add --command /ABS/path/to/.venv/bin/keel-pentest keel
```

`python -m keel` is the same process as `keel-pentest`. Only use a `python` that already has `keel-pentest` installed.

## Local clone (this git repo)

```text
python3 scripts/keel_mcp.py
```

The launcher uses a Python 3.10+ `.venv` from `scripts/bootstrap.sh` and runs `python -m keel`.

When this directory is the workspace root:

| Host | File |
|------|------|
| OpenCode | `opencode.json` |
| Claude Code | `.mcp.json` |
| Cursor | `.cursor/mcp.json` |
| VS Code / Copilot | `.vscode/mcp.json` |
| Codex | `.codex/config.toml` |

Restart the client after bootstrap.

Claude Code:

```bash
cd /path/to/keel
claude mcp add --scope project --transport stdio keel -- python3 scripts/keel_mcp.py
```

Claude Desktop-style: copy [mcpServers.json](mcpServers.json), replace `REPLACE_WITH_REPO` with the absolute path of the clone.

Codex:

```bash
codex mcp add keel -- python3 /ABS/keel/scripts/keel_mcp.py
```

Or merge [codex.toml](codex.toml).

Hermes: merge [hermes.yaml](hermes.yaml) or:

```bash
hermes mcp add --command python3 --args /ABS/keel/scripts/keel_mcp.py keel
```

OpenCode (already in `opencode.json`):

```json
{
  "mcp": {
    "keel": {
      "type": "local",
      "command": ["python3", "scripts/keel_mcp.py"]
    }
  }
}
```

OpenCode v2 uses `mcp.servers` instead of a flat `mcp` map; keep the same `command` array.

## Check

The connected server named `keel` should list: `begin_engagement`, `draft_waves`, `execute_wave`, `query_cards`, `second_look`, `state_impact`, `draft_proof`, `execute_proof`, `engagement_health`.
