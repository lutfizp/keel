# Keel

<!-- mcp-name: io.github.lutfizp/keel -->

Keel is a small control plane MCP server. It exposes nine tools. It does not wrap HexStrike and does not put scanner binaries on the model.

The agent plans waves. Keel enforces scope, a per-host token bucket, finding merge, hunter triage, and bounded proofs on researcher test accounts.

## Install

Use the OS-aware installer (Python 3.10+, venv, pip upgrade, Keel, ProjectDiscovery `httpx` and `nuclei`):

```bash
git clone https://github.com/lutfizp/keel.git
cd keel
sh scripts/bootstrap.sh
```

Windows: `powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1`

Do **not** create the venv with Apple `/usr/bin/python3` (often 3.9). The `mcp` package has no 3.9 wheels, which produces `No matching distribution found for mcp>=1.9`.

Per-OS steps: [INSTALL.md](INSTALL.md).

## OpenCode

`opencode.json` in this repo uses the launcher. Open the **keel** repository as the workspace:

```json
"command": ["python3", "scripts/keel_mcp.py"]
```

Optional overrides: `KEEL_PYTHON` (interpreter) or `KEEL_ROOT` (directory that contains `.venv`).

OpenCode v2 uses `mcp.servers` instead of a flat `mcp` map. Keep the same `command` array.

The same stdio server works in Claude Code, Claude Desktop, Codex, Cursor, VS Code, Gemini CLI, Hermes, Antigravity (`agy`), Windsurf, Cline, and Roo. Snippets and install commands: [clients/README.md](clients/README.md).

## MCP tools

| Tool | Role |
|------|------|
| `begin_engagement` | Scope, RPS, proof flags |
| `draft_waves` | Propose `probe_alive` then `template_scan` |
| `execute_wave` | Run one wave |
| `query_cards` | Cards without informational/hardening by default |
| `second_look` | Bounded rescan of one card |
| `state_impact` | Hunter `impact_class` |
| `draft_proof` | Allowlisted proof plan |
| `execute_proof` | Proof only if `allow_safe_proof` and `operator_confirmed` |
| `engagement_health` | Cooldowns and queue |

Proof playbooks: `cross_account_read`, `own_session_marker`.

## Example prompts

Replace `target.example` with an in-scope host. Always start with `begin_engagement` unless the engagement already exists. OpenCode must call **Keel MCP**, not shell `nuclei`/`httpx`.

### End-to-end bug bounty

Paste this after MCP `keel` is connected:

```
You are a bug bounty hunter. Use only the Keel MCP tools. Do not run nmap, nuclei, or httpx yourself.

1. begin_engagement:
   - engagement_id: bb-2026-01
   - scope_hosts: ["target.example"]
   - exclude_hosts: []
   - requests_per_second: 3
   - allow_safe_proof: false
   - operator_confirmed: false

2. draft_waves with seed_url https://target.example
3. execute_wave once per wave_id, wait for each to finish
4. query_cards (include_noise false)
5. For each remaining card, state_impact with a hunter impact_class
   (none / hardening / sensitive_access / account_takeover / rce / data_other_users)
   and why a hunter would care. Drop informational and missing-header noise.
6. For cards that still look like real impact, draft_proof only
   (playbook_id: cross_account_read or own_session_marker).
   Do not call execute_proof until I say the word CONFIRM.

Stop after draft_proof. Summarize cards, impact, and the proof plan in English.
```

When you are ready to run a bounded proof (tester accounts only):

```
CONFIRM. Call begin_engagement again on bb-2026-01 with allow_safe_proof true
and operator_confirmed true, then execute_proof on card <card_id>
playbook_id cross_account_read. session_a and session_b are my tester
Authorization headers. One request pair. No DoS, no other users' data.
```

### Recon only

```
Keel MCP only. begin_engagement id recon-1, scope_hosts ["target.example"],
RPS 2, allow_safe_proof false. draft_waves for https://target.example.
execute_wave only the probe_alive wave. Do not run template_scan.
Then engagement_health. Tell me which hosts answered. Stop.
```

### Templates only (after recon)

```
Engagement recon-1 is already open. draft_waves is done. execute_wave only
the template_scan wave_id. Then query_cards. Do not draft_proof. Stop.
```

### Cards / triage only

```
query_cards for engagement_id bb-2026-01. If empty, query_cards with
include_noise true and list what you would drop as hardening. No new waves.
```

### Impact only

```
state_impact on card <card_id>, engagement bb-2026-01.
impact_class data_other_users if IDOR-like, else none.
preconditions: two tester accounts. hunter_why: one sentence.
Do not scan and do not prove.
```

### Proof plan only (no traffic)

```
draft_proof engagement bb-2026-01 card <card_id> playbook_id own_session_marker.
Do not execute_proof.
```

### Status

```
engagement_health for bb-2026-01. If unknown, engagement_health with no id.
```

## Layout

Policy, scheduler, adapters, parsers, store, triage, and proof live in separate packages under `src/keel/`.

## PyPI and MCP Registry

PyPI package name is `keel-mcp`. Registry name is `io.github.lutfizp/keel`. Publish steps: [PUBLISH.md](PUBLISH.md).
