# Keel security model

Keel 0.3.0 treats the AI/MCP client as untrusted for authorization. The operator-owned approval manifest controls exact scope, exclusions, expiry, traffic and retry ceilings, reviewed Nuclei templates, credential references, playbooks, and proof targets.

## Traffic and jobs

- Each reviewed Nuclei template is a separate micro-wave.
- One wave runs per host; same-host background jobs wait for that slot.
- Every started attempt reserves a new conservative request allowance.
- Failed waves become `terminal_failed` at `max_wave_attempts`.
- `wave_status` exposes persistent stages/results and `cancel_wave` terminates the managed scanner process.
- Jobs active during server termination restore as `interrupted`; their wave keeps its attempt state.

Proof HTTP traffic is mediated per request. External `httpx` and Nuclei traffic is still controlled through conservative CLI flags and reservations rather than a packet-level interceptor, so its internal request count remains approximate.

## Evidence

Scanner JSONL is atomic. A malformed/non-object line, invalid result schema, nonzero exit, timeout, or cancellation causes zero partial ingest.

Typed exploitability assessment supplies a candidate impact, required evidence, negative control, and implemented safe-proof options. Severity and agent narrative cannot create proof. Only deterministic validation can set `proven` or `refuted`.

Currently only `cross_account_read` proves a vulnerability: tester A must establish a unique canary baseline and tester B must read the identical canary from the exact same A-owned URL. Other classes remain candidates until a class-specific safe validator exists.

## Boundaries

Keel cannot establish legal authority, guarantee coverage or bounty acceptance, safely prove arbitrary SQLi/RCE/SSRF/XSS/business logic, or defend its SQLite audit from a malicious local machine owner. Scanner binaries/templates and the operator's program-rule translation remain trusted components.

See [ROADMAP.md](ROADMAP.md) for remaining work.
