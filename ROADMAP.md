# Proposed roadmap

This lists work that is not yet implemented. Success means accepted, high-confidence findings per bounded request—not raw alert volume.

## P0 — exact external-scanner enforcement

Build a version-pinned instrumented transport or egress proxy so every scanner request receives exact scope, DNS/IP, redirect, byte, retry, cancellation, deadline, and request-count enforcement. Current background jobs, cancellation, micro-waves, and terminal retries improve orchestration but do not make opaque CLI internals exact.

Add signed canonical operator policies with monotonic revocation versions, plus a Nuclei template safety compiler that calculates methods, paths, protocols, payload cardinality, forbidden capabilities, and worst-case requests before approval.

## P1 — safe proof coverage

Extend typed exploitability assessment into a declarative differential-proof DSL: `setup -> baseline -> alternate principal/control -> invariant -> cleanup`. Validators must declare typed inputs, read/write budgets, negative controls, state transitions, evidence fields, and cleanup guarantees.

Prioritize disposable tester-owned scenarios:

- cross-role read/write authorization;
- harmless mass-assignment canaries;
- workflow bypass on disposable drafts;
- benign file visibility and cache separation;
- open redirect to an operator-owned inert endpoint;
- private opt-in OAST with one short-lived token and no target data.

## P1 — discovery yield

Build an explainable graph of routes, parameters, object ownership, roles, and observed controls. Track support, duplicate, contradiction, and same-symptom/different-cause edges. Prioritize surface deltas and separate detector, skeptic, and deterministic validator roles; models may rank candidates but cannot vote them into `proven`.

## P2 — calibration and reporting

Add offline replay against sanitized fixtures/local replicas, bounded attack-chain graphs, accepted/duplicate/false-positive outcome calibration, and redacted evidence packs containing approval ID, preconditions, request count, negative control, result hashes, impact, and remediation.

Track accepted findings per 100 requests, duplicate compression, false-proof rate, cleanup success, throttle events, terminal waves, cancellations, and operator overrides.
