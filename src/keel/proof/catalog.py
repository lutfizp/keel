from keel.models import ProofDraft

PLAYBOOK_CROSS_ACCOUNT_READ = "cross_account_read"
PLAYBOOK_OWN_SESSION_MARKER = "own_session_marker"

_PLAYBOOKS = {
    PLAYBOOK_CROSS_ACCOUNT_READ: (
        "GET the same object URL twice using tester session A then session B. "
        "A unique canary already stored in tester A's resource must be visible to both "
        "sessions. A denial or missing canary for B proves the control is working. "
        "Only tester accounts, two GET requests, no writes."
    ),
    PLAYBOOK_OWN_SESSION_MARKER: (
        "Read a unique canary that the operator placed manually in a tester-owned "
        "resource. This corroborates reachability but never proves a vulnerability."
    ),
}


def known_playbooks() -> dict[str, str]:
    return dict(_PLAYBOOKS)


def draft_playbook(playbook_id: str, card_id: str, url: str) -> ProofDraft:
    if playbook_id not in _PLAYBOOKS:
        raise KeyError(playbook_id)
    if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
        steps = [
            "Verify the operator-provided canary is present using tester A",
            "GET the same tester-A-owned URL using tester B",
            "Prove only if the identical canary is visible to B; stop after two requests",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "tester_a"},
            {"method": "GET", "url": url, "as": "tester_b"},
        ]
    else:
        steps = [
            "Operator manually places a unique canary in a disposable tester-owned resource",
            "GET the resource once using tester A",
            "Record corroboration only; do not label this a vulnerability proof",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "tester_a", "marker": True},
        ]
    return ProofDraft(
        playbook_id=playbook_id,
        card_id=card_id,
        steps=steps,
        requests=requests,
        harm_rationale=_PLAYBOOKS[playbook_id],
        request_budget=2 if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ else 1,
        required_inputs=["proof_target_ref", "expected_marker"],
    )
