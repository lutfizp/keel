from keel.models import ProofDraft

PLAYBOOK_CROSS_ACCOUNT_READ = "cross_account_read"
PLAYBOOK_OWN_SESSION_MARKER = "own_session_marker"

_PLAYBOOKS = {
    PLAYBOOK_CROSS_ACCOUNT_READ: (
        "GET the same object URL twice using tester session A then session B. "
        "A mismatch (A 200 with B body, B 403 or different owner) is the proof. "
        "Only tester accounts. One request pair. No writes."
    ),
    PLAYBOOK_OWN_SESSION_MARKER: (
        "Submit a unique researcher marker in a field the tester already owns. "
        "Confirm the marker echoes in the tester session only. No other users."
    ),
}


def known_playbooks() -> dict[str, str]:
    return dict(_PLAYBOOKS)


def draft_playbook(playbook_id: str, card_id: str, url: str) -> ProofDraft:
    if playbook_id not in _PLAYBOOKS:
        raise KeyError(playbook_id)
    if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
        steps = [
            "Send GET with tester A Authorization or Cookie",
            "Send GET with tester B Authorization or Cookie",
            "Compare status and owner fields; stop",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "tester_a"},
            {"method": "GET", "url": url, "as": "tester_b"},
        ]
    else:
        steps = [
            "PUT or POST a unique marker on a tester-owned resource",
            "GET the same resource in the same session",
            "Confirm marker; do not touch other accounts",
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
    )
