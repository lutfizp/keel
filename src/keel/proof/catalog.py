from keel.models import ProofDraft

PLAYBOOK_CROSS_ACCOUNT_READ = "cross_account_read"
PLAYBOOK_OWN_SESSION_MARKER = "own_session_marker"
PLAYBOOK_REFLECTED_MARKER = "reflected_marker"
PLAYBOOK_OPEN_REDIRECT_CANARY = "open_redirect_canary"
PLAYBOOK_UNAUTH_ACCESS_PROBE = "unauth_access_probe"

_PLAYBOOKS = {
    PLAYBOOK_CROSS_ACCOUNT_READ: (
        "GET the same tester-A-owned object twice: once as tester A, once as tester B. "
        "Proof is the unique canary from A's object appearing in B's response. "
        "A 401/403/404 or a 2xx without the canary refutes the finding. Two GETs, no writes."
    ),
    PLAYBOOK_OWN_SESSION_MARKER: (
        "Read a unique canary the operator placed in a tester-owned resource. "
        "This corroborates reachability. It never proves a vulnerability."
    ),
    PLAYBOOK_REFLECTED_MARKER: (
        "GET the finding URL with a unique alphanumeric marker plus a harmless <keel> probe. "
        "Proof is the exact probe coming back unescaped. HTML-encoded or missing reflection "
        "refutes. The control GET is the original URL, which must not already contain the probe."
    ),
    PLAYBOOK_OPEN_REDIRECT_CANARY: (
        "GET the finding URL with a redirect parameter aimed at https://keel-proof.invalid/<marker>. "
        "Proof is a 3xx Location whose host is keel-proof.invalid. Same-origin or missing redirect "
        "refutes. The control GET is the original URL."
    ),
    PLAYBOOK_UNAUTH_ACCESS_PROBE: (
        "GET the tester-A-owned URL with tester A (canary must be visible), then GET the same URL "
        "with no credentials. Proof is a 2xx unauthenticated response that still contains the canary. "
        "A 401/403/404 without the canary refutes. Two GETs, no writes."
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
        budget = 2
        required = ["proof_target_ref", "expected_marker"]
    elif playbook_id == PLAYBOOK_OWN_SESSION_MARKER:
        steps = [
            "Operator places a unique canary in a disposable tester-owned resource",
            "GET the resource once using tester A",
            "Record corroboration only; do not label this a vulnerability proof",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "tester_a", "marker": True},
        ]
        budget = 1
        required = ["proof_target_ref", "expected_marker"]
    elif playbook_id == PLAYBOOK_REFLECTED_MARKER:
        steps = [
            "GET the original URL as a negative control; it must not already contain the probe",
            "GET the same URL with the unique marker and a harmless <keel> probe in the parameter",
            "Prove only if the exact unescaped probe is reflected; HTML encoding refutes",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "control"},
            {"method": "GET", "url": url, "as": "tester_a", "inject": "reflected_probe"},
        ]
        budget = 2
        required = ["proof_target_ref", "expected_marker"]
    elif playbook_id == PLAYBOOK_OPEN_REDIRECT_CANARY:
        steps = [
            "GET the original URL as a negative control; it must not redirect to keel-proof.invalid",
            "GET the URL with the redirect parameter set to https://keel-proof.invalid/<marker>",
            "Prove only if a 3xx Location host is keel-proof.invalid",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "control"},
            {"method": "GET", "url": url, "as": "tester_a", "inject": "redirect_canary"},
        ]
        budget = 2
        required = ["proof_target_ref", "expected_marker"]
    else:
        steps = [
            "GET the tester-A-owned URL with tester A and confirm the unique canary",
            "GET the same URL with no credentials",
            "Prove only if the unauthenticated 2xx response still contains the canary",
        ]
        requests = [
            {"method": "GET", "url": url, "as": "tester_a"},
            {"method": "GET", "url": url, "as": "unauthenticated"},
        ]
        budget = 2
        required = ["proof_target_ref", "expected_marker"]
    return ProofDraft(
        playbook_id=playbook_id,
        card_id=card_id,
        steps=steps,
        requests=requests,
        harm_rationale=_PLAYBOOKS[playbook_id],
        request_budget=budget,
        required_inputs=required,
    )
