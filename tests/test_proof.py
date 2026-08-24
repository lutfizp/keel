import httpx
import pytest

from keel.proof import http as proof_http
from keel.engagement.policy import EngagementPolicy
from keel.errors import ProofFailed, TargetThrottled
from keel.models import FindingCard, ValidationState
from keel.proof.catalog import PLAYBOOK_CROSS_ACCOUNT_READ, draft_playbook
from keel.proof.http import ProofRequestBroker
from keel.proof.runner import run_playbook
from keel.proof.sanitize import clip, sanitize_evidence
from keel.schedule.bucket import BucketMap


def test_draft_cross_account() -> None:
    draft = draft_playbook(PLAYBOOK_CROSS_ACCOUNT_READ, "card", "https://h/item/1")
    assert len(draft.requests) == 2
    assert draft.requests[0]["method"] == "GET"
    assert draft.request_budget == 2
    assert draft.required_inputs == ["proof_target_ref", "expected_marker"]


def test_clip_redacts_bearer() -> None:
    text = clip("Authorization: Bearer supersecretvalue")
    assert "supersecretvalue" not in text
    assert "[redacted]" in text


def test_clip_redacts_cookie_headers() -> None:
    text = clip("Cookie: session=supersecret\nSet-Cookie: auth=anothersecret")

    assert "supersecret" not in text
    assert "anothersecret" not in text


def test_scanner_evidence_drops_raw_requests_and_secrets() -> None:
    cleaned = sanitize_evidence(
        {
            "request": "GET /private Authorization: Bearer secret",
            "response": "user@example.com",
            "note": "Authorization: Bearer secret",
        }
    )

    assert cleaned["request"] == "[redacted]"
    assert cleaned["response"] == "[redacted]"
    assert "secret" not in cleaned["note"]


def _policy() -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="proof",
        scope_hosts=["app.example.com"],
        requests_per_second=20,
        allow_safe_proof=True,
        operator_confirmed=True,
        approved_playbooks=[PLAYBOOK_CROSS_ACCOUNT_READ],
        approved_credential_refs=["tester-a", "tester-b"],
    )


def _card() -> FindingCard:
    return FindingCard(
        card_id="idor",
        fingerprint="idor",
        semantic_key="idor",
        host="app.example.com",
        path="/objects/1",
        matcher="idor",
        title="BOLA",
        scanner_severity="high",
        vulnerability_class="broken_object_authorization",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/objects/1"},
    )


def _run_with(handler) -> dict:
    policy = _policy()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    broker = ProofRequestBroker(policy, BucketMap(20), 2, client=client)
    try:
        return run_playbook(
            policy,
            _card(),
            PLAYBOOK_CROSS_ACCOUNT_READ,
            "tester-a",
            "tester-b",
            "keel-canary-1234",
            broker,
            credential_resolver=lambda ref, _: {"Authorization": ref},
        )
    finally:
        client.close()


def test_working_access_control_is_protected_not_proven() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Authorization"] == "tester-a":
            return httpx.Response(200, text='{"note":"keel-canary-1234"}')
        return httpx.Response(403, text="denied")

    outcome = _run_with(handler)

    assert outcome["decision"] == "protected"
    assert outcome["marker_seen_a"] is True
    assert outcome["marker_seen_b"] is False


def test_cross_account_canary_access_is_proven() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='{"note":"keel-canary-1234"}')

    outcome = _run_with(handler)

    assert outcome["decision"] == "proven"
    assert outcome["marker_seen_a"] is True
    assert outcome["marker_seen_b"] is True
    assert "body_a" not in outcome and "body_b" not in outcome


def test_status_equality_without_canary_is_not_proof() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = "owned baseline keel-canary-1234" if request.headers["Authorization"] == "tester-a" else "generic page"
        return httpx.Response(200, text=body)

    assert _run_with(handler)["decision"] == "protected"


def test_server_error_for_tester_b_is_inconclusive_not_protected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Authorization"] == "tester-a":
            return httpx.Response(200, text="owned keel-canary-1234")
        return httpx.Response(500, text="internal error")

    assert _run_with(handler)["decision"] == "inconclusive"


def test_truncated_tester_b_response_without_canary_is_inconclusive() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Authorization"] == "tester-a":
            return httpx.Response(200, text="owned keel-canary-1234")
        return httpx.Response(200, content=b"x" * 70_000)

    outcome = _run_with(handler)

    assert outcome["response_truncated_b"] is True
    assert outcome["decision"] == "inconclusive"


def test_broker_stops_immediately_on_429() -> None:
    policy = _policy()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(429, headers={"Retry-After": "90"})
        )
    )
    broker = ProofRequestBroker(policy, BucketMap(20), 2, client=client)
    try:
        with pytest.raises(TargetThrottled) as caught:
            broker.get("https://app.example.com/objects/1", {})
    finally:
        client.close()

    assert caught.value.retry_after_seconds == 90


def test_broker_does_not_inherit_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    original_client = proof_http.httpx.Client

    def client_factory(**kwargs: object) -> httpx.Client:
        captured.update(kwargs)
        return original_client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, text="ok")),
            **kwargs,
        )

    monkeypatch.setattr(proof_http.httpx, "Client", client_factory)
    broker = ProofRequestBroker(_policy(), BucketMap(20), 1)

    broker.get("https://app.example.com/objects/1", {})

    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False


def test_broker_wraps_transport_errors_without_response_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("target offline", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    broker = ProofRequestBroker(_policy(), BucketMap(20), 1, client=client)
    try:
        with pytest.raises(ProofFailed, match="ConnectError"):
            broker.get("https://app.example.com/objects/1", {})
    finally:
        client.close()


def _run_named(playbook_id: str, card: FindingCard, handler, marker: str = "keel-canary-1234") -> dict:
    policy = _policy()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    broker = ProofRequestBroker(policy, BucketMap(20), 2, client=client)
    try:
        return run_playbook(
            policy,
            card,
            playbook_id,
            "tester-a",
            "tester-b",
            marker,
            broker,
            credential_resolver=lambda ref, _: {"Authorization": ref} if ref else {},
        )
    finally:
        client.close()


def test_reflected_marker_proves_unescaped_html_and_emits_repro() -> None:
    from keel.proof.catalog import PLAYBOOK_REFLECTED_MARKER
    from keel.proof.runner import _reflection_probe

    marker = "keelxss99"
    probe = _reflection_probe(marker)
    card = FindingCard(
        card_id="xss",
        fingerprint="xss",
        semantic_key="xss",
        host="app.example.com",
        path="/search",
        matcher="xss",
        title="Reflected XSS",
        scanner_severity="high",
        vulnerability_class="cross_site_scripting",
        parameter="q",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/search?q=test"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        query = str(request.url.params.get("q", ""))
        if probe in query:
            return httpx.Response(200, text=f"<html>result {probe}</html>")
        return httpx.Response(200, text="<html>result test</html>")

    outcome = _run_named(PLAYBOOK_REFLECTED_MARKER, card, handler, marker)

    assert outcome["decision"] == "proven"
    assert "curl" in outcome["repro_script"]
    assert "without changing server data" in outcome["hunter_impact"] or outcome["hunter_impact"]


def test_reflected_marker_html_encoding_is_protected() -> None:
    from keel.proof.catalog import PLAYBOOK_REFLECTED_MARKER
    import html as html_lib
    from keel.proof.runner import _reflection_probe

    marker = "keelxss99"
    probe = _reflection_probe(marker)
    card = FindingCard(
        card_id="xss",
        fingerprint="xss",
        semantic_key="xss",
        host="app.example.com",
        path="/search",
        matcher="xss",
        title="Reflected XSS",
        scanner_severity="high",
        vulnerability_class="cross_site_scripting",
        parameter="q",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/search?q=test"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        query = str(request.url.params.get("q", ""))
        if probe in query:
            return httpx.Response(200, text=f"<html>result {html_lib.escape(probe)}</html>")
        return httpx.Response(200, text="<html>result test</html>")

    assert _run_named(PLAYBOOK_REFLECTED_MARKER, card, handler, marker)["decision"] == "protected"


def test_open_redirect_canary_proves_offsite_location() -> None:
    from keel.proof.catalog import PLAYBOOK_OPEN_REDIRECT_CANARY
    from keel.proof.runner import REDIRECT_CANARY_HOST

    marker = "keelredir1"
    card = FindingCard(
        card_id="redir",
        fingerprint="redir",
        semantic_key="redir",
        host="app.example.com",
        path="/out",
        matcher="redirect",
        title="Open redirect",
        scanner_severity="medium",
        vulnerability_class="open_redirect",
        parameter="next",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/out?next=/home"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        nxt = str(request.url.params.get("next", ""))
        if REDIRECT_CANARY_HOST in nxt:
            return httpx.Response(302, headers={"Location": nxt})
        return httpx.Response(302, headers={"Location": "/home"})

    outcome = _run_named(PLAYBOOK_OPEN_REDIRECT_CANARY, card, handler, marker)
    assert outcome["decision"] == "proven"
    assert outcome["redirect_host"] == REDIRECT_CANARY_HOST


def test_unauth_access_probe_proves_missing_session_check() -> None:
    from keel.proof.catalog import PLAYBOOK_UNAUTH_ACCESS_PROBE

    card = FindingCard(
        card_id="expo",
        fingerprint="expo",
        semantic_key="expo",
        host="app.example.com",
        path="/objects/1",
        matcher="exposure",
        title="Unauth data",
        scanner_severity="high",
        vulnerability_class="sensitive_data_exposure",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/objects/1"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="owned keel-canary-1234")

    outcome = _run_named(PLAYBOOK_UNAUTH_ACCESS_PROBE, card, handler)
    assert outcome["decision"] == "proven"
    assert "no session" in outcome["hunter_impact"]
