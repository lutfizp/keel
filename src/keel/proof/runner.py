from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from keel.engagement.policy import EngagementPolicy
from keel.errors import ProofDenied
from keel.models import (
    CardStatus,
    EvidenceStrength,
    FindingCard,
    ValidationState,
)
from keel.proof.catalog import (
    PLAYBOOK_CROSS_ACCOUNT_READ,
    PLAYBOOK_OPEN_REDIRECT_CANARY,
    PLAYBOOK_OWN_SESSION_MARKER,
    PLAYBOOK_REFLECTED_MARKER,
    PLAYBOOK_UNAUTH_ACCESS_PROBE,
)
from keel.proof.credentials import resolve_credential
from keel.proof.http import ProofRequestBroker, SafeResponse
from keel.triage.exploitability import assess_card
from keel.triage.filters import priority_score


_CANARY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_ACCESS_CONTROL_CLASSES = {
    "broken_object_authorization",
    "missing_authorization",
    "incorrect_authorization",
    "authentication_bypass",
}
_REFLECTED_CLASSES = {
    "cross_site_scripting",
    "html_injection",
}
_REDIRECT_CLASSES = {
    "open_redirect",
}
_UNAUTH_CLASSES = {
    "broken_object_authorization",
    "missing_authorization",
    "incorrect_authorization",
    "authentication_bypass",
    "sensitive_data_exposure",
}
REDIRECT_CANARY_HOST = "keel-proof.invalid"
PROVING_PLAYBOOKS = {
    PLAYBOOK_CROSS_ACCOUNT_READ,
    PLAYBOOK_REFLECTED_MARKER,
    PLAYBOOK_OPEN_REDIRECT_CANARY,
    PLAYBOOK_UNAUTH_ACCESS_PROBE,
}


def run_playbook(
    policy: EngagementPolicy,
    card: FindingCard,
    playbook_id: str,
    session_a: str,
    session_b: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    credential_resolver: Callable[[str, list[str]], dict[str, str]] = resolve_credential,
) -> dict:
    if not policy.allow_safe_proof or not policy.operator_confirmed:
        raise ProofDenied("safe proof does not have an active operator approval")
    url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
    if not url:
        raise ProofDenied("card has no URL")
    if not policy.url_allowed(url):
        raise ProofDenied("card URL is outside exact engagement scope")
    _validate_canary(expected_marker)
    ref_a = session_a or policy.tester_account_a
    ref_b = session_b or policy.tester_account_b
    allowed = policy.approved_credential_refs
    headers_a = credential_resolver(ref_a, allowed) if ref_a else {}

    if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
        return _run_cross_account(
            card, url, expected_marker, broker, headers_a, credential_resolver(ref_b, allowed)
        )
    if playbook_id == PLAYBOOK_OWN_SESSION_MARKER:
        return _run_own_session(url, expected_marker, broker, headers_a)
    if playbook_id == PLAYBOOK_REFLECTED_MARKER:
        return _run_reflected(policy, card, url, expected_marker, broker, headers_a)
    if playbook_id == PLAYBOOK_OPEN_REDIRECT_CANARY:
        return _run_open_redirect(policy, card, url, expected_marker, broker, headers_a)
    if playbook_id == PLAYBOOK_UNAUTH_ACCESS_PROBE:
        if not ref_a:
            raise ProofDenied("unauth_access_probe requires tester A credentials for the baseline")
        return _run_unauth(card, url, expected_marker, broker, headers_a)
    raise ProofDenied(f"unknown playbook {playbook_id}")


def mark_proven(card: FindingCard) -> FindingCard:
    card.status = CardStatus.PROVEN
    card.validation_state = ValidationState.PROVEN
    card.evidence_strength = EvidenceStrength.SAFE_PROOF
    card.confidence = max(card.confidence, 0.95)
    card = assess_card(card)
    card.priority_score = priority_score(card)
    return card


def mark_refuted(card: FindingCard) -> FindingCard:
    card.status = CardStatus.NOISE
    card.validation_state = ValidationState.REFUTED
    card.evidence_strength = EvidenceStrength.SAFE_PROOF
    card.confidence = min(card.confidence, 0.2)
    card = assess_card(card)
    card.priority_score = priority_score(card)
    return card


def _run_cross_account(
    card: FindingCard,
    url: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    headers_a: dict[str, str],
    headers_b: dict[str, str],
) -> dict:
    if card.vulnerability_class not in _ACCESS_CONTROL_CLASSES:
        raise ProofDenied("cross_account_read only applies to an access-control finding class")
    first = broker.get(url, headers_a)
    second = broker.get(url, headers_b)
    marker_a = expected_marker in first.body
    marker_b = expected_marker in second.body
    first_ok = 200 <= first.status_code < 300
    second_ok = 200 <= second.status_code < 300
    if first_ok and second_ok and marker_a and marker_b:
        decision = "proven"
        reason = "tester B read the unique canary from tester A's resource"
    elif first_ok and marker_a and (
        second.status_code in {401, 403, 404}
        or (second_ok and not marker_b and not second.truncated)
    ):
        decision = "protected"
        reason = "tester B could not read tester A's unique canary"
    else:
        decision = "inconclusive"
        reason = "tester A baseline or tester B response did not satisfy proof invariants"
    return _outcome(
        PLAYBOOK_CROSS_ACCOUNT_READ,
        decision,
        reason,
        expected_marker,
        broker,
        hunter_impact=(
            "A second in-scope tester account can read the unique object owned by tester A. "
            "An attacker with a normal user account can do the same to other users."
            if decision == "proven"
            else ""
        ),
        repro_script=_repro_script([("tester A (owner)", url), ("tester B (peer)", url)]),
        extra={
            "status_a": first.status_code,
            "status_b": second.status_code,
            "marker_seen_a": marker_a,
            "marker_seen_b": marker_b,
            "body_sha256_a": first.body_sha256,
            "body_sha256_b": second.body_sha256,
            "same_body_hash": first.body_sha256 == second.body_sha256,
            "response_truncated_a": first.truncated,
            "response_truncated_b": second.truncated,
        },
    )


def _run_own_session(
    url: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    headers_a: dict[str, str],
) -> dict:
    response = broker.get(url, headers_a)
    marker_seen = expected_marker in response.body
    decision = (
        "corroborated"
        if 200 <= response.status_code < 300 and marker_seen
        else "inconclusive"
    )
    return _outcome(
        PLAYBOOK_OWN_SESSION_MARKER,
        decision,
        "manual tester-owned canary read; this is not vulnerability proof",
        expected_marker,
        broker,
        extra={
            "status_a": response.status_code,
            "marker_seen_a": marker_seen,
            "body_sha256_a": response.body_sha256,
            "response_truncated_a": response.truncated,
        },
    )


def _run_reflected(
    policy: EngagementPolicy,
    card: FindingCard,
    url: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    headers_a: dict[str, str],
) -> dict:
    if card.vulnerability_class not in _REFLECTED_CLASSES:
        raise ProofDenied("reflected_marker only applies to a reflected-injection class")
    probe = _reflection_probe(expected_marker)
    payload_url = _inject_query(url, card.parameter, probe)
    if not policy.url_allowed(payload_url):
        raise ProofDenied("injected proof URL is outside exact engagement scope")
    control = broker.get(url, headers_a)
    payload = broker.get(payload_url, headers_a)
    raw = probe in payload.body
    encoded_only = (not raw) and (
        html.escape(probe) in payload.body or expected_marker in payload.body
    )
    already_present = probe in control.body
    if already_present:
        decision = "inconclusive"
        reason = "negative control already contained the probe; marker is not unique to this request"
    elif 200 <= payload.status_code < 300 and raw and not payload.truncated:
        decision = "proven"
        reason = "the unique probe was reflected unescaped in the response body"
    elif 200 <= payload.status_code < 300 and encoded_only and not payload.truncated:
        decision = "protected"
        reason = "the marker was reflected but HTML-encoded or stripped of angle brackets"
    else:
        decision = "inconclusive"
        reason = "the response did not show a clear unescaped or encoded reflection"
    return _outcome(
        PLAYBOOK_REFLECTED_MARKER,
        decision,
        reason,
        expected_marker,
        broker,
        hunter_impact=(
            "Attacker-controlled input is written into the HTML response without encoding. "
            "A hunter can turn this into a script-execution PoC without changing server data."
            if decision == "proven"
            else ""
        ),
        repro_script=_repro_script(
            [("negative control", url), ("reflected probe", payload_url)]
        ),
        extra={
            "status_control": control.status_code,
            "status_payload": payload.status_code,
            "probe_seen_raw": raw,
            "probe_already_present": already_present,
            "payload_url": payload_url,
            "response_truncated": payload.truncated,
        },
    )


def _run_open_redirect(
    policy: EngagementPolicy,
    card: FindingCard,
    url: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    headers_a: dict[str, str],
) -> dict:
    if card.vulnerability_class not in _REDIRECT_CLASSES:
        raise ProofDenied("open_redirect_canary only applies to an open-redirect class")
    canary_target = f"https://{REDIRECT_CANARY_HOST}/{expected_marker}"
    payload_url = _inject_query(url, card.parameter or "next", canary_target)
    if not policy.url_allowed(payload_url):
        raise ProofDenied("injected proof URL is outside exact engagement scope")
    control = broker.get(url, headers_a)
    payload = broker.get(payload_url, headers_a)
    payload_host = _redirect_host(payload_url, payload)
    control_host = _redirect_host(url, control)
    if control_host == REDIRECT_CANARY_HOST:
        decision = "inconclusive"
        reason = "negative control already redirected to the canary host"
    elif _is_redirect(payload.status_code) and payload_host == REDIRECT_CANARY_HOST:
        decision = "proven"
        reason = "the 3xx Location host is the tester-owned canary keel-proof.invalid"
    elif payload_host != REDIRECT_CANARY_HOST:
        decision = "protected"
        reason = "the response did not redirect to the canary host"
    else:
        decision = "inconclusive"
        reason = "redirect behaviour was ambiguous"
    return _outcome(
        PLAYBOOK_OPEN_REDIRECT_CANARY,
        decision,
        reason,
        expected_marker,
        broker,
        hunter_impact=(
            "The application issues a 3xx to an attacker-controlled host. A hunter can "
            "phish a logged-in user into sending their session to an attacker site."
            if decision == "proven"
            else ""
        ),
        repro_script=_repro_script(
            [("negative control", url), ("canary redirect", payload_url)]
        ),
        extra={
            "status_control": control.status_code,
            "status_payload": payload.status_code,
            "location_payload": payload.location,
            "redirect_host": payload_host,
            "payload_url": payload_url,
        },
    )


def _run_unauth(
    card: FindingCard,
    url: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    headers_a: dict[str, str],
) -> dict:
    if card.vulnerability_class not in _UNAUTH_CLASSES:
        raise ProofDenied("unauth_access_probe only applies to an authorization or exposure class")
    first = broker.get(url, headers_a)
    second = broker.get(url, {})
    marker_a = expected_marker in first.body
    marker_unauth = expected_marker in second.body
    first_ok = 200 <= first.status_code < 300
    second_ok = 200 <= second.status_code < 300
    if first_ok and marker_a and second_ok and marker_unauth:
        decision = "proven"
        reason = "an unauthenticated GET read tester A's unique canary"
    elif first_ok and marker_a and (
        second.status_code in {401, 403, 404}
        or (second_ok and not marker_unauth and not second.truncated)
    ):
        decision = "protected"
        reason = "the unauthenticated GET could not read tester A's unique canary"
    else:
        decision = "inconclusive"
        reason = "owner baseline or unauthenticated response did not satisfy proof invariants"
    return _outcome(
        PLAYBOOK_UNAUTH_ACCESS_PROBE,
        decision,
        reason,
        expected_marker,
        broker,
        hunter_impact=(
            "The object is readable with no session at all. Anyone who knows or guesses the URL "
            "can retrieve another user's data."
            if decision == "proven"
            else ""
        ),
        repro_script=_repro_script([("tester A (owner)", url), ("unauthenticated", url)]),
        extra={
            "status_a": first.status_code,
            "status_unauth": second.status_code,
            "marker_seen_a": marker_a,
            "marker_seen_unauth": marker_unauth,
            "body_sha256_a": first.body_sha256,
            "body_sha256_unauth": second.body_sha256,
            "response_truncated_a": first.truncated,
            "response_truncated_unauth": second.truncated,
        },
    )


def _validate_canary(value: str) -> None:
    if not _CANARY.fullmatch(value):
        raise ProofDenied(
            "expected_marker must be an 8-128 character non-secret canary "
            "using letters, digits, dot, underscore, colon, or dash"
        )


def _reflection_probe(marker: str) -> str:
    return f"{marker}<keel>"


def _inject_query(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    name = (parameter or "q").split(",", 1)[0].strip() or "q"
    pairs = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if key != name
    ]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _is_redirect(status_code: int) -> bool:
    return status_code in {301, 302, 303, 307, 308}


def _redirect_host(request_url: str, response: SafeResponse) -> str:
    if not response.location:
        return ""
    absolute = urljoin(request_url, response.location)
    return (urlparse(absolute).hostname or "").rstrip(".").lower()


def _repro_script(steps: list[tuple[str, str]]) -> str:
    lines = [
        "# Harmless replay. Replace <role> with the tester Authorization or Cookie header.",
        "# This script only sends GET requests and never modifies target data.",
    ]
    for label, url in steps:
        quoted = url.replace("'", "'\\''")
        if label == "unauthenticated":
            lines.append(f"curl -sS -D - -o /tmp/keel-body -X GET '{quoted}'  # {label}")
        else:
            lines.append(
                f"curl -sS -D - -o /tmp/keel-body -X GET '{quoted}' "
                f"-H 'Authorization: <{label}>'  # {label}"
            )
    return "\n".join(lines) + "\n"


def _outcome(
    playbook_id: str,
    decision: str,
    reason: str,
    expected_marker: str,
    broker: ProofRequestBroker,
    *,
    hunter_impact: str = "",
    repro_script: str = "",
    extra: dict | None = None,
) -> dict:
    payload = {
        "playbook_id": playbook_id,
        "decision": decision,
        "reason": reason,
        "marker_sha256": hashlib.sha256(expected_marker.encode()).hexdigest(),
        "requests_made": broker.requests_made,
        "hunter_impact": hunter_impact,
        "repro_script": repro_script,
    }
    if extra:
        payload.update(extra)
    return payload
