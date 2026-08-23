from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

from keel.engagement.policy import EngagementPolicy
from keel.errors import ProofDenied
from keel.models import (
    CardStatus,
    EvidenceStrength,
    FindingCard,
    ValidationState,
)
from keel.proof.catalog import PLAYBOOK_CROSS_ACCOUNT_READ, PLAYBOOK_OWN_SESSION_MARKER
from keel.proof.credentials import resolve_credential
from keel.proof.http import ProofRequestBroker
from keel.triage.filters import priority_score


_CANARY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_ACCESS_CONTROL_CLASSES = {
    "broken_object_authorization",
    "missing_authorization",
    "incorrect_authorization",
    "authentication_bypass",
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
    headers_a = credential_resolver(ref_a, policy.approved_credential_refs)

    if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
        if card.vulnerability_class not in _ACCESS_CONTROL_CLASSES:
            raise ProofDenied(
                "cross_account_read only applies to an access-control finding class"
            )
        headers_b = credential_resolver(ref_b, policy.approved_credential_refs)
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
        return {
            "playbook_id": playbook_id,
            "decision": decision,
            "reason": reason,
            "marker_sha256": hashlib.sha256(expected_marker.encode()).hexdigest(),
            "status_a": first.status_code,
            "status_b": second.status_code,
            "marker_seen_a": marker_a,
            "marker_seen_b": marker_b,
            "body_sha256_a": first.body_sha256,
            "body_sha256_b": second.body_sha256,
            "same_body_hash": first.body_sha256 == second.body_sha256,
            "response_truncated_a": first.truncated,
            "response_truncated_b": second.truncated,
            "requests_made": broker.requests_made,
        }
    if playbook_id == PLAYBOOK_OWN_SESSION_MARKER:
        response = broker.get(url, headers_a)
        marker_seen = expected_marker in response.body
        decision = (
            "corroborated"
            if 200 <= response.status_code < 300 and marker_seen
            else "inconclusive"
        )
        return {
            "playbook_id": playbook_id,
            "decision": decision,
            "reason": "manual tester-owned canary read; this is not vulnerability proof",
            "marker_sha256": hashlib.sha256(expected_marker.encode()).hexdigest(),
            "status_a": response.status_code,
            "marker_seen_a": marker_seen,
            "body_sha256_a": response.body_sha256,
            "response_truncated_a": response.truncated,
            "requests_made": broker.requests_made,
        }
    raise ProofDenied(f"unknown playbook {playbook_id}")


def mark_proven(card: FindingCard) -> FindingCard:
    card.status = CardStatus.PROVEN
    card.validation_state = ValidationState.PROVEN
    card.evidence_strength = EvidenceStrength.SAFE_PROOF
    card.confidence = max(card.confidence, 0.95)
    card.priority_score = priority_score(card)
    return card


def mark_refuted(card: FindingCard) -> FindingCard:
    card.status = CardStatus.NOISE
    card.validation_state = ValidationState.REFUTED
    card.evidence_strength = EvidenceStrength.SAFE_PROOF
    card.confidence = min(card.confidence, 0.2)
    card.priority_score = priority_score(card)
    return card


def _validate_canary(value: str) -> None:
    if not _CANARY.fullmatch(value):
        raise ProofDenied(
            "expected_marker must be an 8-128 character non-secret canary "
            "using letters, digits, dot, underscore, colon, or dash"
        )
