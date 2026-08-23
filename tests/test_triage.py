from pathlib import Path

import pytest

from keel.catalog.store import CardStore
from keel.engagement.policy import EngagementPolicy
from keel.models import CardStatus, FindingCard, ImpactClass, ValidationState
from keel.proof.runner import mark_proven, mark_refuted
from keel.triage.filters import default_visible, impact_from_severity
from keel.triage.impact import apply_impact


def test_scope_allows_subdomain() -> None:
    policy = EngagementPolicy(engagement_id="e1", scope_hosts=["*.example.com"])
    assert policy.host_allowed("app.example.com")
    assert not policy.host_allowed("example.com")
    assert not policy.host_allowed("evil.com")


def test_hardening_hidden() -> None:
    card = FindingCard(
        card_id="1",
        fingerprint="1",
        host="h",
        path="/",
        matcher="missing-csp",
        title="Missing CSP header",
        scanner_severity="info",
        impact_class=impact_from_severity("info", "missing-csp", "Missing CSP header"),
    )
    assert card.impact_class == ImpactClass.HARDENING
    assert default_visible(card) is False


def test_medium_candidate_visible() -> None:
    card = FindingCard(
        card_id="2",
        fingerprint="2",
        host="h",
        path="/id",
        matcher="idor",
        title="IDOR",
        scanner_severity="high",
        impact_class=ImpactClass.NONE,
    )
    assert default_visible(card) is True


def test_agent_impact_claim_does_not_manufacture_evidence_confidence(
    tmp_path: Path,
) -> None:
    store = CardStore(tmp_path / "cards.db")
    card = FindingCard(
        card_id="impact",
        fingerprint="impact",
        host="h",
        path="/",
        matcher="candidate",
        title="Candidate",
        scanner_severity="high",
        confidence=0.4,
    )
    store.upsert(card)

    result = apply_impact(
        store,
        "impact",
        ImpactClass.SENSITIVE_ACCESS,
        "authenticated tester",
        "could expose a tester-owned record",
    )

    assert result["confidence"] == 0.4
    assert result["validation_state"] == ValidationState.HYPOTHESIS
    assert result["evidence"]["impact_claim_source"] == "agent_hypothesis"


@pytest.mark.parametrize(
    ("prepared", "expected_status", "expected_state"),
    [
        (mark_proven, CardStatus.PROVEN, ValidationState.PROVEN),
        (mark_refuted, CardStatus.NOISE, ValidationState.REFUTED),
    ],
)
def test_agent_impact_cannot_overwrite_safe_proof_state(
    tmp_path: Path, prepared, expected_status, expected_state
) -> None:
    store = CardStore(tmp_path / "cards.db")
    card = FindingCard(
        card_id="safe-state",
        fingerprint="safe-state",
        host="h",
        path="/",
        matcher="idor",
        title="IDOR",
        scanner_severity="high",
    )
    stored = store.upsert(prepared(card))

    result = apply_impact(
        store,
        stored.card_id,
        ImpactClass.NONE,
        "agent assessment",
        "agent changed its mind",
    )

    assert result["status"] == expected_status
    assert result["validation_state"] == expected_state
