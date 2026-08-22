from keel.engagement.policy import EngagementPolicy
from keel.models import FindingCard, ImpactClass
from keel.triage.filters import default_visible, impact_from_severity


def test_scope_allows_subdomain() -> None:
    policy = EngagementPolicy(engagement_id="e1", scope_hosts=["example.com"])
    assert policy.host_allowed("app.example.com")
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
