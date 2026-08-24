from keel.models import FindingCard, ImpactClass, ValidationState
from keel.catalog.fingerprint import canonical_vulnerability_class
from keel.triage.exploitability import suggested_impact

_HARDENING_MARKERS = (
    "header",
    "csp",
    "hsts",
    "cookie",
    "tls-",
    "deprecated",
    "tech-detect",
    "waf-detect",
    "missing-",
)

_HUNTER = {
    ImpactClass.SENSITIVE_ACCESS,
    ImpactClass.ACCOUNT_TAKEOVER,
    ImpactClass.RCE,
    ImpactClass.DATA_OTHER_USERS,
}


def severity_of_nuclei(value: object) -> str:
    text = str(value or "info").lower()
    if text in {"info", "low", "medium", "high", "critical", "unknown"}:
        return text
    return "info"


def looks_hardening(template: str, title: str) -> bool:
    blob = f"{template} {title}".lower()
    return any(marker in blob for marker in _HARDENING_MARKERS)


def impact_from_severity(
    severity: str,
    template: str,
    title: str,
    vulnerability_class: str = "",
) -> ImpactClass:
    if looks_hardening(template, title):
        return ImpactClass.HARDENING
    canonical = vulnerability_class or canonical_vulnerability_class(template, title)
    return suggested_impact(canonical)


def default_visible(card: FindingCard) -> bool:
    if card.validation_state == ValidationState.REFUTED:
        return False
    if card.impact_class in _HUNTER:
        return True
    if card.impact_class == ImpactClass.HARDENING:
        return False
    return card.scanner_severity in {"medium", "high", "critical"}


def priority_score(card: FindingCard) -> float:
    severity = {
        "unknown": 0.0,
        "info": 0.0,
        "low": 0.1,
        "medium": 0.3,
        "high": 0.5,
        "critical": 0.65,
    }.get(card.scanner_severity, 0.0)
    impact = {
        ImpactClass.NONE: 0.0,
        ImpactClass.HARDENING: -0.3,
        ImpactClass.SENSITIVE_ACCESS: 0.5,
        ImpactClass.DATA_OTHER_USERS: 0.7,
        ImpactClass.ACCOUNT_TAKEOVER: 0.85,
        ImpactClass.RCE: 1.0,
    }[card.impact_class]
    validation = {
        ValidationState.OBSERVED: 0.0,
        ValidationState.HYPOTHESIS: 0.1,
        ValidationState.CORROBORATED: 0.35,
        ValidationState.PROVEN: 0.7,
        ValidationState.REFUTED: -1.0,
    }[card.validation_state]
    impact_weight = {
        ValidationState.OBSERVED: 0.15,
        ValidationState.HYPOTHESIS: 0.25,
        ValidationState.CORROBORATED: 0.7,
        ValidationState.PROVEN: 1.0,
        ValidationState.REFUTED: 0.0,
    }[card.validation_state]
    in_scope = 0.1 if card.in_program else -1.0
    score = severity + (impact * impact_weight) + validation + in_scope
    return round(max(0.0, min(1.0, score)) * 100, 1)
