from keel.models import FindingCard, ImpactClass

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


def impact_from_severity(severity: str, template: str, title: str) -> ImpactClass:
    if looks_hardening(template, title):
        return ImpactClass.HARDENING
    if severity in {"info", "unknown", "low"}:
        return ImpactClass.NONE
    return ImpactClass.NONE


def default_visible(card: FindingCard) -> bool:
    if card.impact_class in _HUNTER:
        return True
    if card.impact_class == ImpactClass.HARDENING:
        return False
    return card.scanner_severity in {"medium", "high", "critical"}
