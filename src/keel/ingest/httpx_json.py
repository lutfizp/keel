from __future__ import annotations

from keel.catalog.fingerprint import fingerprint, load_json_lines, split_url
from keel.models import EvidenceStrength, FindingCard, ImpactClass, ValidationState
from keel.proof.sanitize import sanitize_evidence


def invalid_httpx_record_count(stdout: str) -> int:
    invalid = 0
    for row in load_json_lines(stdout):
        url = row.get("url") or row.get("input")
        if not isinstance(url, str) or not url.strip():
            invalid += 1
    return invalid


def cards_from_httpx(stdout: str) -> list[FindingCard]:
    cards: list[FindingCard] = []
    for row in load_json_lines(stdout):
        url = str(row.get("url") or row.get("input") or "")
        if not url:
            continue
        host, path = split_url(url)
        vulnerability_class = "reachable_http_service"
        fp = fingerprint(vulnerability_class, host, path)
        cards.append(
            FindingCard(
                card_id=fp,
                fingerprint=fp,
                host=host,
                path=path,
                matcher=str(row.get("status_code", "")),
                title="Reachable HTTP service",
                scanner_severity="info",
                impact_class=ImpactClass.NONE,
                evidence={"url": url, "raw": sanitize_evidence(row)},
                sources=["httpx"],
                semantic_key=fp,
                vulnerability_class=vulnerability_class,
                validation_state=ValidationState.OBSERVED,
                evidence_strength=EvidenceStrength.SINGLE_SOURCE,
            )
        )
    return cards
