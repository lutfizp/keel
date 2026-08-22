from __future__ import annotations

from keel.catalog.fingerprint import fingerprint, load_json_lines, split_url
from keel.models import FindingCard
from keel.triage.filters import impact_from_severity, severity_of_nuclei


def cards_from_nuclei(stdout: str) -> list[FindingCard]:
    cards: list[FindingCard] = []
    for row in load_json_lines(stdout):
        matched = str(row.get("matched-at") or row.get("host") or "")
        host, path = split_url(matched)
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        name = str(info.get("name") or row.get("template-id") or "nuclei")
        template = str(row.get("template-id") or name)
        severity = severity_of_nuclei(info.get("severity") or row.get("severity"))
        fp = fingerprint("nuclei", host, path, template)
        cards.append(
            FindingCard(
                card_id=fp,
                fingerprint=fp,
                host=host,
                path=path,
                matcher=template,
                title=name,
                scanner_severity=severity,
                impact_class=impact_from_severity(severity, template, name),
                evidence={"matched": matched, "raw": row},
                sources=["nuclei"],
            )
        )
    return cards
