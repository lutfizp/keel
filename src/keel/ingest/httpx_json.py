from __future__ import annotations

from keel.catalog.fingerprint import fingerprint, load_json_lines, split_url
from keel.models import FindingCard, ImpactClass


def cards_from_httpx(stdout: str) -> list[FindingCard]:
    cards: list[FindingCard] = []
    for row in load_json_lines(stdout):
        url = str(row.get("url") or row.get("input") or "")
        if not url:
            continue
        host, path = split_url(url)
        fp = fingerprint("alive", host, path, str(row.get("status_code", "")))
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
                evidence={"url": url, "raw": row},
                sources=["httpx"],
            )
        )
    return cards
