from pathlib import Path

from keel.catalog.store import CardStore
from keel.models import FindingCard, ImpactClass


def test_upsert_merges_sources(tmp_path: Path) -> None:
    store = CardStore(tmp_path / "cards.db")
    base = FindingCard(
        card_id="abc",
        fingerprint="abc",
        host="h",
        path="/",
        matcher="t",
        title="t",
        scanner_severity="high",
        impact_class=ImpactClass.NONE,
        sources=["httpx"],
        evidence={"url": "https://h/"},
    )
    store.upsert(base)
    again = base.model_copy(update={"sources": ["nuclei"], "evidence": {"matched": "https://h/"}})
    merged = store.upsert(again)
    assert merged.sources == ["httpx", "nuclei"]
    assert "url" in merged.evidence and "matched" in merged.evidence
    store.close()
