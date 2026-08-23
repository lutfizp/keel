from pathlib import Path

from keel.catalog.store import CardStore
from keel.models import EvidenceStrength, FindingCard, ImpactClass, ValidationState
from keel.proof.runner import mark_proven


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


def test_default_query_does_not_crash(tmp_path: Path) -> None:
    store = CardStore(tmp_path / "cards.db")
    card = FindingCard(
        card_id="visible",
        fingerprint="visible",
        host="h",
        path="/",
        matcher="idor",
        title="IDOR",
        scanner_severity="high",
    )
    store.upsert(card)

    assert [item.card_id for item in store.query()] == ["visible"]


def test_semantic_key_merges_different_tool_fingerprints(tmp_path: Path) -> None:
    store = CardStore(tmp_path / "cards.db")
    first = FindingCard(
        card_id="tool-a-fingerprint",
        fingerprint="tool-a-fingerprint",
        semantic_key="semantic-idor",
        host="app.example.com",
        path="/users/{id}",
        matcher="template-one",
        title="BOLA",
        scanner_severity="high",
        vulnerability_class="broken_object_authorization",
        validation_state=ValidationState.HYPOTHESIS,
        evidence_strength=EvidenceStrength.SINGLE_SOURCE,
        sources=["tool-a"],
    )
    second = first.model_copy(
        update={
            "card_id": "tool-b-fingerprint",
            "fingerprint": "tool-b-fingerprint",
            "matcher": "different-template",
            "sources": ["tool-b"],
        }
    )

    store.upsert(first)
    merged = store.upsert(second)

    assert len(store.query(include_noise=True)) == 1
    assert merged.sources == ["tool-a", "tool-b"]
    assert merged.validation_state == ValidationState.CORROBORATED
    assert merged.evidence_strength == EvidenceStrength.MULTI_SOURCE
    assert merged.corroboration_count == 2


def test_safe_proof_state_is_not_downgraded_by_merge(tmp_path: Path) -> None:
    store = CardStore(tmp_path / "cards.db")
    card = FindingCard(
        card_id="proof",
        fingerprint="proof",
        semantic_key="proof",
        host="h",
        path="/",
        matcher="idor",
        title="IDOR",
        scanner_severity="high",
        sources=["nuclei"],
    )
    store.upsert(card)
    store.upsert(mark_proven(card))

    stored = store.get("proof")
    assert stored is not None
    assert stored.validation_state == ValidationState.PROVEN
    assert stored.evidence_strength == EvidenceStrength.SAFE_PROOF
