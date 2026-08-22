from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from keel.models import FindingCard
from keel.triage.filters import default_visible


class CardStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._db = sqlite3.connect(path)
        self._db.row_factory = sqlite3.Row
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cards (
                fingerprint TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
            """
        )
        self._db.commit()

    def upsert(self, card: FindingCard) -> FindingCard:
        existing = self.get(card.fingerprint)
        if existing is not None:
            merged_sources = list(dict.fromkeys(existing.sources + card.sources))
            evidence = {**existing.evidence, **card.evidence}
            card = existing.model_copy(
                update={
                    "sources": merged_sources,
                    "evidence": evidence,
                    "confidence": min(1.0, existing.confidence + 0.1 * (len(merged_sources) - 1)),
                }
            )
        self._db.execute(
            "INSERT OR REPLACE INTO cards(fingerprint, payload) VALUES (?, ?)",
            (card.fingerprint, card.model_dump_json()),
        )
        self._db.commit()
        return card

    def get(self, fingerprint: str) -> FindingCard | None:
        row = self._db.execute(
            "SELECT payload FROM cards WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            return None
        return FindingCard.model_validate_json(row["payload"])

    def query(self, include_noise: bool = False) -> list[FindingCard]:
        rows = self._db.execute("SELECT payload FROM cards").fetchall()
        cards = [FindingCard.model_validate_json(row["payload"]) for row in rows]
        if include_noise:
            return cards
        return [card for card in cards if default_visible(card.impact_class)]

    def close(self) -> None:
        self._db.close()
