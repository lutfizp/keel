from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from keel.models import EvidenceStrength, FindingCard, ValidationState, WaveSpec
from keel.triage.filters import default_visible, priority_score


class CardStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cards (
                fingerprint TEXT PRIMARY KEY,
                semantic_key TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL
            )
            """
        )
        columns = {
            str(row["name"])
            for row in self._db.execute("PRAGMA table_info(cards)").fetchall()
        }
        if "semantic_key" not in columns:
            self._db.execute(
                "ALTER TABLE cards ADD COLUMN semantic_key TEXT NOT NULL DEFAULT ''"
            )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS cards_semantic_key ON cards(semantic_key)"
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS waves (
                wave_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._db.commit()
        self._backfill_semantic_keys()

    def _backfill_semantic_keys(self) -> None:
        rows = self._db.execute(
            "SELECT fingerprint, payload FROM cards WHERE semantic_key = ''"
        ).fetchall()
        for row in rows:
            card = FindingCard.model_validate_json(row["payload"])
            semantic_key = card.semantic_key or card.fingerprint
            if not card.semantic_key:
                card.semantic_key = semantic_key
            self._db.execute(
                "UPDATE cards SET semantic_key = ?, payload = ? WHERE fingerprint = ?",
                (semantic_key, card.model_dump_json(), row["fingerprint"]),
            )
        if rows:
            self._db.commit()

    def upsert(self, card: FindingCard) -> FindingCard:
        with self._lock:
            if not card.semantic_key:
                card.semantic_key = card.fingerprint
            row = self._db.execute(
                """
                SELECT fingerprint, payload FROM cards
                WHERE fingerprint = ? OR semantic_key = ?
                ORDER BY CASE WHEN fingerprint = ? THEN 0 ELSE 1 END
                LIMIT 1
                """,
                (card.fingerprint, card.semantic_key, card.fingerprint),
            ).fetchone()
            existing = (
                FindingCard.model_validate_json(row["payload"]) if row is not None else None
            )
            storage_fingerprint = str(row["fingerprint"]) if row is not None else card.fingerprint
            if existing is not None:
                card = self._merge(existing, card)
                card.fingerprint = storage_fingerprint
                card.card_id = existing.card_id
            card.priority_score = priority_score(card)
            self._db.execute(
                """
                INSERT OR REPLACE INTO cards(fingerprint, semantic_key, payload)
                VALUES (?, ?, ?)
                """,
                (storage_fingerprint, card.semantic_key, card.model_dump_json()),
            )
            self._db.commit()
            return card

    @staticmethod
    def _merge(existing: FindingCard, incoming: FindingCard) -> FindingCard:
        merged_sources = list(dict.fromkeys(existing.sources + incoming.sources))
        evidence = {**existing.evidence, **incoming.evidence}
        observations = list(existing.evidence.get("observations", []))
        observation = {
            "sources": incoming.sources,
            "matcher": incoming.matcher,
            "url": incoming.evidence.get("matched") or incoming.evidence.get("url"),
        }
        if observation not in observations:
            observations.append(observation)
        evidence["observations"] = observations[-20:]

        validation_state = existing.validation_state
        evidence_strength = existing.evidence_strength
        status = existing.status
        confidence = max(existing.confidence, incoming.confidence)
        if incoming.evidence_strength == EvidenceStrength.SAFE_PROOF:
            validation_state = incoming.validation_state
            evidence_strength = EvidenceStrength.SAFE_PROOF
            status = incoming.status
            confidence = incoming.confidence
        elif existing.evidence_strength == EvidenceStrength.SAFE_PROOF:
            validation_state = existing.validation_state
            evidence_strength = EvidenceStrength.SAFE_PROOF
            status = existing.status
            confidence = existing.confidence
        elif len(merged_sources) >= 2:
            validation_state = ValidationState.CORROBORATED
            evidence_strength = EvidenceStrength.MULTI_SOURCE
            confidence = max(confidence, 0.65)

        impact_updated = "impact_claim_source" in incoming.evidence
        impact_class = incoming.impact_class if impact_updated else existing.impact_class
        preconditions = incoming.preconditions if impact_updated else existing.preconditions
        if impact_updated and evidence_strength != EvidenceStrength.SAFE_PROOF:
            status = incoming.status
            validation_state = incoming.validation_state

        return existing.model_copy(
            update={
                "sources": merged_sources,
                "evidence": evidence,
                "confidence": min(1.0, confidence),
                "validation_state": validation_state,
                "evidence_strength": evidence_strength,
                "status": status,
                "impact_class": impact_class,
                "preconditions": preconditions,
                "corroboration_count": max(
                    existing.corroboration_count,
                    incoming.corroboration_count,
                    len(merged_sources),
                    len(observations),
                ),
                "scanner_severity": _higher_severity(
                    existing.scanner_severity, incoming.scanner_severity
                ),
            }
        )

    def get(self, fingerprint: str) -> FindingCard | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM cards WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        if row is None:
            return None
        return FindingCard.model_validate_json(row["payload"])

    def query(self, include_noise: bool = False) -> list[FindingCard]:
        with self._lock:
            rows = self._db.execute("SELECT payload FROM cards").fetchall()
        cards = [FindingCard.model_validate_json(row["payload"]) for row in rows]
        for card in cards:
            card.priority_score = priority_score(card)
        cards.sort(key=lambda card: (card.priority_score, card.confidence), reverse=True)
        if include_noise:
            return cards
        return [card for card in cards if default_visible(card)]

    def set_metadata(self, key: str, payload: Any) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO metadata(key, payload) VALUES (?, ?)",
                (key, encoded),
            )
            self._db.commit()

    def get_metadata(self, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM metadata WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["payload"]) if row is not None else None

    def save_wave(self, wave: WaveSpec) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO waves(wave_id, payload) VALUES (?, ?)",
                (wave.wave_id, wave.model_dump_json()),
            )
            self._db.commit()

    def delete_wave(self, wave_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM waves WHERE wave_id = ?", (wave_id,))
            self._db.commit()

    def load_waves(self) -> list[WaveSpec]:
        with self._lock:
            rows = self._db.execute("SELECT payload FROM waves").fetchall()
        return [WaveSpec.model_validate_json(row["payload"]) for row in rows]

    def append_audit(self, event_type: str, payload: Any) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            self._db.execute(
                "INSERT INTO audit(created_at, event_type, payload) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), event_type, encoded),
            )
            self._db.commit()

    def audit(self, limit: int = 50) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 500))
        with self._lock:
            rows = self._db.execute(
                """
                SELECT event_id, created_at, event_type, payload
                FROM audit ORDER BY event_id DESC LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload"]),
            }
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._db.close()


def _higher_severity(first: str, second: str) -> str:
    order = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    return max((first, second), key=lambda item: order.get(item, 0))
