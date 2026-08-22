from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from keel.adapters.httpx_probe import probe_alive
from keel.adapters.nuclei_scan import template_scan
from keel.catalog.store import CardStore
from keel.engagement.policy import EngagementPolicy
from keel.engagement.session import EngagementSession
from keel.errors import PolicyDenied, UnknownCard, UnknownEngagement
from keel.ingest.httpx_json import cards_from_httpx
from keel.ingest.nuclei_jsonl import cards_from_nuclei
from keel.models import ImpactClass, ProbeClass, WaveKind, WaveSpec
from keel.proof.catalog import draft_playbook
from keel.proof.runner import mark_proven, run_playbook
from keel.schedule.bucket import BucketMap
from keel.schedule.waves import WaveRunner
from keel.triage.impact import apply_impact


class Workspace:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: dict[str, EngagementSession] = {}
        self.stores: dict[str, CardStore] = {}
        self.waves: dict[str, dict[str, WaveSpec]] = {}
        self.runners: dict[str, WaveRunner] = {}

    def begin(self, policy: EngagementPolicy) -> dict:
        session = EngagementSession(policy)
        store = CardStore(self.data_dir / f"{policy.engagement_id}.db")
        buckets = BucketMap(policy.requests_per_second)
        self.sessions[policy.engagement_id] = session
        self.stores[policy.engagement_id] = store
        self.waves[policy.engagement_id] = {}
        self.runners[policy.engagement_id] = WaveRunner(session, buckets)
        return {"engagement_id": policy.engagement_id, "scope_hosts": policy.scope_hosts}

    def _session(self, engagement_id: str) -> EngagementSession:
        session = self.sessions.get(engagement_id)
        if session is None:
            raise UnknownEngagement(engagement_id)
        return session

    def health(self, engagement_id: str | None = None) -> dict:
        if engagement_id is None:
            return {"engagements": list(self.sessions.keys())}
        session = self._session(engagement_id)
        return {
            "engagement_id": engagement_id,
            "too_many_count": session.too_many_count,
            "paused_hosts": list(session.paused_hosts.keys()),
            "pending_waves": len(self.waves.get(engagement_id, {})),
        }

    def draft_waves(self, engagement_id: str, seed_url: str) -> list[dict]:
        session = self._session(engagement_id)
        specs = session.draft_waves(seed_url)
        bucket = self.waves[engagement_id]
        out = []
        for spec in specs:
            bucket[spec.wave_id] = spec
            out.append(spec.model_dump())
        return out

    def execute_wave(self, engagement_id: str, wave_id: str) -> dict:
        session = self._session(engagement_id)
        spec = self.waves.get(engagement_id, {}).get(wave_id)
        if spec is None:
            raise PolicyDenied(f"unknown wave {wave_id}")
        runner = self.runners[engagement_id]
        host = runner.admit(spec)
        rate = session.policy.requests_per_second
        try:
            if spec.kind == WaveKind.PROBE_ALIVE:
                result = probe_alive(spec.target, rate)
                fresh = cards_from_httpx(result.stdout)
            elif spec.kind == WaveKind.TEMPLATE_SCAN:
                severity = str(spec.extra.get("severity", "medium,high,critical"))
                result = template_scan(spec.target, rate, severity)
                fresh = cards_from_nuclei(result.stdout)
            else:
                raise PolicyDenied(spec.kind.value)
            if result.throttled:
                runner.note_throttle(host)
            else:
                runner.finish(host)
        except Exception:
            runner.finish(host)
            raise
        store = self.stores[engagement_id]
        stored = [store.upsert(card).model_dump() for card in fresh]
        self.waves[engagement_id].pop(wave_id, None)
        return {
            "wave_id": wave_id,
            "throttled": result.throttled,
            "returncode": result.returncode,
            "cards": stored,
        }

    def query_cards(self, engagement_id: str, include_noise: bool = False) -> list[dict]:
        self._session(engagement_id)
        return [card.model_dump() for card in self.stores[engagement_id].query(include_noise)]

    def second_look(self, engagement_id: str, card_id: str) -> dict:
        self._session(engagement_id)
        card = self.stores[engagement_id].get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
        spec = WaveSpec(
            wave_id=str(uuid4()),
            kind=WaveKind.TEMPLATE_SCAN,
            probe_class=ProbeClass.SAFE_ACTIVE,
            target=url,
            extra={"severity": "medium,high,critical"},
        )
        self.waves[engagement_id][spec.wave_id] = spec
        return self.execute_wave(engagement_id, spec.wave_id)

    def state_impact(
        self,
        engagement_id: str,
        card_id: str,
        impact: str,
        preconditions: str,
        hunter_why: str,
    ) -> dict:
        self._session(engagement_id)
        return apply_impact(
            self.stores[engagement_id],
            card_id,
            ImpactClass(impact),
            preconditions,
            hunter_why,
        )

    def draft_proof(self, engagement_id: str, card_id: str, playbook_id: str) -> dict:
        self._session(engagement_id)
        card = self.stores[engagement_id].get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
        return draft_playbook(playbook_id, card_id, url).model_dump()

    def execute_proof(
        self,
        engagement_id: str,
        card_id: str,
        playbook_id: str,
        session_a: str,
        session_b: str,
    ) -> dict:
        session = self._session(engagement_id)
        store = self.stores[engagement_id]
        card = store.get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        outcome = run_playbook(session.policy, card, playbook_id, session_a, session_b)
        if outcome.get("marker_seen") or (
            "status_a" in outcome and outcome.get("status_a") != outcome.get("status_b")
        ):
            store.upsert(mark_proven(card))
            outcome["status"] = "proven"
        else:
            outcome["status"] = "not_proven"
        return outcome
