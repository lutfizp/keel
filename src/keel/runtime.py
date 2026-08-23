from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from uuid import uuid4

from keel.adapters.httpx_probe import probe_alive
from keel.adapters.nuclei_scan import template_scan
from keel.catalog.fingerprint import invalid_json_line_count
from keel.catalog.store import CardStore
from keel.engagement.policy import EngagementPolicy
from keel.engagement.session import EngagementSession
from keel.errors import (
    AdapterFailed,
    KeelError,
    PolicyDenied,
    TargetThrottled,
    UnknownCard,
    UnknownEngagement,
)
from keel.ingest.httpx_json import cards_from_httpx, invalid_httpx_record_count
from keel.ingest.nuclei_jsonl import cards_from_nuclei, invalid_nuclei_record_count
from keel.models import ImpactClass, ProbeClass, WaveKind, WaveSpec
from keel.proof.approval import (
    activate_approval,
    proof_target_for,
    revalidate_scope_approval,
)
from keel.proof.catalog import PLAYBOOK_CROSS_ACCOUNT_READ, draft_playbook
from keel.proof.http import ProofRequestBroker
from keel.proof.runner import mark_proven, mark_refuted, run_playbook
from keel.proof.sanitize import clip
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
        self._lock = threading.RLock()
        self._restore()

    def _restore(self) -> None:
        for database in sorted(self.data_dir.glob("*.db")):
            store = CardStore(database)
            payload = store.get_metadata("policy")
            if payload is None:
                store.close()
                continue
            try:
                policy = EngagementPolicy.model_validate(payload)
            except ValueError:
                store.close()
                continue
            session = EngagementSession(policy)
            session.restore_state(store.get_metadata("session") or {})
            waves = {wave.wave_id: wave for wave in store.load_waves()}
            self.sessions[policy.engagement_id] = session
            self.stores[policy.engagement_id] = store
            self.waves[policy.engagement_id] = waves
            self.runners[policy.engagement_id] = WaveRunner(
                session,
                BucketMap(policy.requests_per_second, policy.max_parallel_hosts),
            )

    def begin(self, policy: EngagementPolicy) -> dict:
        with self._lock:
            return self._begin_locked(policy)

    def _begin_locked(self, policy: EngagementPolicy) -> dict:
        policy = policy.model_copy(
            update={
                "operator_confirmed": False,
                "approval_id": "",
                "approval_expires_at": "",
                "approved_playbooks": [],
                "approved_credential_refs": [],
                "approved_proof_target_refs": [],
                "scope_approved": False,
            }
        )
        allow_unapproved_recon = os.environ.get("KEEL_ALLOW_UNAPPROVED_RECON") == "1"
        if policy.allow_safe_proof or not allow_unapproved_recon:
            policy = activate_approval(policy)
        existing = self.sessions.get(policy.engagement_id)
        if existing is not None:
            if _policy_identity(existing.policy) != _policy_identity(policy):
                raise PolicyDenied(
                    "engagement already exists with a different policy; use a new engagement_id"
                )
            if existing.policy.model_dump(mode="json") != policy.model_dump(mode="json"):
                existing.policy = policy
                self.stores[policy.engagement_id].set_metadata(
                    "policy", policy.model_dump(mode="json")
                )
                self.stores[policy.engagement_id].append_audit(
                    "operator_approval_refreshed",
                    {"approval_id": policy.approval_id},
                )
            return self._begin_payload(existing.policy, resumed=True)
        session = EngagementSession(policy)
        store = CardStore(self.data_dir / f"{policy.engagement_id}.db")
        buckets = BucketMap(policy.requests_per_second, policy.max_parallel_hosts)
        self.sessions[policy.engagement_id] = session
        self.stores[policy.engagement_id] = store
        self.waves[policy.engagement_id] = {}
        self.runners[policy.engagement_id] = WaveRunner(session, buckets)
        store.set_metadata("policy", policy.model_dump(mode="json"))
        store.set_metadata("session", session.state())
        store.append_audit(
            "engagement_started",
            {
                "scope_hosts": policy.scope_hosts,
                "exclude_hosts": policy.exclude_hosts,
                "requests_per_second": policy.requests_per_second,
                "proof_approved": policy.operator_confirmed,
                "approval_id": policy.approval_id,
            },
        )
        return self._begin_payload(policy, resumed=False)

    @staticmethod
    def _begin_payload(policy: EngagementPolicy, resumed: bool) -> dict:
        return {
            "engagement_id": policy.engagement_id,
            "scope_hosts": policy.scope_hosts,
            "exclude_hosts": policy.exclude_hosts,
            "resumed": resumed,
            "proof_approved": policy.operator_confirmed,
            "approved_playbooks": policy.approved_playbooks,
            "approved_proof_target_refs": policy.approved_proof_target_refs,
            "nuclei_template_ids": policy.nuclei_template_ids,
            "approval_expires_at": policy.approval_expires_at,
            "requests_remaining": policy.max_engagement_requests,
        }

    def _session(self, engagement_id: str) -> EngagementSession:
        with self._lock:
            session = self.sessions.get(engagement_id)
        if session is None:
            raise UnknownEngagement(engagement_id)
        return session

    def health(self, engagement_id: str | None = None) -> dict:
        if engagement_id is None:
            return {"engagements": list(self.sessions.keys())}
        session = self._session(engagement_id)
        state = session.state()
        self._persist_session(engagement_id)
        return {
            "engagement_id": engagement_id,
            "too_many_count": state["too_many_count"],
            "paused_hosts": state["paused_hosts"],
            "pending_waves": len(self.waves.get(engagement_id, {})),
            "proof_approved": session.policy.operator_confirmed,
            "approval_expires_at": session.policy.approval_expires_at,
            "requests_reserved": state["requests_reserved"],
            "requests_remaining": session.requests_remaining(),
        }

    def draft_waves(self, engagement_id: str, seed_url: str) -> list[dict]:
        session = self._session(engagement_id)
        specs = session.draft_waves(seed_url)
        bucket = self.waves[engagement_id]
        out = []
        for spec in specs:
            bucket[spec.wave_id] = spec
            self.stores[engagement_id].save_wave(spec)
            out.append(spec.model_dump())
        self.stores[engagement_id].append_audit(
            "waves_drafted", {"seed_url": seed_url, "wave_ids": [item.wave_id for item in specs]}
        )
        return out

    def execute_wave(self, engagement_id: str, wave_id: str) -> dict:
        session = self._session(engagement_id)
        revalidate_scope_approval(session.policy)
        spec = self.waves.get(engagement_id, {}).get(wave_id)
        if spec is None:
            raise PolicyDenied(f"unknown wave {wave_id}")
        if (
            spec.kind == WaveKind.TEMPLATE_SCAN
            and not session.policy.external_template_scan_allowed(spec.target)
        ):
            raise PolicyDenied(
                "external template scans are disabled for path-bounded scope or exclusions"
            )
        runner = self.runners[engagement_id]
        host = runner.admit(spec)
        released = False
        try:
            rate = session.policy.requests_per_second
            request_budget = _wave_request_budget(session.policy, spec)
            session.reserve_requests(request_budget)
            self._persist_session(engagement_id)
            spec.extra["reserved_requests"] = request_budget
            spec.extra["attempt_count"] = int(spec.extra.get("attempt_count", 0)) + 1
            self.stores[engagement_id].save_wave(spec)
            self.stores[engagement_id].append_audit(
                "wave_attempt_reserved",
                {
                    "wave_id": wave_id,
                    "attempt": spec.extra["attempt_count"],
                    "reserved_requests": request_budget,
                    "engagement_requests_reserved": session.state()["requests_reserved"],
                },
            )
            scanner_timeout = session.policy.max_wave_seconds
            scanner_rate = (
                rate
                if spec.kind == WaveKind.PROBE_ALIVE
                else min(rate, request_budget / scanner_timeout)
            )
            if spec.kind == WaveKind.PROBE_ALIVE:
                result = probe_alive(
                    spec.target,
                    scanner_rate,
                    timeout=scanner_timeout,
                    max_response_bytes=session.policy.max_response_bytes,
                )
            elif spec.kind == WaveKind.TEMPLATE_SCAN:
                severity = str(spec.extra.get("severity", "medium,high,critical"))
                template_id = str(spec.extra.get("template_id", ""))
                raw_template_ids = spec.extra.get("template_ids", [])
                if not template_id and not isinstance(raw_template_ids, list):
                    raise PolicyDenied("invalid Nuclei template allowlist in wave")
                requested_ids = (
                    [template_id]
                    if template_id
                    else [str(item) for item in raw_template_ids]
                )
                if not requested_ids:
                    raise PolicyDenied("a reviewed Nuclei template allowlist is required")
                if any(
                    not re.fullmatch(r"[A-Za-z0-9._:-]+", item)
                    for item in requested_ids
                ):
                    raise PolicyDenied("unsafe nuclei template id")
                if not set(requested_ids).issubset(
                    set(session.policy.nuclei_template_ids)
                ):
                    raise PolicyDenied("Nuclei template is outside operator selection")
                result = template_scan(
                    spec.target,
                    scanner_rate,
                    severity,
                    timeout=scanner_timeout,
                    max_response_bytes=session.policy.max_response_bytes,
                    template_id=",".join(requested_ids),
                    project_path=(
                        self.data_dir
                        / ".nuclei-projects"
                        / engagement_id
                        / spec.wave_id
                    ),
                )
            else:
                raise PolicyDenied(spec.kind.value)
            if result.throttled:
                runner.note_throttle(host, result.retry_after_seconds)
                released = True
                self._persist_session(engagement_id)
                self.stores[engagement_id].append_audit(
                    "wave_throttled",
                    {
                        "wave_id": wave_id,
                        "host": host,
                        "retry_after_seconds": result.retry_after_seconds,
                    },
                )
                raise AdapterFailed("scanner observed target throttling; wave retained")
            if result.returncode != 0:
                self.stores[engagement_id].append_audit(
                    "wave_failed",
                    {
                        "wave_id": wave_id,
                        "returncode": result.returncode,
                        "stderr": clip(result.stderr, 500),
                    },
                )
                raise AdapterFailed(
                    f"scanner exited {result.returncode}; wave retained: "
                    f"{clip(result.stderr, 300)}"
                )
            malformed_lines = invalid_json_line_count(result.stdout)
            if malformed_lines:
                self.stores[engagement_id].append_audit(
                    "wave_parse_failed",
                    {
                        "wave_id": wave_id,
                        "malformed_lines": malformed_lines,
                        "stdout_bytes": len(result.stdout.encode("utf-8")),
                    },
                )
                raise AdapterFailed(
                    f"scanner emitted {malformed_lines} malformed or non-object JSON "
                    "line(s); wave retained without partial ingest"
                )
            invalid_records = (
                invalid_httpx_record_count(result.stdout)
                if spec.kind == WaveKind.PROBE_ALIVE
                else invalid_nuclei_record_count(result.stdout)
            )
            if invalid_records:
                scanner = "httpx" if spec.kind == WaveKind.PROBE_ALIVE else "nuclei"
                self.stores[engagement_id].append_audit(
                    "wave_schema_failed",
                    {
                        "wave_id": wave_id,
                        "scanner": scanner,
                        "invalid_records": invalid_records,
                    },
                )
                raise AdapterFailed(
                    f"{scanner} emitted {invalid_records} record(s) without required "
                    "identity fields; wave retained without partial ingest"
                )
            fresh = (
                cards_from_httpx(result.stdout)
                if spec.kind == WaveKind.PROBE_ALIVE
                else cards_from_nuclei(result.stdout)
            )
        except KeelError as exc:
            self.stores[engagement_id].append_audit(
                "wave_execution_failed",
                {
                    "wave_id": wave_id,
                    "error": type(exc).__name__,
                    "message": clip(str(exc), 300),
                },
            )
            raise
        finally:
            if not released:
                runner.finish(host)
        store = self.stores[engagement_id]
        admitted = []
        for card in fresh:
            card_url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
            if card_url and session.policy.url_allowed(card_url):
                admitted.append(card)
            else:
                store.append_audit(
                    "scanner_result_dropped_out_of_scope",
                    {"wave_id": wave_id, "url": card_url},
                )
        stored = [store.upsert(card).model_dump() for card in admitted]
        self.waves[engagement_id].pop(wave_id, None)
        store.delete_wave(wave_id)
        store.append_audit(
            "wave_completed",
            {
                "wave_id": wave_id,
                "returncode": result.returncode,
                "cards": [card["card_id"] for card in stored],
            },
        )
        return {
            "wave_id": wave_id,
            "throttled": result.throttled,
            "returncode": result.returncode,
            "cards": stored,
            "dropped_out_of_scope": len(fresh) - len(admitted),
        }

    def query_cards(self, engagement_id: str, include_noise: bool = False) -> list[dict]:
        self._session(engagement_id)
        return [card.model_dump() for card in self.stores[engagement_id].query(include_noise)]

    def second_look(self, engagement_id: str, card_id: str) -> dict:
        session = self._session(engagement_id)
        card = self.stores[engagement_id].get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
        if not session.policy.url_allowed(url):
            raise PolicyDenied("card URL is outside exact engagement scope")
        if "nuclei" not in card.sources:
            raise PolicyDenied("second_look requires a nuclei-backed card")
        raw = card.evidence.get("raw") if isinstance(card.evidence.get("raw"), dict) else {}
        template_id = str(raw.get("template-id") or card.matcher)
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", template_id):
            raise PolicyDenied("card has no safe nuclei template id")
        if template_id not in session.policy.nuclei_template_ids:
            raise PolicyDenied("originating Nuclei template is no longer approved")
        spec = WaveSpec(
            wave_id=str(uuid4()),
            kind=WaveKind.TEMPLATE_SCAN,
            probe_class=ProbeClass.SAFE_ACTIVE,
            target=url,
            extra={"severity": card.scanner_severity, "template_id": template_id},
        )
        self.waves[engagement_id][spec.wave_id] = spec
        self.stores[engagement_id].save_wave(spec)
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
        result = apply_impact(
            self.stores[engagement_id],
            card_id,
            ImpactClass(impact),
            preconditions,
            hunter_why,
        )
        self.stores[engagement_id].append_audit(
            "impact_hypothesis_stated",
            {"card_id": card_id, "impact": impact, "preconditions": preconditions},
        )
        return result

    def draft_proof(self, engagement_id: str, card_id: str, playbook_id: str) -> dict:
        session = self._session(engagement_id)
        card = self.stores[engagement_id].get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
        if not session.policy.url_allowed(url):
            raise PolicyDenied("card URL is outside exact engagement scope")
        return draft_playbook(playbook_id, card_id, url).model_dump()

    def execute_proof(
        self,
        engagement_id: str,
        card_id: str,
        playbook_id: str,
        session_a: str,
        session_b: str,
        expected_marker: str,
        proof_target_ref: str,
    ) -> dict:
        session = self._session(engagement_id)
        store = self.stores[engagement_id]
        card = store.get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        card_url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
        grant, proof_target = proof_target_for(
            session.policy,
            playbook_id,
            proof_target_ref,
            card_url,
            expected_marker,
            session_a,
            session_b,
        )
        draft = draft_playbook(
            playbook_id,
            card_id,
            card_url,
        )
        runner = self.runners[engagement_id]
        host = runner.admit(
            WaveSpec(
                wave_id=f"proof-{uuid4()}",
                kind=WaveKind.PROBE_ALIVE,
                probe_class=ProbeClass.SAFE_ACTIVE,
                target=str(card.evidence.get("url") or card.evidence.get("matched") or ""),
            )
        )
        released = False
        try:
            broker = ProofRequestBroker(
                session.policy,
                runner.buckets,
                min(draft.request_budget, grant.max_proof_requests),
            )
            session.reserve_requests(broker.max_requests)
            self._persist_session(engagement_id)
            outcome = run_playbook(
                session.policy,
                card,
                playbook_id,
                proof_target.owner_credential_ref,
                proof_target.peer_credential_ref,
                expected_marker,
                broker,
            )
        except TargetThrottled as exc:
            runner.note_throttle(host, exc.retry_after_seconds)
            released = True
            self._persist_session(engagement_id)
            store.append_audit(
                "proof_throttled",
                {"card_id": card_id, "playbook_id": playbook_id, "host": host},
            )
            raise
        except KeelError as exc:
            store.append_audit(
                "proof_failed",
                {
                    "card_id": card_id,
                    "playbook_id": playbook_id,
                    "proof_target_ref": proof_target_ref,
                    "error": type(exc).__name__,
                },
            )
            raise
        finally:
            if not released:
                runner.finish(host)

        proof_history = list(card.evidence.get("proof_history", []))
        proof_history.append(outcome)
        card.evidence["proof_history"] = proof_history[-10:]
        decision = outcome["decision"]
        if decision == "proven":
            card = mark_proven(card)
        elif decision == "protected" and playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
            card = mark_refuted(card)
        store.upsert(card)
        store.append_audit(
            "proof_completed",
            {
                "card_id": card_id,
                "playbook_id": playbook_id,
                "proof_target_ref": proof_target_ref,
                "decision": decision,
                "requests_made": outcome["requests_made"],
            },
        )
        outcome["status"] = decision
        return outcome

    def audit(self, engagement_id: str, limit: int = 50) -> list[dict]:
        self._session(engagement_id)
        return self.stores[engagement_id].audit(limit)

    def _persist_session(self, engagement_id: str) -> None:
        self.stores[engagement_id].set_metadata(
            "session", self.sessions[engagement_id].state()
        )


def _policy_identity(policy: EngagementPolicy) -> dict:
    return policy.model_dump(
        mode="json",
        exclude={
            "operator_confirmed",
            "allow_safe_proof",
            "tester_account_a",
            "tester_account_b",
            "nuclei_template_ids",
            "approval_id",
            "approval_expires_at",
            "approved_playbooks",
            "approved_credential_refs",
            "approved_proof_target_refs",
            "scope_approved",
        },
    )


def _wave_request_budget(policy: EngagementPolicy, spec: WaveSpec) -> int:
    if spec.kind == WaveKind.PROBE_ALIVE:
        return 1
    if spec.extra.get("template_id"):
        return min(policy.max_wave_requests, 20)
    return policy.max_wave_requests
