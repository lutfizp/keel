from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
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
    OperationCancelled,
    PolicyDenied,
    TargetThrottled,
    UnknownCard,
    UnknownEngagement,
    WaveBusy,
)
from keel.ingest.httpx_json import cards_from_httpx, invalid_httpx_record_count
from keel.ingest.nuclei_jsonl import cards_from_nuclei, invalid_nuclei_record_count
from keel.models import (
    ImpactClass,
    JobState,
    ProbeClass,
    WaveJob,
    WaveKind,
    WaveSpec,
    WaveState,
)
from keel.proof.approval import (
    activate_approval,
    approval_configured,
    proof_target_for,
    revalidate_scope_approval,
)
from keel.proof.catalog import draft_playbook
from keel.proof.http import ProofRequestBroker
from keel.proof.runner import PROVING_PLAYBOOKS, mark_proven, mark_refuted, run_playbook
from keel.proof.sanitize import clip
from keel.schedule.bucket import BucketMap
from keel.schedule.waves import WaveRunner
from keel.triage.exploitability import assess_card
from keel.triage.impact import apply_impact


_ACTIVE_JOB_STATES = {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}


class Workspace:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: dict[str, EngagementSession] = {}
        self.stores: dict[str, CardStore] = {}
        self.waves: dict[str, dict[str, WaveSpec]] = {}
        self.runners: dict[str, WaveRunner] = {}
        self.jobs: dict[str, WaveJob] = {}
        self._job_events: dict[str, threading.Event] = {}
        self._job_futures: dict[str, Future] = {}
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="keel-wave")
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
            waves = self._restore_waves(store, policy)
            self.sessions[policy.engagement_id] = session
            self.stores[policy.engagement_id] = store
            self.waves[policy.engagement_id] = waves
            self.runners[policy.engagement_id] = WaveRunner(
                session,
                BucketMap(policy.requests_per_second, policy.max_parallel_hosts),
            )
            for job in store.load_jobs():
                if job.state in _ACTIVE_JOB_STATES:
                    job.state = JobState.INTERRUPTED
                    job.stage = "server_restarted"
                    job.error_type = "Interrupted"
                    job.error_message = "server restarted before the background job completed"
                    job.updated_at = _now()
                    store.save_job(job)
                self.jobs[job.job_id] = job

    @staticmethod
    def _restore_waves(
        store: CardStore, policy: EngagementPolicy
    ) -> dict[str, WaveSpec]:
        restored: dict[str, WaveSpec] = {}
        for wave in store.load_waves():
            legacy_attempts = int(wave.extra.pop("attempt_count", 0) or 0)
            wave.attempt_count = max(wave.attempt_count, legacy_attempts)
            wave.max_attempts = min(wave.max_attempts, policy.max_wave_attempts)
            if wave.state == WaveState.RUNNING:
                wave.state = (
                    WaveState.TERMINAL_FAILED
                    if wave.attempt_count >= wave.max_attempts
                    else WaveState.RETRYABLE_FAILED
                )
                wave.last_error = "server restarted while the scanner was running"
            legacy_ids = wave.extra.pop("template_ids", None)
            if wave.kind != WaveKind.TEMPLATE_SCAN or not isinstance(legacy_ids, list):
                restored[wave.wave_id] = wave
                store.save_wave(wave)
                continue
            template_ids = [str(item) for item in legacy_ids if str(item)]
            if not template_ids:
                wave.state = WaveState.TERMINAL_FAILED
                wave.last_error = "legacy template wave has an empty template selection"
                restored[wave.wave_id] = wave
                store.save_wave(wave)
                continue
            store.delete_wave(wave.wave_id)
            replacements: list[str] = []
            for template_id in template_ids:
                split = wave.model_copy(deep=True)
                split.wave_id = str(uuid4())
                split.extra["template_id"] = template_id
                split.extra["origin_wave_id"] = wave.wave_id
                restored[split.wave_id] = split
                store.save_wave(split)
                replacements.append(split.wave_id)
            store.append_audit(
                "legacy_template_wave_split",
                {
                    "wave_id": wave.wave_id,
                    "replacement_wave_ids": replacements,
                },
            )
        return restored

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
        if approval_configured():
            # Strict mode: recon, scans, and proofs must fit an operator manifest.
            policy = activate_approval(policy)
        elif policy.allow_safe_proof or not allow_unapproved_recon:
            # Self-attested mode: the operator who runs begin_engagement asserts
            # authorization. Automatic safety (scope, rate, one wave/host, signed
            # templates, sanitized evidence) still applies. Proof also needs
            # KEEL_CREDENTIALS_FILE at execute time.
            policy = policy.model_copy(
                update={
                    "operator_confirmed": policy.allow_safe_proof,
                    "scope_approved": True,
                }
            )
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
            "max_wave_attempts": policy.max_wave_attempts,
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
        waves = list(self.waves.get(engagement_id, {}).values())
        jobs = [job for job in self.jobs.values() if job.engagement_id == engagement_id]
        return {
            "engagement_id": engagement_id,
            "too_many_count": state["too_many_count"],
            "paused_hosts": state["paused_hosts"],
            "pending_waves": sum(
                wave.state != WaveState.TERMINAL_FAILED for wave in waves
            ),
            "terminal_failed_waves": sum(
                wave.state == WaveState.TERMINAL_FAILED for wave in waves
            ),
            "active_jobs": sum(job.state in _ACTIVE_JOB_STATES for job in jobs),
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

    def start_wave(self, engagement_id: str, wave_id: str) -> dict:
        self._session(engagement_id)
        with self._lock:
            spec = self.waves.get(engagement_id, {}).get(wave_id)
            if spec is None:
                raise PolicyDenied(f"unknown wave {wave_id}")
            if (
                spec.state == WaveState.TERMINAL_FAILED
                or spec.attempt_count >= spec.max_attempts
            ):
                raise PolicyDenied(
                    f"wave {wave_id} reached its terminal attempt limit "
                    f"({spec.max_attempts})"
                )
            for existing in self.jobs.values():
                if (
                    existing.engagement_id == engagement_id
                    and existing.wave_id == wave_id
                    and existing.state in _ACTIVE_JOB_STATES
                ):
                    return self.wave_status(engagement_id, existing.job_id)
            now = _now()
            job = WaveJob(
                job_id=str(uuid4()),
                engagement_id=engagement_id,
                wave_id=wave_id,
                created_at=now,
                updated_at=now,
            )
            event = threading.Event()
            self.jobs[job.job_id] = job
            self._job_events[job.job_id] = event
            self.stores[engagement_id].save_job(job)
            self.stores[engagement_id].append_audit(
                "wave_job_queued", {"job_id": job.job_id, "wave_id": wave_id}
            )
            future = self._executor.submit(
                self._run_wave_job, engagement_id, wave_id, job.job_id, event
            )
            self._job_futures[job.job_id] = future
            if future.done():
                self._job_futures.pop(job.job_id, None)
            return self.wave_status(engagement_id, job.job_id)

    def _run_wave_job(
        self,
        engagement_id: str,
        wave_id: str,
        job_id: str,
        cancel_event: threading.Event,
    ) -> None:
        self._update_job(job_id, JobState.RUNNING, 1.0, "starting")
        try:
            result = self.execute_wave(
                engagement_id,
                wave_id,
                cancel_event=cancel_event,
                progress_callback=lambda percent, stage: self._progress_job(
                    job_id, percent, stage
                ),
                wait_for_slot=True,
            )
        except OperationCancelled as exc:
            self._finish_job(
                job_id,
                JobState.CANCELLED,
                "cancelled",
                error=exc,
            )
        except KeelError as exc:
            wave = self.waves.get(engagement_id, {}).get(wave_id)
            state = (
                JobState.TERMINAL_FAILED
                if wave is not None and wave.state == WaveState.TERMINAL_FAILED
                else JobState.RETRYABLE_FAILED
            )
            self._finish_job(job_id, state, state.value, error=exc)
        except Exception as exc:  # defensive boundary for background workers
            wave = self.waves.get(engagement_id, {}).get(wave_id)
            if wave is not None:
                wave.state = WaveState.TERMINAL_FAILED
                wave.last_error = clip(str(exc), 300)
                self.stores[engagement_id].save_wave(wave)
            self.stores[engagement_id].append_audit(
                "wave_worker_crashed",
                {
                    "job_id": job_id,
                    "wave_id": wave_id,
                    "error": type(exc).__name__,
                    "message": clip(str(exc), 300),
                },
            )
            self._finish_job(
                job_id, JobState.TERMINAL_FAILED, "worker_crashed", error=exc
            )
        else:
            self._finish_job(
                job_id, JobState.COMPLETED, "completed", result=result
            )
        finally:
            with self._lock:
                self._job_events.pop(job_id, None)
                self._job_futures.pop(job_id, None)

    def wave_status(self, engagement_id: str, job_id: str = "") -> dict:
        self._session(engagement_id)
        with self._lock:
            if not job_id:
                waves = [
                    wave.model_dump()
                    for wave in self.waves.get(engagement_id, {}).values()
                ]
                jobs = [
                    job.model_dump()
                    for job in self.jobs.values()
                    if job.engagement_id == engagement_id
                ]
                jobs.sort(key=lambda item: str(item["created_at"]), reverse=True)
                return {"jobs": jobs, "waves": waves}
            job = self.jobs.get(job_id)
            if job is None or job.engagement_id != engagement_id:
                raise PolicyDenied(f"unknown wave job {job_id}")
            wave = self.waves.get(engagement_id, {}).get(job.wave_id)
            return {
                "job": job.model_dump(),
                "wave": wave.model_dump() if wave is not None else None,
            }

    def cancel_wave(self, engagement_id: str, job_id: str) -> dict:
        self._session(engagement_id)
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None or job.engagement_id != engagement_id:
                raise PolicyDenied(f"unknown wave job {job_id}")
            if job.state not in _ACTIVE_JOB_STATES:
                return self.wave_status(engagement_id, job_id)
            event = self._job_events.get(job_id)
            if event is not None:
                event.set()
            future = self._job_futures.get(job_id)
            if future is not None and future.cancel():
                self._finish_job(
                    job_id,
                    JobState.CANCELLED,
                    "cancelled_before_start",
                    error=OperationCancelled("wave cancelled before scanner launch"),
                )
                self._job_events.pop(job_id, None)
                self._job_futures.pop(job_id, None)
            else:
                self._update_job(
                    job_id, JobState.CANCELLING, job.progress_percent, "cancelling"
                )
            self.stores[engagement_id].append_audit(
                "wave_job_cancel_requested",
                {"job_id": job_id, "wave_id": job.wave_id},
            )
            return self.wave_status(engagement_id, job_id)

    def _progress_job(self, job_id: str, percent: float, stage: str) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None or job.state not in {JobState.RUNNING, JobState.CANCELLING}:
                return
            bounded = max(job.progress_percent, min(99.0, percent))
            if stage == job.stage and bounded - job.progress_percent < 0.5:
                return
            self._update_job(job_id, job.state, bounded, stage)

    def _update_job(
        self, job_id: str, state: JobState, progress_percent: float, stage: str
    ) -> None:
        with self._lock:
            job = self.jobs[job_id]
            job.state = state
            job.progress_percent = max(0.0, min(100.0, progress_percent))
            job.stage = stage
            job.updated_at = _now()
            self.stores[job.engagement_id].save_job(job)

    def _finish_job(
        self,
        job_id: str,
        state: JobState,
        stage: str,
        result: dict | None = None,
        error: Exception | None = None,
    ) -> None:
        with self._lock:
            job = self.jobs[job_id]
            job.state = state
            job.progress_percent = 100.0 if state == JobState.COMPLETED else job.progress_percent
            job.stage = stage
            job.updated_at = _now()
            job.result = result
            if error is not None:
                job.error_type = type(error).__name__
                job.error_message = clip(str(error), 300)
            self.stores[job.engagement_id].save_job(job)
            self.stores[job.engagement_id].append_audit(
                "wave_job_finished",
                {
                    "job_id": job_id,
                    "wave_id": job.wave_id,
                    "state": state.value,
                    "error": job.error_type,
                },
            )

    def execute_wave(
        self,
        engagement_id: str,
        wave_id: str,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[float, str], None] | None = None,
        wait_for_slot: bool = False,
    ) -> dict:
        session = self._session(engagement_id)
        revalidate_scope_approval(session.policy)
        spec = self.waves.get(engagement_id, {}).get(wave_id)
        if spec is None:
            raise PolicyDenied(f"unknown wave {wave_id}")
        if spec.state == WaveState.TERMINAL_FAILED or spec.attempt_count >= spec.max_attempts:
            spec.state = WaveState.TERMINAL_FAILED
            self.stores[engagement_id].save_wave(spec)
            raise PolicyDenied(
                f"wave {wave_id} reached its terminal attempt limit ({spec.max_attempts})"
            )
        if (
            spec.kind == WaveKind.TEMPLATE_SCAN
            and not session.policy.external_template_scan_allowed(spec.target)
        ):
            raise PolicyDenied(
                "external template scans are disabled for path-bounded scope or exclusions"
            )
        runner = self.runners[engagement_id]
        _notify_progress(progress_callback, 2.0, "validating_policy")
        host = _admit_wave(
            runner,
            spec,
            cancel_event,
            progress_callback,
            wait_for_slot,
        )
        released = False
        try:
            # A background wave may have waited for another wave on the same host.
            # Re-read the approval at the actual launch boundary so a revoked or
            # narrowed manifest cannot become stale while the job is queued.
            revalidate_scope_approval(session.policy)
            _notify_progress(progress_callback, 4.0, "revalidating_before_launch")
            if cancel_event is not None and cancel_event.is_set():
                raise OperationCancelled("wave cancelled before scanner launch")
            rate = session.policy.requests_per_second
            request_budget = _wave_request_budget(session.policy, spec)
            session.reserve_requests(request_budget)
            self._persist_session(engagement_id)
            spec.attempt_count += 1
            spec.state = WaveState.RUNNING
            spec.last_error = ""
            spec.extra["reserved_requests"] = request_budget
            self.stores[engagement_id].save_wave(spec)
            self.stores[engagement_id].append_audit(
                "wave_attempt_reserved",
                {
                    "wave_id": wave_id,
                    "attempt": spec.attempt_count,
                    "reserved_requests": request_budget,
                    "engagement_requests_reserved": session.state()["requests_reserved"],
                },
            )
            _notify_progress(progress_callback, 8.0, "request_budget_reserved")
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
                    cancel_event=cancel_event,
                    progress_callback=progress_callback,
                )
            elif spec.kind == WaveKind.TEMPLATE_SCAN:
                severity = str(spec.extra.get("severity", "medium,high,critical"))
                template_id = str(spec.extra.get("template_id", ""))
                if not template_id:
                    raise PolicyDenied("a reviewed Nuclei template id is required")
                if not re.fullmatch(r"[A-Za-z0-9._:-]+", template_id):
                    raise PolicyDenied("unsafe nuclei template id")
                if template_id not in session.policy.nuclei_template_ids:
                    raise PolicyDenied("Nuclei template is outside operator selection")
                result = template_scan(
                    spec.target,
                    scanner_rate,
                    severity,
                    timeout=scanner_timeout,
                    max_response_bytes=session.policy.max_response_bytes,
                    template_id=template_id,
                    project_path=(
                        self.data_dir
                        / ".nuclei-projects"
                        / engagement_id
                        / spec.wave_id
                    ),
                    cancel_event=cancel_event,
                    progress_callback=progress_callback,
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
            if cancel_event is not None and cancel_event.is_set():
                raise OperationCancelled("wave cancelled before result validation")
            _notify_progress(progress_callback, 90.0, "validating_scanner_output")
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
            terminal = (
                spec.attempt_count >= spec.max_attempts
                or (
                    isinstance(exc, PolicyDenied)
                    and "budget exhausted" in str(exc)
                )
            )
            spec.state = (
                WaveState.TERMINAL_FAILED
                if terminal
                else WaveState.RETRYABLE_FAILED
            )
            spec.last_error = clip(str(exc), 300)
            self.stores[engagement_id].save_wave(spec)
            self.stores[engagement_id].append_audit(
                "wave_execution_failed",
                {
                    "wave_id": wave_id,
                    "error": type(exc).__name__,
                    "message": clip(str(exc), 300),
                    "attempt": spec.attempt_count,
                    "wave_state": spec.state.value,
                },
            )
            raise
        finally:
            if not released:
                runner.finish(host)
        store = self.stores[engagement_id]
        _notify_progress(progress_callback, 95.0, "ingesting_results")
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
        _notify_progress(progress_callback, 100.0, "completed")
        return {
            "wave_id": wave_id,
            "completed": True,
            "throttled": result.throttled,
            "returncode": result.returncode,
            "cards": stored,
            "dropped_out_of_scope": len(fresh) - len(admitted),
        }

    def query_cards(self, engagement_id: str, include_noise: bool = False) -> list[dict]:
        self._session(engagement_id)
        return [card.model_dump() for card in self.stores[engagement_id].query(include_noise)]

    def second_look(
        self, engagement_id: str, card_id: str, background: bool = False
    ) -> dict:
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
            max_attempts=session.policy.max_wave_attempts,
            extra={"severity": card.scanner_severity, "template_id": template_id},
        )
        self.waves[engagement_id][spec.wave_id] = spec
        self.stores[engagement_id].save_wave(spec)
        if background:
            return self.start_wave(engagement_id, spec.wave_id)
        return self.execute_wave(engagement_id, spec.wave_id)

    def assess_exploitability(self, engagement_id: str, card_id: str) -> dict:
        self._session(engagement_id)
        store = self.stores[engagement_id]
        card = store.get(card_id)
        if card is None:
            raise UnknownCard(card_id)
        card = assess_card(card)
        stored = store.upsert(card)
        store.append_audit(
            "exploitability_assessed",
            {
                "card_id": card_id,
                "state": stored.exploitability.state.value,
                "candidate_impact": stored.exploitability.candidate_impact.value,
                "safe_proof_playbooks": stored.exploitability.safe_proof_playbooks,
            },
        )
        return {
            "card_id": stored.card_id,
            "vulnerability_class": stored.vulnerability_class,
            "validation_state": stored.validation_state,
            "assessment": stored.exploitability.model_dump(),
        }

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
        if approval_configured():
            grant, proof_target = proof_target_for(
                session.policy,
                playbook_id,
                proof_target_ref,
                card_url,
                expected_marker,
                session_a,
                session_b,
            )
            owner_ref = proof_target.owner_credential_ref
            peer_ref = proof_target.peer_credential_ref
            proof_budget_cap = grant.max_proof_requests
            audit_target_ref = proof_target_ref
        else:
            if not session.policy.allow_safe_proof or not session.policy.operator_confirmed:
                raise KeelError(
                    "safe proof requires begin_engagement(allow_safe_proof=True)"
                )
            owner_ref = session_a or session.policy.tester_account_a
            peer_ref = session_b or session.policy.tester_account_b
            proof_budget_cap = session.policy.max_proof_requests
            audit_target_ref = proof_target_ref or "self_attested"
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
                min(draft.request_budget, proof_budget_cap),
            )
            session.reserve_requests(broker.max_requests)
            self._persist_session(engagement_id)
            outcome = run_playbook(
                session.policy,
                card,
                playbook_id,
                owner_ref,
                peer_ref,
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
                    "proof_target_ref": audit_target_ref,
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
        elif decision == "protected" and playbook_id in PROVING_PLAYBOOKS:
            card = mark_refuted(card)
        store.upsert(card)
        store.append_audit(
            "proof_completed",
            {
                "card_id": card_id,
                "playbook_id": playbook_id,
                "proof_target_ref": audit_target_ref,
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _notify_progress(
    callback: Callable[[float, str], None] | None,
    percent: float,
    stage: str,
) -> None:
    if callback is not None:
        callback(percent, stage)


def _admit_wave(
    runner: WaveRunner,
    spec: WaveSpec,
    cancel_event: threading.Event | None,
    progress_callback: Callable[[float, str], None] | None,
    wait_for_slot: bool,
) -> str:
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise OperationCancelled("wave cancelled while waiting for a host slot")
        try:
            return runner.admit(spec)
        except WaveBusy:
            if not wait_for_slot:
                raise
            _notify_progress(progress_callback, 2.0, "waiting_for_host_slot")
            if cancel_event is not None:
                cancel_event.wait(0.1)
            else:
                threading.Event().wait(0.1)
