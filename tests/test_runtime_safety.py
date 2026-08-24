import json
import threading
import time
from pathlib import Path

import httpx
import pytest

from keel.adapters.base import CommandResult
from keel.engagement.policy import EngagementPolicy
from keel.errors import AdapterFailed, OperationCancelled, PolicyDenied
from keel.models import (
    FindingCard,
    JobState,
    ValidationState,
    WaveJob,
    WaveKind,
    WaveState,
)
from keel.proof.http import ProofRequestBroker
from keel.runtime import Workspace


@pytest.fixture(autouse=True)
def allow_unapproved_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEEL_ALLOW_UNAPPROVED_RECON", "1")


def _policy() -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="runtime",
        scope_hosts=["app.example.com"],
        requests_per_second=20,
        nuclei_template_ids=["idor-template"],
    )


def _draft(space: Workspace) -> list[dict]:
    space.begin(_policy())
    return space.draft_waves("runtime", "https://app.example.com/")


def _wait_for_job(
    space: Workspace,
    job_id: str,
    expected: set[JobState],
    timeout: float = 2.0,
) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = space.wave_status("runtime", job_id)
        if status["job"]["state"] in expected:
            return status
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not reach {expected}")


def test_pending_waves_and_audit_survive_restart(tmp_path: Path) -> None:
    first = Workspace(tmp_path)
    _draft(first)

    restored = Workspace(tmp_path)

    assert restored.health("runtime")["pending_waves"] == 2
    events = restored.audit("runtime")
    assert {event["event_type"] for event in events} >= {
        "engagement_started",
        "waves_drafted",
    }
    assert restored.begin(_policy())["resumed"] is True


def test_running_job_is_restored_as_interrupted_and_wave_is_retryable(
    tmp_path: Path,
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    wave = space.waves["runtime"][probe["wave_id"]]
    wave.state = WaveState.RUNNING
    wave.attempt_count = 1
    space.stores["runtime"].save_wave(wave)
    job = WaveJob(
        job_id="interrupted-job",
        engagement_id="runtime",
        wave_id=wave.wave_id,
        state=JobState.RUNNING,
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )
    space.stores["runtime"].save_job(job)

    restored = Workspace(tmp_path)
    status = restored.wave_status("runtime", "interrupted-job")

    assert status["job"]["state"] == JobState.INTERRUPTED
    assert status["wave"]["state"] == WaveState.RETRYABLE_FAILED
    assert status["wave"]["attempt_count"] == 1


def test_nonzero_scanner_exit_keeps_wave_and_ingests_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    monkeypatch.setattr(
        "keel.runtime.probe_alive",
        lambda *_, **__: CommandResult(
            argv=["httpx"],
            returncode=2,
            stdout='{"url":"https://app.example.com/"}\n',
            stderr="scanner failed",
            throttled=False,
        ),
    )

    with pytest.raises(AdapterFailed, match="wave retained"):
        space.execute_wave("runtime", probe["wave_id"])

    assert space.health("runtime")["pending_waves"] == 2
    assert space.query_cards("runtime", include_noise=True) == []


def test_retry_requires_a_new_engagement_request_reservation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = _policy().model_copy(update={"max_engagement_requests": 1})
    space = Workspace(tmp_path)
    space.begin(policy)
    waves = space.draft_waves("runtime", "https://app.example.com/")
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    calls = 0

    def failed_probe(*_: object, **__: object) -> CommandResult:
        nonlocal calls
        calls += 1
        return CommandResult(
            argv=["httpx"],
            returncode=2,
            stdout="",
            stderr="scanner failed",
            throttled=False,
        )

    monkeypatch.setattr("keel.runtime.probe_alive", failed_probe)

    with pytest.raises(AdapterFailed, match="wave retained"):
        space.execute_wave("runtime", probe["wave_id"])
    with pytest.raises(PolicyDenied, match="budget exhausted"):
        space.execute_wave("runtime", probe["wave_id"])

    assert calls == 1
    assert space.health("runtime")["requests_reserved"] == 1
    assert space.health("runtime")["pending_waves"] == 1
    assert space.health("runtime")["terminal_failed_waves"] == 1


def test_wave_becomes_terminal_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    calls = 0

    def failed_probe(*_: object, **__: object) -> CommandResult:
        nonlocal calls
        calls += 1
        return CommandResult(["httpx"], 2, "", "failed", False)

    monkeypatch.setattr("keel.runtime.probe_alive", failed_probe)

    for _ in range(2):
        with pytest.raises(AdapterFailed, match="wave retained"):
            space.execute_wave("runtime", probe["wave_id"])
    with pytest.raises(PolicyDenied, match="terminal attempt limit"):
        space.execute_wave("runtime", probe["wave_id"])

    assert calls == 2
    stored = space.waves["runtime"][probe["wave_id"]]
    assert stored.state == WaveState.TERMINAL_FAILED
    assert stored.attempt_count == 2


def test_background_wave_reports_progress_and_survives_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)

    def successful_probe(*_: object, **kwargs: object) -> CommandResult:
        callback = kwargs["progress_callback"]
        callback(55.0, "scanner_running")
        return CommandResult(
            ["httpx"],
            0,
            '{"url":"https://app.example.com/","status_code":200}\n',
            "",
            False,
        )

    monkeypatch.setattr("keel.runtime.probe_alive", successful_probe)

    started = space.start_wave("runtime", probe["wave_id"])
    job_id = started["job"]["job_id"]
    completed = _wait_for_job(space, job_id, {JobState.COMPLETED})

    assert completed["job"]["progress_percent"] == 100.0
    assert completed["job"]["result"]["cards"]
    assert completed["wave"] is None

    restored = Workspace(tmp_path)
    restored_status = restored.wave_status("runtime", job_id)
    assert restored_status["job"]["state"] == JobState.COMPLETED
    assert restored_status["job"]["result"]["cards"]
    listing = restored.wave_status("runtime")
    assert [job["job_id"] for job in listing["jobs"]] == [job_id]


def test_background_wave_can_cancel_running_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    scanner_started = threading.Event()

    def cancellable_probe(*_: object, **kwargs: object) -> CommandResult:
        cancel_event = kwargs["cancel_event"]
        callback = kwargs["progress_callback"]
        scanner_started.set()
        while not cancel_event.wait(0.01):
            callback(25.0, "scanner_running")
        raise OperationCancelled("test scanner cancelled")

    monkeypatch.setattr("keel.runtime.probe_alive", cancellable_probe)

    started = space.start_wave("runtime", probe["wave_id"])
    job_id = started["job"]["job_id"]
    assert scanner_started.wait(1.0)
    space.cancel_wave("runtime", job_id)
    cancelled = _wait_for_job(space, job_id, {JobState.CANCELLED})

    assert cancelled["job"]["error_type"] == "OperationCancelled"
    assert cancelled["wave"]["state"] == WaveState.RETRYABLE_FAILED
    assert space.query_cards("runtime", include_noise=True) == []


def test_background_micro_waves_wait_for_same_host_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    template = next(item for item in waves if item["kind"] == WaveKind.TEMPLATE_SCAN)
    probe_started = threading.Event()
    release_probe = threading.Event()

    def slow_probe(*_: object, **__: object) -> CommandResult:
        probe_started.set()
        assert release_probe.wait(1.0)
        return CommandResult(
            ["httpx"],
            0,
            '{"url":"https://app.example.com/","status_code":200}\n',
            "",
            False,
        )

    monkeypatch.setattr("keel.runtime.probe_alive", slow_probe)
    monkeypatch.setattr(
        "keel.runtime.template_scan",
        lambda *_, **__: CommandResult(["nuclei"], 0, "", "", False),
    )

    first = space.start_wave("runtime", probe["wave_id"])
    assert probe_started.wait(1.0)
    second = space.start_wave("runtime", template["wave_id"])
    second_job = second["job"]["job_id"]
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        status = space.wave_status("runtime", second_job)
        if status["job"]["stage"] == "waiting_for_host_slot":
            break
        time.sleep(0.01)
    else:
        raise AssertionError("second micro-wave did not wait for the host slot")

    release_probe.set()
    _wait_for_job(space, first["job"]["job_id"], {JobState.COMPLETED})
    _wait_for_job(space, second_job, {JobState.COMPLETED})


def test_wave_revalidates_approval_at_scanner_launch_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    validation_calls = 0
    scanner_calls = 0

    def approval_changed(_: EngagementPolicy) -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 2:
            raise PolicyDenied("approval changed while the wave was queued")

    def successful_probe(*_: object, **__: object) -> CommandResult:
        nonlocal scanner_calls
        scanner_calls += 1
        return CommandResult(
            ["httpx"],
            0,
            '{"url":"https://app.example.com/","status_code":200}\n',
            "",
            False,
        )

    monkeypatch.setattr("keel.runtime.revalidate_scope_approval", approval_changed)
    monkeypatch.setattr("keel.runtime.probe_alive", successful_probe)

    with pytest.raises(PolicyDenied, match="approval changed"):
        space.execute_wave("runtime", probe["wave_id"])

    assert validation_calls == 2
    assert scanner_calls == 0
    assert space.waves["runtime"][probe["wave_id"]].attempt_count == 0

    result = space.execute_wave("runtime", probe["wave_id"])

    assert result["completed"] is True
    assert scanner_calls == 1


def test_malformed_scanner_output_keeps_wave_without_partial_ingest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    monkeypatch.setattr(
        "keel.runtime.probe_alive",
        lambda *_, **__: CommandResult(
            argv=["httpx"],
            returncode=0,
            stdout=(
                '{"url":"https://app.example.com/","status_code":200}\n'
                "scanner diagnostic that is not JSON\n"
            ),
            stderr="",
            throttled=False,
        ),
    )

    with pytest.raises(AdapterFailed, match="without partial ingest"):
        space.execute_wave("runtime", probe["wave_id"])

    assert space.health("runtime")["pending_waves"] == 2
    assert space.query_cards("runtime", include_noise=True) == []
    parse_events = [
        event
        for event in space.audit("runtime")
        if event["event_type"] == "wave_parse_failed"
    ]
    assert parse_events[-1]["payload"]["malformed_lines"] == 1


def test_invalid_scanner_record_keeps_wave_without_partial_ingest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    monkeypatch.setattr(
        "keel.runtime.probe_alive",
        lambda *_, **__: CommandResult(
            argv=["httpx"],
            returncode=0,
            stdout=(
                '{"url":"https://app.example.com/","status_code":200}\n'
                '{"error":"probe failed"}\n'
            ),
            stderr="",
            throttled=False,
        ),
    )

    with pytest.raises(AdapterFailed, match="required identity fields"):
        space.execute_wave("runtime", probe["wave_id"])

    assert space.health("runtime")["pending_waves"] == 2
    assert space.query_cards("runtime", include_noise=True) == []
    schema_events = [
        event
        for event in space.audit("runtime")
        if event["event_type"] == "wave_schema_failed"
    ]
    assert schema_events[-1]["payload"]["invalid_records"] == 1


def test_throttle_honors_retry_after_and_keeps_wave(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    monkeypatch.setattr(
        "keel.runtime.probe_alive",
        lambda *_, **__: CommandResult(
            argv=["httpx"],
            returncode=0,
            stdout="",
            stderr="HTTP 429 Retry-After: 90",
            throttled=True,
            retry_after_seconds=90,
        ),
    )

    with pytest.raises(AdapterFailed, match="throttling"):
        space.execute_wave("runtime", probe["wave_id"])

    health = space.health("runtime")
    assert health["pending_waves"] == 2
    assert health["paused_hosts"]["app.example.com"] > 0


def test_out_of_scope_scanner_results_are_dropped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    waves = _draft(space)
    probe = next(item for item in waves if item["kind"] == WaveKind.PROBE_ALIVE)
    monkeypatch.setattr(
        "keel.runtime.probe_alive",
        lambda *_, **__: CommandResult(
            argv=["httpx"],
            returncode=0,
            stdout='{"url":"https://evil.example.net/","status_code":200}\n',
            stderr="",
            throttled=False,
        ),
    )

    outcome = space.execute_wave("runtime", probe["wave_id"])

    assert outcome["cards"] == []
    assert outcome["dropped_out_of_scope"] == 1


def test_second_look_runs_only_the_originating_template(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    space = Workspace(tmp_path)
    space.begin(_policy())
    card = FindingCard(
        card_id="card",
        fingerprint="card",
        semantic_key="card",
        host="app.example.com",
        path="/objects/1",
        matcher="idor-template",
        title="BOLA",
        scanner_severity="high",
        vulnerability_class="broken_object_authorization",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={
            "matched": "https://app.example.com/objects/1",
            "raw": {"template-id": "idor-template"},
        },
        sources=["nuclei"],
    )
    space.stores["runtime"].upsert(card)
    captured: dict[str, str] = {}

    def fake_scan(*_: object, **kwargs: object) -> CommandResult:
        captured["template_id"] = str(kwargs["template_id"])
        return CommandResult(
            argv=["nuclei"], returncode=0, stdout="", stderr="", throttled=False
        )

    monkeypatch.setattr("keel.runtime.template_scan", fake_scan)

    space.second_look("runtime", "card")

    assert captured["template_id"] == "idor-template"


def test_workspace_proof_uses_manifest_refs_and_persists_proven_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("KEEL_ALLOW_UNAPPROVED_RECON", raising=False)
    approval = tmp_path / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "version": 1,
                "engagements": {
                    "proof-runtime": {
                        "scope_hosts": ["app.example.com"],
                        "exclude_hosts": [],
                        "playbooks": ["cross_account_read"],
                        "credential_refs": ["tester-a", "tester-b"],
                        "max_requests_per_second": 20,
                        "max_parallel_hosts": 1,
                        "max_wave_seconds": 120,
                        "max_wave_requests": 120,
                        "max_engagement_requests": 1000,
                        "max_proof_requests": 2,
                        "proof_targets": {
                            "object-a": {
                                "url": "https://app.example.com/objects/1",
                                "canary_sha256": "8b9a3dfeeed65c5260f0960781bbd3851edd673b44bfd028afc0e934c93211f2",
                                "owner_credential_ref": "tester-a",
                                "peer_credential_ref": "tester-b",
                                "playbooks": ["cross_account_read"],
                            }
                        },
                        "expires_at": "2999-01-01T00:00:00Z",
                    }
                },
            }
        )
    )
    approval.chmod(0o600)
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "tester-a": {"authorization": "Bearer tester-a"},
                "tester-b": {"authorization": "Bearer tester-b"},
            }
        )
    )
    credentials.chmod(0o600)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    monkeypatch.setenv("KEEL_CREDENTIALS_FILE", str(credentials))

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, text="owned keel-canary-runtime")
        )
    )

    def broker_factory(policy, buckets, max_requests):
        return ProofRequestBroker(policy, buckets, max_requests, client=client)

    monkeypatch.setattr("keel.runtime.ProofRequestBroker", broker_factory)
    space = Workspace(tmp_path / "state")
    policy = EngagementPolicy(
        engagement_id="proof-runtime",
        scope_hosts=["app.example.com"],
        requests_per_second=20,
        allow_safe_proof=True,
        tester_account_a="tester-a",
        tester_account_b="tester-b",
    )
    space.begin(policy)
    card = FindingCard(
        card_id="idor-card",
        fingerprint="idor-card",
        semantic_key="idor-card",
        host="app.example.com",
        path="/objects/1",
        matcher="idor",
        title="BOLA",
        scanner_severity="high",
        vulnerability_class="broken_object_authorization",
        validation_state=ValidationState.HYPOTHESIS,
        evidence={"url": "https://app.example.com/objects/1"},
        sources=["nuclei"],
    )
    space.stores["proof-runtime"].upsert(card)
    try:
        outcome = space.execute_proof(
            "proof-runtime",
            "idor-card",
            "cross_account_read",
            "",
            "",
            "keel-canary-runtime",
            "object-a",
        )
    finally:
        client.close()

    stored = space.stores["proof-runtime"].get("idor-card")
    assert outcome["decision"] == "proven"
    assert stored is not None and stored.validation_state == ValidationState.PROVEN
    assert any(
        event["event_type"] == "proof_completed"
        for event in space.audit("proof-runtime")
    )
