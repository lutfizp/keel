from keel.engagement.policy import EngagementPolicy
from keel.engagement.session import EngagementSession
from keel.models import WaveKind
from keel.runtime import Workspace
from keel.errors import PolicyDenied
from keel.schedule.bucket import BucketMap, TokenBucket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest


def test_draft_waves_in_scope() -> None:
    policy = EngagementPolicy(
        engagement_id="e",
        scope_hosts=["*.example.com"],
        nuclei_template_ids=["reviewed-template"],
    )
    waves = EngagementSession(policy).draft_waves("https://app.example.com/")
    assert [item.kind for item in waves] == [WaveKind.PROBE_ALIVE, WaveKind.TEMPLATE_SCAN]


def test_draft_waves_out_of_scope() -> None:
    policy = EngagementPolicy(engagement_id="e", scope_hosts=["example.com"])
    assert EngagementSession(policy).draft_waves("https://other.test/") == []


def test_path_bounded_scope_drafts_only_exact_reachability() -> None:
    policy = EngagementPolicy(
        engagement_id="path",
        scope_hosts=["https://app.example.com/api"],
        nuclei_template_ids=["reviewed-template"],
    )

    waves = EngagementSession(policy).draft_waves("https://app.example.com/api")

    assert [item.kind for item in waves] == [WaveKind.PROBE_ALIVE]


def test_no_template_allowlist_drafts_only_reachability() -> None:
    policy = EngagementPolicy(engagement_id="no-templates", scope_hosts=["example.com"])

    waves = EngagementSession(policy).draft_waves("https://example.com/")

    assert [item.kind for item in waves] == [WaveKind.PROBE_ALIVE]


def test_each_reviewed_template_is_drafted_as_its_own_micro_wave() -> None:
    policy = EngagementPolicy(
        engagement_id="micro",
        scope_hosts=["example.com"],
        nuclei_template_ids=["template-a", "template-b"],
        max_wave_attempts=3,
    )

    waves = EngagementSession(policy).draft_waves("https://example.com/")
    templates = [wave for wave in waves if wave.kind == WaveKind.TEMPLATE_SCAN]

    assert [wave.extra["template_id"] for wave in templates] == [
        "template-a",
        "template-b",
    ]
    assert all(wave.max_attempts == 3 for wave in waves)


def test_bucket_does_not_raise() -> None:
    bucket = TokenBucket(100.0)
    bucket.consume()
    bucket.consume()


def test_health_unknown(tmp_path: Path) -> None:
    space = Workspace(tmp_path)
    payload = space.health()
    assert payload["engagements"] == []


def test_only_one_active_wave_per_host() -> None:
    buckets = BucketMap(100, max_parallel_hosts=2)
    buckets.gate("a.example")
    try:
        with pytest.raises(RuntimeError, match="already has an active wave"):
            buckets.gate("a.example")
    finally:
        buckets.release("a.example")


def test_engagement_request_budget_is_fail_closed() -> None:
    session = EngagementSession(
        EngagementPolicy(
            engagement_id="budget",
            scope_hosts=["example.com"],
            max_engagement_requests=2,
        )
    )
    session.reserve_requests(2)

    with pytest.raises(PolicyDenied, match="budget exhausted"):
        session.reserve_requests(1)


def test_concurrent_request_reservations_cannot_overspend() -> None:
    session = EngagementSession(
        EngagementPolicy(
            engagement_id="concurrent-budget",
            scope_hosts=["example.com"],
            max_engagement_requests=1,
        )
    )

    def reserve() -> bool:
        try:
            session.reserve_requests(1)
        except PolicyDenied:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: reserve(), range(2)))

    assert sorted(outcomes) == [False, True]
    assert session.requests_reserved == 1
