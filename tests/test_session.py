from keel.engagement.policy import EngagementPolicy
from keel.engagement.session import EngagementSession
from keel.models import WaveKind
from keel.runtime import Workspace
from keel.schedule.bucket import TokenBucket
from pathlib import Path


def test_draft_waves_in_scope() -> None:
    policy = EngagementPolicy(engagement_id="e", scope_hosts=["example.com"])
    waves = EngagementSession(policy).draft_waves("https://app.example.com/")
    assert [item.kind for item in waves] == [WaveKind.PROBE_ALIVE, WaveKind.TEMPLATE_SCAN]


def test_draft_waves_out_of_scope() -> None:
    policy = EngagementPolicy(engagement_id="e", scope_hosts=["example.com"])
    assert EngagementSession(policy).draft_waves("https://other.test/") == []


def test_bucket_does_not_raise() -> None:
    bucket = TokenBucket(100.0)
    bucket.consume()
    bucket.consume()


def test_health_unknown(tmp_path: Path) -> None:
    space = Workspace(tmp_path)
    payload = space.health()
    assert payload["engagements"] == []
