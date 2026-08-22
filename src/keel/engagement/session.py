from uuid import uuid4

from keel.engagement.policy import EngagementPolicy
from keel.engagement.urls import host_of
from keel.models import ProbeClass, WaveKind, WaveSpec


class EngagementSession:
    def __init__(self, policy: EngagementPolicy) -> None:
        self.policy = policy
        self.paused_hosts: dict[str, float] = {}
        self.too_many_count: int = 0

    def draft_waves(self, seed_url: str) -> list[WaveSpec]:
        host = host_of(seed_url)
        if not self.policy.host_allowed(host):
            return []
        return [
            WaveSpec(
                wave_id=str(uuid4()),
                kind=WaveKind.PROBE_ALIVE,
                probe_class=ProbeClass.SAFE_ACTIVE,
                target=seed_url,
            ),
            WaveSpec(
                wave_id=str(uuid4()),
                kind=WaveKind.TEMPLATE_SCAN,
                probe_class=ProbeClass.SAFE_ACTIVE,
                target=seed_url,
                extra={"severity": "medium,high,critical"},
            ),
        ]
