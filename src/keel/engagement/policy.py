from __future__ import annotations

from pydantic import BaseModel, Field

from keel.models import ProbeClass


class EngagementPolicy(BaseModel):
    engagement_id: str
    scope_hosts: list[str]
    exclude_hosts: list[str] = Field(default_factory=list)
    requests_per_second: float = 3.0
    max_parallel_hosts: int = 1
    allowed_classes: list[ProbeClass] = Field(
        default_factory=lambda: [ProbeClass.PASSIVE, ProbeClass.SAFE_ACTIVE]
    )
    allow_safe_proof: bool = False
    operator_confirmed: bool = False
    tester_account_a: str = ""
    tester_account_b: str = ""

    def host_allowed(self, host: str) -> bool:
        lowered = host.lower()
        if any(lowered == item.lower() or lowered.endswith("." + item.lower()) for item in self.exclude_hosts):
            return False
        return any(
            lowered == item.lower() or lowered.endswith("." + item.lower()) for item in self.scope_hosts
        )

    def class_allowed(self, probe_class: ProbeClass) -> bool:
        return probe_class in self.allowed_classes
