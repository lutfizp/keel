from __future__ import annotations

import time

from keel.errors import PolicyDenied, WaveBusy
from keel.engagement.session import EngagementSession
from keel.engagement.urls import host_of
from keel.models import WaveSpec
from keel.schedule.bucket import BucketMap


class WaveRunner:
    def __init__(self, session: EngagementSession, buckets: BucketMap) -> None:
        self.session = session
        self.buckets = buckets

    def admit(self, spec: WaveSpec) -> str:
        policy = self.session.policy
        host = host_of(spec.target)
        if not policy.url_allowed(spec.target):
            raise PolicyDenied(f"target {spec.target} is outside exact scope")
        if not policy.class_allowed(spec.probe_class):
            raise PolicyDenied(f"class {spec.probe_class.value} is not allowed")
        until = self.session.cooldown_until(host)
        now = time.time()
        if until > now:
            raise PolicyDenied(f"host {host} is cooling down")
        try:
            self.buckets.gate(host)
        except RuntimeError as exc:
            raise WaveBusy(str(exc)) from exc
        return host

    def note_throttle(self, host: str, retry_after_seconds: float | None = None) -> None:
        self.session.note_throttle(host, retry_after_seconds)
        self.buckets.release(host)

    def finish(self, host: str) -> None:
        self.buckets.release(host)
