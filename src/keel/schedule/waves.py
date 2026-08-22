from __future__ import annotations

import time

from keel.errors import PolicyDenied
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
        if not policy.host_allowed(host):
            raise PolicyDenied(f"host {host} is outside scope")
        if not policy.class_allowed(spec.probe_class):
            raise PolicyDenied(f"class {spec.probe_class.value} is not allowed")
        until = self.session.paused_hosts.get(host, 0.0)
        now = time.monotonic()
        if until > now:
            raise PolicyDenied(f"host {host} is cooling down")
        self.buckets.gate(host)
        return host

    def note_throttle(self, host: str) -> None:
        self.session.too_many_count += 1
        self.session.paused_hosts[host] = time.monotonic() + 30.0
        self.buckets.release(host)

    def finish(self, host: str) -> None:
        self.buckets.release(host)
