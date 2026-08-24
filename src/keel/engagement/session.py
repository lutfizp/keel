from uuid import uuid4
import time
import threading

from keel.engagement.policy import EngagementPolicy
from keel.errors import PolicyDenied
from keel.engagement.urls import host_of
from keel.models import ProbeClass, WaveKind, WaveSpec


class EngagementSession:
    def __init__(self, policy: EngagementPolicy) -> None:
        self.policy = policy
        self.paused_hosts: dict[str, float] = {}
        self.too_many_count: int = 0
        self.requests_reserved: int = 0
        self._lock = threading.RLock()

    def active_pauses(self) -> dict[str, float]:
        with self._lock:
            now = time.time()
            self.paused_hosts = {
                host: until for host, until in self.paused_hosts.items() if until > now
            }
            return dict(self.paused_hosts)

    def state(self) -> dict:
        with self._lock:
            return {
                "paused_hosts": self.active_pauses(),
                "too_many_count": self.too_many_count,
                "requests_reserved": self.requests_reserved,
            }

    def restore_state(self, payload: dict) -> None:
        with self._lock:
            self.paused_hosts = {
                str(host): float(until)
                for host, until in dict(payload.get("paused_hosts", {})).items()
            }
            self.too_many_count = int(payload.get("too_many_count", 0))
            self.requests_reserved = int(payload.get("requests_reserved", 0))
            self.active_pauses()

    def reserve_requests(self, count: int) -> None:
        with self._lock:
            if count < 1:
                raise PolicyDenied("request reservation must be positive")
            if self.requests_reserved + count > self.policy.max_engagement_requests:
                remaining = self.policy.max_engagement_requests - self.requests_reserved
                raise PolicyDenied(
                    f"engagement request budget exhausted; remaining={remaining}, requested={count}"
                )
            self.requests_reserved += count

    def requests_remaining(self) -> int:
        with self._lock:
            return max(0, self.policy.max_engagement_requests - self.requests_reserved)

    def cooldown_until(self, host: str) -> float:
        with self._lock:
            return self.paused_hosts.get(host, 0.0)

    def note_throttle(self, host: str, retry_after_seconds: float | None) -> None:
        with self._lock:
            self.too_many_count += 1
            exponent = min(max(0, self.too_many_count - 1), 4)
            exponential = min(300.0, 30.0 * (2**exponent))
            cooldown = max(exponential, retry_after_seconds or 0.0)
            self.paused_hosts[host] = time.time() + cooldown

    def draft_waves(self, seed_url: str) -> list[WaveSpec]:
        if not self.policy.url_allowed(seed_url):
            return []
        waves = [
            WaveSpec(
                wave_id=str(uuid4()),
                kind=WaveKind.PROBE_ALIVE,
                probe_class=ProbeClass.SAFE_ACTIVE,
                target=seed_url,
                max_attempts=self.policy.max_wave_attempts,
            )
        ]
        if (
            self.policy.nuclei_template_ids
            and self.policy.external_template_scan_allowed(seed_url)
        ):
            waves.extend(
                WaveSpec(
                    wave_id=str(uuid4()),
                    kind=WaveKind.TEMPLATE_SCAN,
                    probe_class=ProbeClass.SAFE_ACTIVE,
                    target=seed_url,
                    max_attempts=self.policy.max_wave_attempts,
                    extra={
                        "severity": "medium,high,critical",
                        "template_id": template_id,
                    },
                )
                for template_id in self.policy.nuclei_template_ids
            )
        return waves
