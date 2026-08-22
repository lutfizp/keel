from __future__ import annotations

import time


class TokenBucket:
    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(rate_per_second, 0.1)
        self.tokens = self.rate
        self.stamp = time.monotonic()

    def consume(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return
        wait = (1.0 - self.tokens) / self.rate
        time.sleep(wait)
        self.tokens = 0.0
        self.stamp = time.monotonic()


class BucketMap:
    def __init__(self, rate_per_second: float) -> None:
        self.rate = rate_per_second
        self.global_bucket = TokenBucket(rate_per_second)
        self.by_host: dict[str, TokenBucket] = {}
        self.active_host: str | None = None

    def gate(self, host: str) -> None:
        if self.active_host not in (None, host):
            raise RuntimeError(f"host {self.active_host} still holds the single-host slot")
        self.active_host = host
        self.by_host.setdefault(host, TokenBucket(self.rate)).consume()
        self.global_bucket.consume()

    def release(self, host: str) -> None:
        if self.active_host == host:
            self.active_host = None
