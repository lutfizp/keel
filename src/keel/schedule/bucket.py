from __future__ import annotations

import time
import threading


class TokenBucket:
    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(rate_per_second, 0.1)
        self.tokens = self.rate
        self.stamp = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> None:
        with self._lock:
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
    def __init__(self, rate_per_second: float, max_parallel_hosts: int = 1) -> None:
        self.rate = rate_per_second
        self.global_bucket = TokenBucket(rate_per_second)
        self.by_host: dict[str, TokenBucket] = {}
        self.max_parallel_hosts = max_parallel_hosts
        self.active_hosts: set[str] = set()
        self._lock = threading.Lock()

    def gate(self, host: str) -> None:
        with self._lock:
            if host in self.active_hosts:
                raise RuntimeError(f"host {host} already has an active wave")
            if len(self.active_hosts) >= self.max_parallel_hosts:
                raise RuntimeError("maximum parallel host waves reached")
            self.active_hosts.add(host)
        self.consume_request(host)

    def consume_request(self, host: str) -> None:
        with self._lock:
            bucket = self.by_host.setdefault(host, TokenBucket(self.rate))
        bucket.consume()
        self.global_bucket.consume()

    def release(self, host: str) -> None:
        with self._lock:
            self.active_hosts.discard(host)
