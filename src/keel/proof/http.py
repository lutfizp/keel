from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Mapping

import httpx

from keel.engagement.policy import EngagementPolicy
from keel.engagement.urls import host_of
from keel.errors import ProofDenied, ProofFailed, TargetThrottled
from keel.schedule.bucket import BucketMap


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    body: str
    body_sha256: str
    truncated: bool
    content_type: str
    location: str = ""
    url: str = ""


class ProofRequestBroker:
    def __init__(
        self,
        policy: EngagementPolicy,
        buckets: BucketMap,
        max_requests: int,
        client: httpx.Client | None = None,
    ) -> None:
        self.policy = policy
        self.buckets = buckets
        self.max_requests = min(max_requests, policy.max_proof_requests)
        self.requests_made = 0
        self._client = client

    def get(self, url: str, headers: Mapping[str, str]) -> SafeResponse:
        if not self.policy.url_allowed(url):
            raise ProofDenied(f"proof URL is outside exact engagement scope: {url}")
        if self.requests_made >= self.max_requests:
            raise ProofDenied(f"proof request budget exhausted ({self.max_requests})")
        host = host_of(url)
        self.buckets.consume_request(host)
        self.requests_made += 1

        owned_client = self._client is None
        client = self._client
        try:
            if client is None:
                client = httpx.Client(
                    timeout=20.0,
                    follow_redirects=False,
                    trust_env=False,
                )
            with client.stream("GET", url, headers=dict(headers)) as response:
                if response.status_code == 429:
                    raise TargetThrottled(host, _retry_after(response.headers))
                body_bytes = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    remaining = self.policy.max_response_bytes - len(body_bytes)
                    if remaining <= 0:
                        truncated = True
                        break
                    body_bytes.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                encoding = response.encoding or "utf-8"
                body = bytes(body_bytes).decode(encoding, errors="replace")
                return SafeResponse(
                    status_code=response.status_code,
                    body=body,
                    body_sha256=hashlib.sha256(body_bytes).hexdigest(),
                    truncated=truncated,
                    content_type=response.headers.get("content-type", "")[:200],
                    location=str(response.headers.get("location", "") or "")[:2048],
                    url=url,
                )
        except TargetThrottled:
            raise
        except httpx.HTTPError as exc:
            raise ProofFailed(
                f"proof request failed without a valid response: {type(exc).__name__}"
            ) from exc
        finally:
            if owned_client and client is not None:
                client.close()


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = str(headers.get("retry-after", "")).strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
