from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import unquote, urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from keel.models import ProbeClass

_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9._:-]+$")


class EngagementPolicy(BaseModel):
    engagement_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    scope_hosts: list[str]
    exclude_hosts: list[str] = Field(default_factory=list)
    requests_per_second: float = Field(default=3.0, gt=0.0, le=20.0)
    max_parallel_hosts: int = Field(default=1, ge=1, le=4)
    max_wave_seconds: int = Field(default=120, ge=10, le=600)
    max_wave_requests: int = Field(default=120, ge=1, le=10_000)
    max_engagement_requests: int = Field(default=1_000, ge=1, le=100_000)
    max_response_bytes: int = Field(default=65_536, ge=1_024, le=1_048_576)
    max_proof_requests: int = Field(default=2, ge=1, le=10)
    nuclei_template_ids: list[str] = Field(default_factory=list, max_length=100)
    allowed_classes: list[ProbeClass] = Field(
        default_factory=lambda: [ProbeClass.PASSIVE, ProbeClass.SAFE_ACTIVE]
    )
    allow_safe_proof: bool = False
    operator_confirmed: bool = False
    tester_account_a: str = ""
    tester_account_b: str = ""
    approval_id: str = ""
    approval_expires_at: str = ""
    approved_playbooks: list[str] = Field(default_factory=list)
    approved_credential_refs: list[str] = Field(default_factory=list)
    approved_proof_target_refs: list[str] = Field(default_factory=list)
    scope_approved: bool = False

    @field_validator("scope_hosts", "exclude_hosts")
    @classmethod
    def validate_scope_rules(cls, values: list[str]) -> list[str]:
        return [normalize_scope_rule(value) for value in values]

    @field_validator("nuclei_template_ids")
    @classmethod
    def validate_template_ids(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_template_id(value) for value in values))

    @model_validator(mode="after")
    def require_scope(self) -> "EngagementPolicy":
        if not self.scope_hosts:
            raise ValueError("scope_hosts must contain at least one exact or wildcard rule")
        return self

    def host_allowed(self, host: str) -> bool:
        lowered = host.rstrip(".").lower()
        if any(_rule_matches_host(item, lowered) for item in self.exclude_hosts):
            return False
        return any(_rule_matches_host(item, lowered) for item in self.scope_hosts)

    def url_allowed(self, url: str) -> bool:
        parsed = _parse_target(url)
        if parsed is None:
            return False
        if any(_rule_matches_url(item, parsed) for item in self.exclude_hosts):
            return False
        return any(_rule_matches_url(item, parsed) for item in self.scope_hosts)

    def class_allowed(self, probe_class: ProbeClass) -> bool:
        return probe_class in self.allowed_classes

    def external_template_scan_allowed(self, url: str) -> bool:
        """Return true only when an opaque scanner cannot escape a path boundary."""
        target = _parse_target(url)
        if target is None or not self.url_allowed(url):
            return False
        host = (target.hostname or "").rstrip(".").lower()
        broad_allow = False
        for rule in self.scope_hosts:
            if not _rule_matches_host(rule, host):
                continue
            if "://" not in rule:
                broad_allow = True
                break
            allowed = urlparse(rule)
            if (
                target.scheme.lower() == allowed.scheme.lower()
                and _effective_port(target) == _effective_port(allowed)
                and normalize_target_path(allowed.path or "/") == "/"
            ):
                broad_allow = True
                break
        if not broad_allow:
            return False
        return not any(
            _rule_matches_host(rule, host)
            and "://" in rule
            and normalize_target_path(urlparse(rule).path or "/") != "/"
            for rule in self.exclude_hosts
        )


def normalize_scope_rule(value: str) -> str:
    rule = str(value).strip()
    if not rule:
        raise ValueError("scope rule cannot be empty")
    if "://" not in rule:
        lowered = rule.rstrip(".").lower()
        if "/" in lowered or ":" in lowered or "@" in lowered:
            raise ValueError(
                "bare scope rules must be a hostname; use an http(s) URL for ports or paths"
            )
        _validate_host_pattern(lowered)
        return lowered

    parsed = urlparse(rule)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("scope URL scheme must be http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("scope URLs cannot contain credentials, query strings, or fragments")
    host = (parsed.hostname or "").rstrip(".").lower()
    _validate_host_pattern(host)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid scope URL port") from exc
    display_host = f"[{host}]" if ":" in host else host
    authority = display_host if port is None else f"{display_host}:{port}"
    raw_path = parsed.path or "/"
    if _has_dot_segment(raw_path):
        raise ValueError("scope URL path cannot contain dot-segment traversal")
    path = normalize_target_path(raw_path).rstrip("/") or "/"
    return f"{parsed.scheme.lower()}://{authority}{path}"


def normalize_template_id(value: str) -> str:
    template_id = str(value).strip()
    if not _TEMPLATE_ID.fullmatch(template_id):
        raise ValueError(f"invalid Nuclei template id: {template_id!r}")
    return template_id


def normalize_target_path(path: str) -> str:
    decoded = _decoded_target_path(path)
    decoded = decoded.replace("\\", "/")
    normalized = posixpath.normpath(f"/{decoded.lstrip('/')}")
    return f"/{normalized.lstrip('/')}" if normalized != "/" else "/"


def _decoded_target_path(path: str) -> str:
    decoded = str(path or "/")
    for _ in range(5):
        expanded = unquote(decoded, errors="strict")
        if expanded == decoded:
            break
        decoded = expanded
    if "\x00" in decoded:
        raise ValueError("URL path cannot contain a null byte")
    return decoded


def _has_dot_segment(path: str) -> bool:
    decoded = _decoded_target_path(path).replace("\\", "/")
    return any(segment in {".", ".."} for segment in decoded.split("/"))


def _validate_host_pattern(host: str) -> None:
    candidate = host[2:] if host.startswith("*.") else host
    if not candidate or "*" in candidate:
        raise ValueError(f"invalid scope hostname: {host}")
    try:
        ipaddress.ip_address(candidate)
        if host.startswith("*."):
            raise ValueError("wildcards cannot be used with IP addresses")
        return
    except ValueError as exc:
        if "wildcards" in str(exc):
            raise
    if candidate == "localhost":
        return
    labels = candidate.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"invalid scope hostname: {host}")


def _parse_target(url: str):
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    try:
        parsed.port
    except ValueError:
        return None
    return parsed


def _rule_matches_host(rule: str, host: str) -> bool:
    rule_host = (
        (urlparse(rule).hostname or "").lower() if "://" in rule else rule.lower()
    )
    if rule_host.startswith("*."):
        suffix = rule_host[2:]
        return host.endswith(f".{suffix}") and host != suffix
    return host == rule_host


def _rule_matches_url(rule: str, target) -> bool:
    host = (target.hostname or "").rstrip(".").lower()
    if not _rule_matches_host(rule, host):
        return False
    if "://" not in rule:
        return True

    allowed = urlparse(rule)
    if target.scheme.lower() != allowed.scheme.lower():
        return False
    if _effective_port(target) != _effective_port(allowed):
        return False
    try:
        allowed_path = normalize_target_path(allowed.path or "/").rstrip("/") or "/"
        target_path = normalize_target_path(target.path or "/").rstrip("/") or "/"
    except (UnicodeDecodeError, ValueError):
        return False
    return target_path == allowed_path or target_path.startswith(f"{allowed_path}/")


def _effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme.lower() == "https":
        return 443
    if parsed.scheme.lower() == "http":
        return 80
    return None
