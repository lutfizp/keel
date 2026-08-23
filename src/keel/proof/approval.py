from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from keel.engagement.policy import (
    EngagementPolicy,
    normalize_scope_rule,
    normalize_template_id,
    normalize_target_path,
)
from keel.errors import ProofDenied


class ProofTargetGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    canary_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    owner_credential_ref: str = Field(min_length=1)
    peer_credential_ref: str = ""
    playbooks: list[str]

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return canonical_proof_url(value)


class ApprovalGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_hosts: list[str]
    exclude_hosts: list[str] = Field(default_factory=list)
    playbooks: list[str]
    credential_refs: list[str] = Field(default_factory=list)
    max_requests_per_second: float = Field(default=3.0, gt=0.0, le=20.0)
    max_parallel_hosts: int = Field(default=1, ge=1, le=4)
    max_wave_seconds: int = Field(default=120, ge=10, le=600)
    max_wave_requests: int = Field(default=120, ge=1, le=10_000)
    max_engagement_requests: int = Field(default=1_000, ge=1, le=100_000)
    max_response_bytes: int = Field(default=65_536, ge=1_024, le=1_048_576)
    max_proof_requests: int = Field(default=2, ge=1, le=10)
    nuclei_template_ids: list[str] = Field(default_factory=list, max_length=100)
    proof_targets: dict[str, ProofTargetGrant] = Field(default_factory=dict)
    expires_at: datetime

    @field_validator("scope_hosts", "exclude_hosts")
    @classmethod
    def normalize_scope_rules(cls, values: list[str]) -> list[str]:
        return [normalize_scope_rule(value) for value in values]

    @field_validator("nuclei_template_ids")
    @classmethod
    def normalize_template_ids(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_template_id(value) for value in values))


class ApprovalManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    engagements: dict[str, ApprovalGrant]


def activate_approval(policy: EngagementPolicy) -> EngagementPolicy:
    grant, approval_id = approval_for(policy)
    expires_at = grant.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return policy.model_copy(
        update={
            "operator_confirmed": policy.allow_safe_proof,
            "approval_id": approval_id,
            "approval_expires_at": expires_at.astimezone(timezone.utc).isoformat(),
            "approved_playbooks": list(grant.playbooks),
            "approved_credential_refs": list(grant.credential_refs),
            "approved_proof_target_refs": sorted(grant.proof_targets),
            "max_proof_requests": min(policy.max_proof_requests, grant.max_proof_requests),
            "scope_approved": True,
        }
    )


def approval_for(policy: EngagementPolicy) -> tuple[ApprovalGrant, str]:
    manifest, raw, _ = _load_manifest()
    grant = manifest.engagements.get(policy.engagement_id)
    if grant is None:
        raise ProofDenied(f"engagement {policy.engagement_id} is not operator-approved")
    expires_at = grant.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise ProofDenied("operator approval has expired")
    if set(policy.scope_hosts) != set(grant.scope_hosts):
        raise ProofDenied("engagement scope does not exactly match operator approval")
    if set(policy.exclude_hosts) != set(grant.exclude_hosts):
        raise ProofDenied("engagement exclusions do not exactly match operator approval")
    if policy.requests_per_second > grant.max_requests_per_second:
        raise ProofDenied("engagement rate exceeds operator approval")
    if policy.max_parallel_hosts > grant.max_parallel_hosts:
        raise ProofDenied("parallel-host limit exceeds operator approval")
    if policy.max_wave_seconds > grant.max_wave_seconds:
        raise ProofDenied("wave duration exceeds operator approval")
    if policy.max_wave_requests > grant.max_wave_requests:
        raise ProofDenied("wave request budget exceeds operator approval")
    if policy.max_engagement_requests > grant.max_engagement_requests:
        raise ProofDenied("engagement request budget exceeds operator approval")
    if policy.max_response_bytes > grant.max_response_bytes:
        raise ProofDenied("response-size limit exceeds operator approval")
    if not set(policy.nuclei_template_ids).issubset(set(grant.nuclei_template_ids)):
        raise ProofDenied("Nuclei template selection exceeds operator approval")
    for reference, target in grant.proof_targets.items():
        if not reference.strip():
            raise ProofDenied("proof target references cannot be empty")
        if not policy.url_allowed(target.url):
            raise ProofDenied(f"proof target {reference!r} is outside approved scope")
        target_refs = {target.owner_credential_ref}
        if target.peer_credential_ref:
            target_refs.add(target.peer_credential_ref)
        if not target_refs.issubset(set(grant.credential_refs)):
            raise ProofDenied(
                f"proof target {reference!r} uses a credential outside credential_refs"
            )
        if not set(target.playbooks).issubset(set(grant.playbooks)):
            raise ProofDenied(
                f"proof target {reference!r} uses a playbook outside the engagement grant"
            )
    return grant, hashlib.sha256(raw).hexdigest()[:16]


def approval_manifest_summary() -> dict | None:
    configured = (
        os.environ.get("KEEL_APPROVAL_FILE", "").strip()
        or os.environ.get("KEEL_PROOF_APPROVAL_FILE", "").strip()
    )
    if not configured:
        return None
    manifest, _, path = _load_manifest()
    return {"path": str(path), "engagements": sorted(manifest.engagements)}


def _load_manifest() -> tuple[ApprovalManifest, bytes, Path]:
    configured = (
        os.environ.get("KEEL_APPROVAL_FILE", "").strip()
        or os.environ.get("KEEL_PROOF_APPROVAL_FILE", "").strip()
    )
    if not configured:
        raise ProofDenied("network traffic requires an operator-owned KEEL_APPROVAL_FILE")
    configured_path = Path(configured).expanduser()
    if configured_path.is_symlink():
        raise ProofDenied("operator approval file must not be a symlink")
    path = configured_path.resolve()
    if not path.is_file():
        raise ProofDenied("operator approval file must be a regular file")
    if os.name != "nt" and path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProofDenied("operator approval file must not be group/world writable")
    try:
        raw = path.read_bytes()
        if len(raw) > 1_048_576:
            raise ValueError("approval manifest exceeds 1 MiB")
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        manifest = ApprovalManifest.model_validate(document)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProofDenied(f"cannot load operator approval manifest: {exc}") from exc
    return manifest, raw, path


def revalidate_approval(policy: EngagementPolicy, playbook_id: str) -> ApprovalGrant:
    grant, approval_id = approval_for(policy)
    if approval_id != policy.approval_id:
        raise ProofDenied("operator approval manifest changed; resume the engagement")
    if playbook_id not in grant.playbooks:
        raise ProofDenied(f"playbook {playbook_id} is not operator-approved")
    return grant


def proof_target_for(
    policy: EngagementPolicy,
    playbook_id: str,
    proof_target_ref: str,
    card_url: str,
    expected_marker: str,
    requested_owner_ref: str = "",
    requested_peer_ref: str = "",
) -> tuple[ApprovalGrant, ProofTargetGrant]:
    grant = revalidate_approval(policy, playbook_id)
    if not proof_target_ref:
        raise ProofDenied("an operator-approved proof_target_ref is required")
    target = grant.proof_targets.get(proof_target_ref)
    if target is None:
        raise ProofDenied(f"proof target {proof_target_ref!r} is not operator-approved")
    if playbook_id not in target.playbooks:
        raise ProofDenied(
            f"playbook {playbook_id} is not approved for proof target {proof_target_ref!r}"
        )
    try:
        normalized_card_url = canonical_proof_url(card_url)
    except ValueError as exc:
        raise ProofDenied(f"card has no valid proof URL: {exc}") from exc
    if normalized_card_url != target.url:
        raise ProofDenied("card URL does not exactly match the operator-approved proof target")
    if requested_owner_ref and requested_owner_ref != target.owner_credential_ref:
        raise ProofDenied("session_a does not match the proof target owner credential")
    if requested_peer_ref and requested_peer_ref != target.peer_credential_ref:
        raise ProofDenied("session_b does not match the proof target peer credential")
    if playbook_id == "cross_account_read" and not target.peer_credential_ref:
        raise ProofDenied("cross_account_read requires an approved peer credential")
    digest = hashlib.sha256(expected_marker.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, target.canary_sha256.lower()):
        raise ProofDenied("expected_marker does not match the operator-approved canary hash")
    return grant, target


def canonical_proof_url(value: str) -> str:
    parsed = urlsplit(str(value).strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("proof target URL must be an absolute http(s) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("proof target URL cannot contain credentials or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid proof target URL port") from exc
    host = parsed.hostname.rstrip(".").lower()
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = display_host if port in {None, default_port} else f"{display_host}:{port}"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            authority,
            normalize_target_path(parsed.path or "/"),
            parsed.query,
            "",
        )
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def revalidate_scope_approval(policy: EngagementPolicy) -> ApprovalGrant | None:
    if not policy.scope_approved:
        if os.environ.get("KEEL_ALLOW_UNAPPROVED_RECON") == "1":
            return None
        raise ProofDenied("engagement scope has no active operator approval")
    grant, approval_id = approval_for(policy)
    if approval_id != policy.approval_id:
        raise ProofDenied("operator approval manifest changed; resume the engagement first")
    return grant
