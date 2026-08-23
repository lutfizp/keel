from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProbeClass(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    INTRUSIVE = "intrusive"


class ImpactClass(str, Enum):
    NONE = "none"
    HARDENING = "hardening"
    SENSITIVE_ACCESS = "sensitive_access"
    ACCOUNT_TAKEOVER = "account_takeover"
    RCE = "rce"
    DATA_OTHER_USERS = "data_other_users"


class CardStatus(str, Enum):
    NOISE = "noise"
    HYPOTHESIS = "hypothesis"
    SAFE_PROOF_PENDING = "safe_proof_pending"
    PROVEN = "proven"
    WONT_FIX_IMPACT = "wont_fix_impact"


class ValidationState(str, Enum):
    OBSERVED = "observed"
    HYPOTHESIS = "hypothesis"
    CORROBORATED = "corroborated"
    PROVEN = "proven"
    REFUTED = "refuted"


class EvidenceStrength(str, Enum):
    UNVERIFIED = "unverified"
    SINGLE_SOURCE = "single_source"
    MULTI_SOURCE = "multi_source"
    SAFE_PROOF = "safe_proof"


class WaveKind(str, Enum):
    PROBE_ALIVE = "probe_alive"
    TEMPLATE_SCAN = "template_scan"


class FindingCard(BaseModel):
    card_id: str
    fingerprint: str
    host: str
    path: str
    matcher: str
    title: str
    scanner_severity: str
    confidence: float = 0.4
    impact_class: ImpactClass = ImpactClass.NONE
    preconditions: str = ""
    in_program: bool = True
    status: CardStatus = CardStatus.NOISE
    evidence: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    semantic_key: str = ""
    vulnerability_class: str = "unclassified"
    parameter: str = ""
    method: str = "GET"
    validation_state: ValidationState = ValidationState.OBSERVED
    evidence_strength: EvidenceStrength = EvidenceStrength.UNVERIFIED
    corroboration_count: int = 1
    priority_score: float = 0.0


class WaveSpec(BaseModel):
    wave_id: str
    kind: WaveKind
    probe_class: ProbeClass
    target: str
    extra: dict[str, Any] = Field(default_factory=dict)


class ProofDraft(BaseModel):
    playbook_id: str
    card_id: str
    steps: list[str]
    requests: list[dict[str, Any]]
    harm_rationale: str
    request_budget: int = 0
    required_inputs: list[str] = Field(default_factory=list)
