from __future__ import annotations

from uuid import uuid4

import httpx

from keel.engagement.policy import EngagementPolicy
from keel.errors import ProofDenied
from keel.models import CardStatus, FindingCard
from keel.proof.catalog import PLAYBOOK_CROSS_ACCOUNT_READ, PLAYBOOK_OWN_SESSION_MARKER
from keel.proof.sanitize import clip


def run_playbook(
    policy: EngagementPolicy,
    card: FindingCard,
    playbook_id: str,
    session_a: str,
    session_b: str,
    marker: str | None = None,
) -> dict:
    if not policy.allow_safe_proof or not policy.operator_confirmed:
        raise ProofDenied("safe proof is not enabled for this engagement")
    url = str(card.evidence.get("url") or card.evidence.get("matched") or "")
    if not url:
        raise ProofDenied("card has no URL")
    token = marker or str(uuid4())
    headers_a = _auth_header(session_a)
    headers_b = _auth_header(session_b)
    with httpx.Client(timeout=20.0, follow_redirects=False) as client:
        if playbook_id == PLAYBOOK_CROSS_ACCOUNT_READ:
            first = client.get(url, headers=headers_a)
            second = client.get(url, headers=headers_b)
            return {
                "playbook_id": playbook_id,
                "marker": token,
                "status_a": first.status_code,
                "status_b": second.status_code,
                "body_a": clip(first.text),
                "body_b": clip(second.text),
                "same_status": first.status_code == second.status_code,
            }
        if playbook_id == PLAYBOOK_OWN_SESSION_MARKER:
            echoed = client.get(url, headers=headers_a, params={"keel_marker": token})
            return {
                "playbook_id": playbook_id,
                "marker": token,
                "status": echoed.status_code,
                "marker_seen": token in echoed.text,
                "body": clip(echoed.text),
            }
    raise ProofDenied(f"unknown playbook {playbook_id}")


def mark_proven(card: FindingCard) -> FindingCard:
    card.status = CardStatus.PROVEN
    return card


def _auth_header(value: str) -> dict[str, str]:
    if not value:
        return {}
    if value.lower().startswith("cookie:"):
        return {"Cookie": value.split(":", 1)[1].strip()}
    return {"Authorization": value}
