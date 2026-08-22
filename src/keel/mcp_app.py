from __future__ import annotations

from pathlib import Path

from mcp.server import MCPServer

from keel.engagement.policy import EngagementPolicy
from keel.errors import KeelError
from keel.models import ProbeClass
from keel.runtime import Workspace

_DATA = Path(__file__).resolve().parent.parent.parent / ".data" / "engagements"
mcp = MCPServer("keel")
workspace = Workspace(_DATA)


def _ok(payload: object) -> dict:
    return {"ok": True, "data": payload}


def _err(exc: Exception) -> dict:
    return {"ok": False, "error": type(exc).__name__, "message": str(exc)}


@mcp.tool()
def begin_engagement(
    engagement_id: str,
    scope_hosts: list[str],
    exclude_hosts: list[str] | None = None,
    requests_per_second: float = 3.0,
    allow_safe_proof: bool = False,
    operator_confirmed: bool = False,
    tester_account_a: str = "",
    tester_account_b: str = "",
) -> dict:
    """Register scope, rate limits, and proof flags for one engagement."""
    try:
        policy = EngagementPolicy(
            engagement_id=engagement_id,
            scope_hosts=scope_hosts,
            exclude_hosts=exclude_hosts or [],
            requests_per_second=requests_per_second,
            allowed_classes=[ProbeClass.PASSIVE, ProbeClass.SAFE_ACTIVE],
            allow_safe_proof=allow_safe_proof,
            operator_confirmed=operator_confirmed,
            tester_account_a=tester_account_a,
            tester_account_b=tester_account_b,
        )
        return _ok(workspace.begin(policy))
    except (KeelError, ValueError) as exc:
        return _err(exc)


@mcp.tool()
def draft_waves(engagement_id: str, seed_url: str) -> dict:
    """Propose probe_alive then template_scan waves without executing them."""
    try:
        return _ok(workspace.draft_waves(engagement_id, seed_url))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def execute_wave(engagement_id: str, wave_id: str) -> dict:
    """Run one admitted wave behind the per-host token bucket."""
    try:
        return _ok(workspace.execute_wave(engagement_id, wave_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def query_cards(engagement_id: str, include_noise: bool = False) -> dict:
    """Return hunter-relevant cards. Informational and hardening are hidden by default."""
    try:
        return _ok(workspace.query_cards(engagement_id, include_noise))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def second_look(engagement_id: str, card_id: str) -> dict:
    """Re-run a bounded template scan on a single card URL."""
    try:
        return _ok(workspace.second_look(engagement_id, card_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def state_impact(
    engagement_id: str,
    card_id: str,
    impact: str,
    preconditions: str,
    hunter_why: str,
) -> dict:
    """Record hunter impact_class and preconditions on a card."""
    try:
        return _ok(
            workspace.state_impact(engagement_id, card_id, impact, preconditions, hunter_why)
        )
    except (KeelError, ValueError) as exc:
        return _err(exc)


@mcp.tool()
def draft_proof(engagement_id: str, card_id: str, playbook_id: str) -> dict:
    """Describe an allowlisted proof without sending traffic."""
    try:
        return _ok(workspace.draft_proof(engagement_id, card_id, playbook_id))
    except (KeelError, KeyError) as exc:
        return _err(exc)


@mcp.tool()
def execute_proof(
    engagement_id: str,
    card_id: str,
    playbook_id: str,
    session_a: str,
    session_b: str = "",
) -> dict:
    """Run an allowlisted proof. Requires allow_safe_proof and operator_confirmed."""
    try:
        return _ok(
            workspace.execute_proof(engagement_id, card_id, playbook_id, session_a, session_b)
        )
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def engagement_health(engagement_id: str | None = None) -> dict:
    """Report registered engagements, cooldowns, and pending waves."""
    try:
        return _ok(workspace.health(engagement_id))
    except KeelError as exc:
        return _err(exc)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
