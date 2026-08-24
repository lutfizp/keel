import sys
from importlib.metadata import PackageNotFoundError, version

try:
    from mcp.server import MCPServer

    _MCP_SDK_V2 = True
except ImportError:  # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

    _MCP_SDK_V2 = False

from keel.adapters.process import (
    resolve_projectdiscovery,
    validate_projectdiscovery_capabilities,
)
from keel.engagement.policy import EngagementPolicy
from keel.errors import KeelError
from keel.models import ProbeClass
from keel.paths import data_dir
from keel.proof.approval import approval_manifest_summary
from keel.proof.credentials import credentials_file_summary
from keel.runtime import Workspace

_DATA = data_dir()


def _package_version() -> str:
    try:
        return version("keel-pentest")
    except PackageNotFoundError:
        return "unknown"


if _MCP_SDK_V2:
    mcp = MCPServer("keel", version=_package_version())
else:
    mcp = MCPServer("keel")
    mcp._mcp_server.version = _package_version()
_workspace: Workspace | None = None


def _get_workspace() -> Workspace:
    global _workspace
    if _workspace is None:
        _workspace = Workspace(_DATA)
    return _workspace


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
    max_parallel_hosts: int = 1,
    max_wave_seconds: int = 120,
    max_wave_requests: int = 120,
    max_wave_attempts: int = 2,
    max_engagement_requests: int = 1000,
    max_response_bytes: int = 65536,
    max_proof_requests: int = 2,
    nuclei_template_ids: list[str] | None = None,
    allow_safe_proof: bool = False,
    operator_confirmed: bool = False,
    tester_account_a: str = "",
    tester_account_b: str = "",
) -> dict:
    """Register exact/wildcard scope and bounded traffic policy.

    Default mode is self-attested: calling begin_engagement is the authorization.
    Set KEEL_APPROVAL_FILE for optional strict/team manifests. The legacy
    operator_confirmed argument is ignored and cannot grant approval.
    """
    try:
        policy = EngagementPolicy(
            engagement_id=engagement_id,
            scope_hosts=scope_hosts,
            exclude_hosts=exclude_hosts or [],
            requests_per_second=requests_per_second,
            max_parallel_hosts=max_parallel_hosts,
            max_wave_seconds=max_wave_seconds,
            max_wave_requests=max_wave_requests,
            max_wave_attempts=max_wave_attempts,
            max_engagement_requests=max_engagement_requests,
            max_response_bytes=max_response_bytes,
            max_proof_requests=max_proof_requests,
            nuclei_template_ids=nuclei_template_ids or [],
            allowed_classes=[ProbeClass.PASSIVE, ProbeClass.SAFE_ACTIVE],
            allow_safe_proof=allow_safe_proof,
            operator_confirmed=False,
            tester_account_a=tester_account_a,
            tester_account_b=tester_account_b,
        )
        return _ok(_get_workspace().begin(policy))
    except (KeelError, ValueError) as exc:
        return _err(exc)


@mcp.tool()
def draft_waves(engagement_id: str, seed_url: str) -> dict:
    """Draft reachability plus one micro-wave per reviewed template; no traffic."""
    try:
        return _ok(_get_workspace().draft_waves(engagement_id, seed_url))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def execute_wave(engagement_id: str, wave_id: str) -> dict:
    """Start one admitted wave in the background and return its persistent job."""
    try:
        return _ok(_get_workspace().start_wave(engagement_id, wave_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def wave_status(engagement_id: str, job_id: str = "") -> dict:
    """Return one job, or list persistent jobs/waves when job_id is omitted."""
    try:
        return _ok(_get_workspace().wave_status(engagement_id, job_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def cancel_wave(engagement_id: str, job_id: str) -> dict:
    """Request cancellation of a queued or running scanner process."""
    try:
        return _ok(_get_workspace().cancel_wave(engagement_id, job_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def query_cards(engagement_id: str, include_noise: bool = False) -> dict:
    """Return hunter-relevant cards. Informational and hardening are hidden by default."""
    try:
        return _ok(_get_workspace().query_cards(engagement_id, include_noise))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def second_look(engagement_id: str, card_id: str) -> dict:
    """Start a background micro-wave using only the originating template."""
    try:
        return _ok(_get_workspace().second_look(engagement_id, card_id, background=True))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def assess_exploitability(engagement_id: str, card_id: str) -> dict:
    """Explain candidate impact, missing evidence, controls, and safe proof options."""
    try:
        return _ok(_get_workspace().assess_exploitability(engagement_id, card_id))
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
            _get_workspace().state_impact(
                engagement_id, card_id, impact, preconditions, hunter_why
            )
        )
    except (KeelError, ValueError) as exc:
        return _err(exc)


@mcp.tool()
def draft_proof(engagement_id: str, card_id: str, playbook_id: str) -> dict:
    """Describe an allowlisted proof without sending traffic."""
    try:
        return _ok(_get_workspace().draft_proof(engagement_id, card_id, playbook_id))
    except (KeelError, KeyError) as exc:
        return _err(exc)


@mcp.tool()
def execute_proof(
    engagement_id: str,
    card_id: str,
    playbook_id: str,
    session_a: str = "",
    session_b: str = "",
    expected_marker: str = "",
    proof_target_ref: str = "",
) -> dict:
    """Run a proof bound to an operator-approved target, credentials, and canary hash."""
    try:
        return _ok(
            _get_workspace().execute_proof(
                engagement_id,
                card_id,
                playbook_id,
                session_a,
                session_b,
                expected_marker,
                proof_target_ref,
            )
        )
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def engagement_health(engagement_id: str | None = None) -> dict:
    """Report registered engagements, cooldowns, and pending waves."""
    try:
        return _ok(_get_workspace().health(engagement_id))
    except KeelError as exc:
        return _err(exc)


@mcp.tool()
def engagement_audit(engagement_id: str, limit: int = 50) -> dict:
    """Return recent append-only application audit events for one engagement."""
    try:
        return _ok(_get_workspace().audit(engagement_id, limit))
    except KeelError as exc:
        return _err(exc)


def _doctor() -> int:
    failures = 0
    print(f"[ok] keel-pentest {_package_version()}")
    print(f"[ok] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    print(f"[ok] MCP SDK {'2.x' if _MCP_SDK_V2 else '1.x'} API")
    try:
        _get_workspace()
    except OSError as exc:
        failures += 1
        print(f"[missing] data directory is not writable: {_DATA} ({exc})")
    else:
        print(f"[ok] data directory: {_DATA}")
    for binary in ("httpx", "nuclei"):
        try:
            resolved = resolve_projectdiscovery(binary)
            validate_projectdiscovery_capabilities(binary, resolved)
        except KeelError as exc:
            failures += 1
            print(f"[missing] {exc}")
        else:
            print(f"[ok] ProjectDiscovery {binary}: {resolved}")
    if failures:
        print("[hint] run `keel-pentest setup` to auto-install httpx and nuclei")
    for label, check in (
        ("operator approval", approval_manifest_summary),
        ("credential references", credentials_file_summary),
    ):
        try:
            summary = check()
        except KeelError as exc:
            failures += 1
            print(f"[missing] invalid {label}: {exc}")
        else:
            if summary is None:
                print(f"[notice] {label} not configured")
            else:
                print(f"[ok] {label}: {summary['path']}")
    return 1 if failures else 0


def _setup() -> int:
    from keel.provision import ProvisionError, provision_scanners

    print("[setup] downloading ProjectDiscovery httpx and nuclei into the managed bin dir")
    try:
        installed = provision_scanners()
    except ProvisionError as exc:
        print(f"[error] {exc}")
        return 1
    for path in installed:
        print(f"[ok] installed {path}")
    print("[setup] done; run `keel-pentest doctor` to verify")
    return 0


def main() -> None:
    if sys.argv[1:] == ["--version"]:
        print(f"keel-pentest {_package_version()}")
        return
    if sys.argv[1:] in (["setup"], ["--setup"]):
        raise SystemExit(_setup())
    if sys.argv[1:] in (["doctor"], ["--doctor"]):
        raise SystemExit(_doctor())
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
