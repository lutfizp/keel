from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from keel.engagement.policy import EngagementPolicy
from keel.errors import ProofDenied
from keel.proof.approval import activate_approval, proof_target_for, revalidate_approval
from keel.proof.credentials import resolve_credential
from keel.runtime import Workspace


def _approval(path: Path, scope: list[str] | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "engagements": {
                    "bb-1": {
                        "scope_hosts": scope or ["app.example.com"],
                        "exclude_hosts": [],
                        "playbooks": ["cross_account_read"],
                        "credential_refs": ["tester-a", "tester-b"],
                        "max_requests_per_second": 2,
                        "max_proof_requests": 2,
                        "nuclei_template_ids": ["idor-template"],
                        "proof_targets": {
                            "object-a": {
                                "url": "https://app.example.com/objects/1",
                                "canary_sha256": "87b67301c4bd58bd38536ffb4a1a528e7d88f12930bd64b7f77f791cbf253f28",
                                "owner_credential_ref": "tester-a",
                                "peer_credential_ref": "tester-b",
                                "playbooks": ["cross_account_read"],
                            }
                        },
                        "expires_at": "2999-01-01T00:00:00Z",
                    }
                },
            }
        )
    )
    path.chmod(0o600)


def test_operator_manifest_activates_and_binds_proof(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        requests_per_second=2,
        allow_safe_proof=True,
    )

    active = activate_approval(policy)

    assert active.operator_confirmed is True
    assert active.approved_credential_refs == ["tester-a", "tester-b"]
    assert active.approved_proof_target_refs == ["object-a"]
    assert revalidate_approval(active, "cross_account_read").max_proof_requests == 2


def test_proof_target_binds_url_credentials_and_canary(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    active = activate_approval(
        EngagementPolicy(
            engagement_id="bb-1",
            scope_hosts=["app.example.com"],
            requests_per_second=2,
            allow_safe_proof=True,
        )
    )

    _, target = proof_target_for(
        active,
        "cross_account_read",
        "object-a",
        "https://app.example.com/objects/1",
        "keel-canary-1234",
    )
    assert target.owner_credential_ref == "tester-a"

    with pytest.raises(ProofDenied, match="canary hash"):
        proof_target_for(
            active,
            "cross_account_read",
            "object-a",
            "https://app.example.com/objects/1",
            "different-canary",
        )


def test_same_engagement_can_enable_manifest_approved_proof(
    monkeypatch, tmp_path: Path
) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    workspace = Workspace(tmp_path / "state")
    base = dict(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        requests_per_second=2,
    )

    assert workspace.begin(EngagementPolicy(**base))["proof_approved"] is False
    resumed = workspace.begin(
        EngagementPolicy(**base, allow_safe_proof=True)
    )

    assert resumed["resumed"] is True
    assert resumed["proof_approved"] is True


def test_boolean_cannot_bypass_missing_manifest(monkeypatch) -> None:
    monkeypatch.delenv("KEEL_APPROVAL_FILE", raising=False)
    monkeypatch.delenv("KEEL_PROOF_APPROVAL_FILE", raising=False)
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        allow_safe_proof=True,
        operator_confirmed=True,
    )

    with pytest.raises(ProofDenied, match="operator-owned"):
        activate_approval(policy)


def test_manifest_rejects_unknown_or_duplicate_fields(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    document = json.loads(approval.read_text())
    document["engagements"]["bb-1"]["max_request_per_second"] = 1
    approval.write_text(json.dumps(document))
    approval.chmod(0o600)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        requests_per_second=2,
    )

    with pytest.raises(ProofDenied, match="extra_forbidden"):
        activate_approval(policy)

    approval.write_text('{"version":1,"version":1,"engagements":{}}')
    approval.chmod(0o600)
    with pytest.raises(ProofDenied, match="duplicate JSON key"):
        activate_approval(policy)


def test_workspace_rejects_unapproved_network_policy(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("KEEL_APPROVAL_FILE", raising=False)
    monkeypatch.delenv("KEEL_PROOF_APPROVAL_FILE", raising=False)
    monkeypatch.delenv("KEEL_ALLOW_UNAPPROVED_RECON", raising=False)
    policy = EngagementPolicy(engagement_id="recon", scope_hosts=["app.example.com"])

    with pytest.raises(ProofDenied, match="network traffic"):
        Workspace(tmp_path).begin(policy)


def test_manifest_scope_must_match_exactly(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval, ["*.example.com"])
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        allow_safe_proof=True,
    )

    with pytest.raises(ProofDenied, match="exactly match"):
        activate_approval(policy)


def test_manifest_bounds_response_size(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        requests_per_second=2,
        max_response_bytes=131_072,
    )

    with pytest.raises(ProofDenied, match="response-size"):
        activate_approval(policy)


def test_manifest_bounds_nuclei_template_selection(monkeypatch, tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    _approval(approval)
    monkeypatch.setenv("KEEL_APPROVAL_FILE", str(approval))
    policy = EngagementPolicy(
        engagement_id="bb-1",
        scope_hosts=["app.example.com"],
        requests_per_second=2,
        nuclei_template_ids=["not-approved"],
    )

    with pytest.raises(ProofDenied, match="template selection"):
        activate_approval(policy)


def test_credentials_are_resolved_by_approved_reference(monkeypatch, tmp_path: Path) -> None:
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "tester-a": {"authorization": "Bearer a-secret"},
                "tester-b": {"cookie": "session=b-secret"},
            }
        )
    )
    credentials.chmod(0o600)
    monkeypatch.setenv("KEEL_CREDENTIALS_FILE", str(credentials))

    assert resolve_credential("tester-a", ["tester-a"])["Authorization"] == "Bearer a-secret"
    with pytest.raises(ProofDenied, match="not operator-approved"):
        resolve_credential("tester-b", ["tester-a"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not Windows ACLs")
def test_credentials_file_rejects_open_permissions(monkeypatch, tmp_path: Path) -> None:
    credentials = tmp_path / "credentials.json"
    credentials.write_text('{"tester-a":{"authorization":"Bearer secret"}}')
    credentials.chmod(0o644)
    monkeypatch.setenv("KEEL_CREDENTIALS_FILE", str(credentials))

    with pytest.raises(ProofDenied, match="group or other"):
        resolve_credential("tester-a", ["tester-a"])


def test_credentials_reject_duplicate_keys_and_control_characters(
    monkeypatch, tmp_path: Path
) -> None:
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        '{"tester-a":{"authorization":"Bearer first"},'
        '"tester-a":{"authorization":"Bearer second"}}'
    )
    credentials.chmod(0o600)
    monkeypatch.setenv("KEEL_CREDENTIALS_FILE", str(credentials))

    with pytest.raises(ProofDenied, match="duplicate JSON key"):
        resolve_credential("tester-a", ["tester-a"])

    credentials.write_text(
        json.dumps({"tester-a": {"authorization": "Bearer secret\tvalue"}})
    )
    credentials.chmod(0o600)
    with pytest.raises(ProofDenied, match="invalid credential header"):
        resolve_credential("tester-a", ["tester-a"])


def test_credentials_summary_rejects_empty_entry(monkeypatch, tmp_path: Path) -> None:
    credentials = tmp_path / "credentials.json"
    credentials.write_text('{"tester-a":{}}')
    credentials.chmod(0o600)
    monkeypatch.setenv("KEEL_CREDENTIALS_FILE", str(credentials))

    with pytest.raises(ProofDenied, match="no usable headers"):
        resolve_credential("tester-a", ["tester-a"])
