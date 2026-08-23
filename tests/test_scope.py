import pytest

from keel.engagement.policy import EngagementPolicy


def test_exact_host_does_not_implicitly_include_subdomains() -> None:
    policy = EngagementPolicy(engagement_id="exact", scope_hosts=["example.com"])

    assert policy.url_allowed("https://example.com/path")
    assert not policy.url_allowed("https://app.example.com/path")


def test_wildcard_host_excludes_apex() -> None:
    policy = EngagementPolicy(engagement_id="wild", scope_hosts=["*.example.com"])

    assert policy.url_allowed("https://api.example.com/")
    assert not policy.url_allowed("https://example.com/")
    assert not policy.url_allowed("https://evil-example.com/")


def test_url_scope_binds_scheme_port_and_path_prefix() -> None:
    policy = EngagementPolicy(
        engagement_id="url-rule",
        scope_hosts=["https://app.example.com:8443/api"],
    )

    assert policy.url_allowed("https://app.example.com:8443/api")
    assert policy.url_allowed("https://app.example.com:8443/api/v1/items")
    assert not policy.url_allowed("http://app.example.com:8443/api")
    assert not policy.url_allowed("https://app.example.com/api")
    assert not policy.url_allowed("https://app.example.com:8443/apix")
    assert not policy.url_allowed("https://app.example.com:8443/api/../admin")
    assert not policy.url_allowed("https://app.example.com:8443/api/%2e%2e/admin")
    assert not policy.url_allowed(
        "https://app.example.com:8443/api/%252e%252e%252fadmin"
    )


def test_target_url_rejects_userinfo_and_fragments() -> None:
    policy = EngagementPolicy(engagement_id="userinfo", scope_hosts=["example.com"])

    assert not policy.url_allowed("https://user:secret@example.com/path")
    assert not policy.url_allowed("https://example.com/path#fragment")


def test_scope_rule_rejects_dot_segment_traversal() -> None:
    with pytest.raises(ValueError, match="dot-segment"):
        EngagementPolicy(
            engagement_id="bad-path",
            scope_hosts=["https://app.example.com/api/%2e%2e/admin"],
        )


def test_exclusion_wins_over_allow_rule() -> None:
    policy = EngagementPolicy(
        engagement_id="exclude",
        scope_hosts=["*.example.com"],
        exclude_hosts=["admin.example.com"],
    )

    assert policy.url_allowed("https://api.example.com/")
    assert not policy.url_allowed("https://admin.example.com/")


def test_opaque_template_scan_requires_host_wide_path_permission() -> None:
    path_only = EngagementPolicy(
        engagement_id="path-only",
        scope_hosts=["https://app.example.com/api"],
    )
    excluded_path = EngagementPolicy(
        engagement_id="excluded-path",
        scope_hosts=["app.example.com"],
        exclude_hosts=["https://app.example.com/admin"],
    )
    host_wide = EngagementPolicy(
        engagement_id="host-wide",
        scope_hosts=["https://app.example.com/"],
    )

    assert not path_only.external_template_scan_allowed(
        "https://app.example.com/api"
    )
    assert not excluded_path.external_template_scan_allowed(
        "https://app.example.com/"
    )
    assert host_wide.external_template_scan_allowed("https://app.example.com/")


def test_engagement_id_cannot_escape_data_directory() -> None:
    with pytest.raises(ValueError):
        EngagementPolicy(engagement_id="../escape", scope_hosts=["example.com"])
