from keel.catalog.fingerprint import (
    canonical_vulnerability_class,
    fingerprint,
    invalid_json_line_count,
    load_json_lines,
    normalize_route,
    split_url,
)


def test_fingerprint_is_stable() -> None:
    first = fingerprint("nuclei", "a.example", "/x/", "tmpl")
    second = fingerprint("nuclei", "A.example", "/x", "tmpl")
    assert first == second


def test_split_url() -> None:
    host, path = split_url("https://app.example.com/api/v1")
    assert host == "app.example.com"
    assert path == "/api/v1"


def test_load_json_lines_skips_junk() -> None:
    rows = load_json_lines("not-json\n{\"a\": 1}\n[1, 2]\n")
    assert rows == [{"a": 1}]


def test_invalid_json_line_count_rejects_malformed_and_non_objects() -> None:
    assert invalid_json_line_count('not-json\n{"a": 1}\n[1, 2]\n42\n\n') == 3


def test_dynamic_object_ids_share_semantic_route() -> None:
    assert normalize_route("/api/users/1234/orders/550e8400-e29b-41d4-a716-446655440000") == (
        "/api/users/{id}/orders/{uuid}"
    )


def test_cwe_normalizes_tool_specific_names() -> None:
    assert canonical_vulnerability_class(
        "vendor-template", "object issue", ["CWE-639"], ["api"]
    ) == "broken_object_authorization"
