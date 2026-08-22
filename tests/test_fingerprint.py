from keel.catalog.fingerprint import fingerprint, load_json_lines, split_url


def test_fingerprint_is_stable() -> None:
    first = fingerprint("nuclei", "a.example", "/x/", "tmpl")
    second = fingerprint("nuclei", "A.example", "/x", "tmpl")
    assert first == second


def test_split_url() -> None:
    host, path = split_url("https://app.example.com/api/v1")
    assert host == "app.example.com"
    assert path == "/api/v1"


def test_load_json_lines_skips_junk() -> None:
    rows = load_json_lines("not-json\n{\"a\": 1}\n")
    assert rows == [{"a": 1}]
