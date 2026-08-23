from keel.ingest.httpx_json import cards_from_httpx, invalid_httpx_record_count
from keel.ingest.nuclei_jsonl import cards_from_nuclei, invalid_nuclei_record_count


def test_httpx_parser() -> None:
    stdout = '{"url":"https://a.example/login","status_code":200}\n'
    cards = cards_from_httpx(stdout)
    assert len(cards) == 1
    assert cards[0].host == "a.example"
    assert cards[0].sources == ["httpx"]


def test_nuclei_parser() -> None:
    stdout = (
        '{"template-id":"missing-csp","matched-at":"https://a.example/",'
        '"info":{"name":"Missing CSP header","severity":"info"}}\n'
    )
    cards = cards_from_nuclei(stdout)
    assert cards[0].matcher == "missing-csp"
    assert cards[0].scanner_severity == "info"


def test_scanner_record_validators_reject_diagnostic_objects() -> None:
    assert invalid_httpx_record_count('{"error":"probe failed"}\n') == 1
    assert invalid_nuclei_record_count('{"error":"template load failed"}\n') == 1


def test_scanner_record_validators_accept_minimum_identity() -> None:
    assert invalid_httpx_record_count('{"url":"https://a.example/"}\n') == 0
    assert (
        invalid_nuclei_record_count(
            '{"template-id":"x","matched-at":"https://a.example/"}\n'
        )
        == 0
    )
