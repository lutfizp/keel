from keel.ingest.httpx_json import cards_from_httpx
from keel.ingest.nuclei_jsonl import cards_from_nuclei


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
