from keel.proof.catalog import PLAYBOOK_CROSS_ACCOUNT_READ, draft_playbook
from keel.proof.sanitize import clip


def test_draft_cross_account() -> None:
    draft = draft_playbook(PLAYBOOK_CROSS_ACCOUNT_READ, "card", "https://h/item/1")
    assert len(draft.requests) == 2
    assert draft.requests[0]["method"] == "GET"


def test_clip_redacts_bearer() -> None:
    text = clip("Authorization: Bearer supersecretvalue")
    assert "supersecretvalue" not in text
    assert "[redacted]" in text
