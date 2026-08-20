import pytest

from verion.modules.scanning.domain.exceptions import InvalidWebhookPayload
from verion.modules.scanning.domain.webhook_payload import parse_push_event_repo


def _payload(owner: str = "octocat", name: str = "Hello-World") -> dict:
    return {"ref": "refs/heads/main", "repository": {"name": name, "owner": {"login": owner}}}


def test_extracts_owner_and_repo_from_a_well_formed_push_payload():
    assert parse_push_event_repo(_payload()) == ("octocat", "Hello-World")


def test_raises_when_repository_key_is_missing():
    with pytest.raises(InvalidWebhookPayload):
        parse_push_event_repo({"ref": "refs/heads/main"})


def test_raises_when_repository_is_not_an_object():
    with pytest.raises(InvalidWebhookPayload):
        parse_push_event_repo({"repository": "not-an-object"})


def test_raises_when_owner_login_is_missing():
    with pytest.raises(InvalidWebhookPayload):
        parse_push_event_repo({"repository": {"name": "Hello-World", "owner": {}}})


def test_raises_when_repo_name_is_missing():
    with pytest.raises(InvalidWebhookPayload):
        parse_push_event_repo({"repository": {"owner": {"login": "octocat"}}})
