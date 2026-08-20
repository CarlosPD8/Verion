from typing import Any

from verion.modules.scanning.domain.exceptions import InvalidWebhookPayload


def parse_push_event_repo(payload: dict[str, Any]) -> tuple[str, str]:
    """Extracts (owner, repo) from a GitHub push-event payload's `repository`
    object (`repository.owner.login`, `repository.name`) — the same
    owner/repo shape scanning/domain/repo_url.py already validates for a
    clone URL, so the caller can join these into the same
    https://github.com/{owner}/{repo} form ConnectedRepo.url already stores.

    Mirrors projects' _parse_github_owner_repo in spirit, not by import —
    modules don't share domain/application code (same precedent as
    repo_url.py's parse_github_clone_url).
    """
    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise InvalidWebhookPayload("Payload is missing a 'repository' object")

    owner_info = repository.get("owner")
    name = repository.get("name")
    owner = owner_info.get("login") if isinstance(owner_info, dict) else None

    if not isinstance(owner, str) or not owner or not isinstance(name, str) or not name:
        raise InvalidWebhookPayload("Payload's 'repository' object is missing owner/name")

    return owner, name
