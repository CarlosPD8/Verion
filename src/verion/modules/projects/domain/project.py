import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlparse

from verion.modules.projects.domain.exceptions import InvalidConnectedRepoUrl


class Role(StrEnum):
    OWNER = "owner"
    MEMBER = "member"


@dataclass(frozen=True)
class Project:
    id: str
    owner_id: str
    name: str
    created_at: datetime


@dataclass(frozen=True)
class ConnectedRepo:
    id: str
    project_id: str
    provider: str
    url: str
    default_branch: str


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_AUTHORITY_END = re.compile(r"[/\\?#]")


def url_carries_userinfo(url: str) -> bool:
    """Whether `url` carries `user[:pass]@` ahead of its host, however the authority is written.

    `urlparse` reports userinfo only inside a `//` authority. `https:user:pass@host/path`,
    `https:/user:pass@host/path`, a backslash form and a scheme-less `user:pass@host/path` all
    leave `netloc` empty and `username` None, while other URL parsers read the text before the
    `@` as credentials. So the text between the scheme and the first `/`, backslash, `?` or `#`
    is checked for `@` as well, which also catches an scp-style `git@host:path`. An `@` after
    the host (`?ref=a@b`) is not userinfo. Shared by this module's repository URL validators,
    so the refusal has one definition.
    """
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        return True
    remainder = _SCHEME.sub("", url, count=1).lstrip("/\\")
    return "@" in _AUTHORITY_END.split(remainder, maxsplit=1)[0]


def validate_connected_repo_url(url: str) -> None:
    """Refuses `user:pass@host` in a connected repository URL. Rule 12, nothing else.

    The write-path counterpart of `validate_zap_target_url`'s first branch and of
    `validate_declared_repo_url`. Until 2026-09-15 this was the one URL in the module stored
    with no userinfo check, so a credential written here came back in the connect response,
    in the detect route's error detail and in the message of scanning's `UnsupportedRepoUrl`.

    **Only the userinfo branch.** The shape a context build or a scan needs is checked where it
    is needed (`_parse_github_owner_repo`, `parse_github_clone_url`). Refusing other shapes
    here would change which repositories can be connected, which is not this function's
    question. The message does not quote the URL back, or it would carry the credential.
    """
    if url_carries_userinfo(url):
        raise InvalidConnectedRepoUrl(
            "Repository URL must not contain userinfo (user:pass@host) — "
            "credentials must not be stored in a repository URL"
        )


@dataclass(frozen=True)
class ProjectMembership:
    project_id: str
    user_id: str
    role: Role
