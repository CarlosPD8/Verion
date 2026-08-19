from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class GitHubConnection:
    """A Verion user's linked GitHub account. No separate id — user_id is
    the natural key (one connection per user for MVP; reconnecting isn't
    an upsert, out of scope for now)."""

    user_id: str
    access_token: str
    github_username: str
    connected_at: datetime
