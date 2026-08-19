from datetime import UTC, datetime

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.identity.domain.github_connection import GitHubConnection


def _connection(user_id: str = "user-1") -> GitHubConnection:
    return GitHubConnection(
        user_id=user_id,
        access_token="gho_faketoken",
        github_username="octocat",
        connected_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def test_round_trips_a_github_connection_through_postgres(db_session):
    repository = PostgresGitHubConnectionRepository(db_session)
    connection = _connection()

    await repository.add(connection)

    assert await repository.get_by_user_id("user-1") == connection


async def test_get_by_user_id_returns_none_when_missing(db_session):
    repository = PostgresGitHubConnectionRepository(db_session)

    assert await repository.get_by_user_id("does-not-exist") is None
