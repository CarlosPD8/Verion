from datetime import UTC, datetime

from verion.modules.identity.adapters.outbound.db.repository import PostgresUserRepository
from verion.modules.identity.domain.user import Email, User


def _user(email: str = "dev@example.com") -> User:
    return User(
        id="11111111-1111-1111-1111-111111111111",
        email=Email(email),
        hashed_password="argon2-hash-placeholder",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def test_round_trips_a_user_through_postgres(db_session):
    repository = PostgresUserRepository(db_session)
    user = _user()

    await repository.add(user)

    by_email = await repository.get_by_email("dev@example.com")
    by_id = await repository.get_by_id(user.id)

    assert by_email == user
    assert by_id == user


async def test_get_by_email_returns_none_when_missing(db_session):
    repository = PostgresUserRepository(db_session)

    assert await repository.get_by_email("nobody@example.com") is None


async def test_get_by_id_returns_none_when_missing(db_session):
    repository = PostgresUserRepository(db_session)

    assert await repository.get_by_id("does-not-exist") is None
