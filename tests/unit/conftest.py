from datetime import UTC, datetime

import pytest

from verion.modules.identity.domain.user import User


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    async def add(self, user: User) -> None:
        self._users[user.id] = user

    async def get_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if str(u.email) == email), None)

    async def get_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)


class FakePasswordHasher:
    """Non-cryptographic stand-in — proves the use-case flow, not real security."""

    _PREFIX = "hashed:"

    def hash(self, plaintext_password: str) -> str:
        return f"{self._PREFIX}{plaintext_password}"

    def verify(self, plaintext_password: str, hashed_password: str) -> bool:
        return hashed_password == self.hash(plaintext_password)


class FakeClock:
    def __init__(self, fixed_now: datetime) -> None:
        self._fixed_now = fixed_now

    def now(self) -> datetime:
        return self._fixed_now


class FakeIdGenerator:
    def __init__(self) -> None:
        self._counter = 0

    def new_id(self) -> str:
        self._counter += 1
        return f"fake-id-{self._counter}"


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    return InMemoryUserRepository()


@pytest.fixture
def password_hasher() -> FakePasswordHasher:
    return FakePasswordHasher()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(fixed_now=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.fixture
def id_generator() -> FakeIdGenerator:
    return FakeIdGenerator()
