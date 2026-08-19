from typing import Protocol

from verion.modules.identity.domain.user import User


class UserRepositoryPort(Protocol):
    async def add(self, user: User) -> None: ...

    async def get_by_email(self, email: str) -> User | None: ...

    async def get_by_id(self, user_id: str) -> User | None: ...
