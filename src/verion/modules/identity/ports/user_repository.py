from typing import Protocol

from verion.modules.identity.domain.user import User


class UserRepositoryPort(Protocol):
    def add(self, user: User) -> None: ...

    def get_by_email(self, email: str) -> User | None: ...

    def get_by_id(self, user_id: str) -> User | None: ...
