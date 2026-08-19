from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.identity.adapters.outbound.db.models import (
    GitHubConnectionModel,
    UserModel,
)
from verion.modules.identity.domain.github_connection import GitHubConnection
from verion.modules.identity.domain.user import Email, User


def _to_domain(model: UserModel) -> User:
    return User(
        id=model.id,
        email=Email(model.email),
        hashed_password=model.hashed_password,
        created_at=model.created_at,
    )


def _from_domain(user: User) -> UserModel:
    return UserModel(
        id=user.id,
        email=str(user.email),
        hashed_password=user.hashed_password,
        created_at=user.created_at,
    )


class PostgresUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, user: User) -> None:
        self._session.add(_from_domain(user))
        await self._session.flush()

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.execute(select(UserModel).where(UserModel.email == email))
        model = result.scalar_one_or_none()
        return _to_domain(model) if model is not None else None

    async def get_by_id(self, user_id: str) -> User | None:
        model = await self._session.get(UserModel, user_id)
        return _to_domain(model) if model is not None else None


def _github_connection_to_domain(model: GitHubConnectionModel) -> GitHubConnection:
    return GitHubConnection(
        user_id=model.user_id,
        access_token=model.access_token,
        github_username=model.github_username,
        connected_at=model.connected_at,
    )


def _github_connection_from_domain(connection: GitHubConnection) -> GitHubConnectionModel:
    return GitHubConnectionModel(
        user_id=connection.user_id,
        access_token=connection.access_token,
        github_username=connection.github_username,
        connected_at=connection.connected_at,
    )


class PostgresGitHubConnectionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, connection: GitHubConnection) -> None:
        self._session.add(_github_connection_from_domain(connection))
        await self._session.flush()

    async def get_by_user_id(self, user_id: str) -> GitHubConnection | None:
        model = await self._session.get(GitHubConnectionModel, user_id)
        return _github_connection_to_domain(model) if model is not None else None
