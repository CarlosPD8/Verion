from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.identity.adapters.outbound.db.models import UserModel
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
