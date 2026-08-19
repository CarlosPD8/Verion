from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from verion.platform.settings import get_settings


class Base(DeclarativeBase):
    pass


_engine = create_async_engine(get_settings().database_url)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
