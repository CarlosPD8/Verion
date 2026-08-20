from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from verion.platform.settings import get_settings


class Base(DeclarativeBase):
    pass


# Both public: the arq worker (platform/worker.py, M3.3) has no FastAPI
# Depends() graph to build a per-job session through, so it opens its own
# session per job directly from this shared factory instead of going
# through get_db_session()'s request-scoped generator below, and disposes
# `engine` itself on worker shutdown.
engine = create_async_engine(get_settings().database_url)
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
