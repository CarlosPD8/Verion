import pytest_asyncio
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from verion.modules.identity.adapters.outbound.db.models import UserModel
from verion.platform.db import Base
from verion.platform.settings import get_settings


@pytest_asyncio.fixture(scope="session")
async def engine() -> AsyncEngine:
    test_engine = create_async_engine(get_settings().database_url)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield test_engine
    await test_engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_users_table(engine: AsyncEngine):
    yield
    async with engine.begin() as conn:
        await conn.execute(delete(UserModel))


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
