import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

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
async def _clean_all_tables(engine: AsyncEngine):
    yield
    # Generic over every table registered on Base.metadata (not one model
    # import per table) — route tests commit real rows (platform/db.py's
    # get_db_session commits on success), so any table can accumulate
    # cross-test state; reversed(sorted_tables) respects FK dependency order.
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
