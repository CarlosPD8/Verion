import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

# Importing every model module is what puts its table on `Base.metadata`, and
# two fixtures below depend on that being complete rather than on whichever
# modules some other test happened to import first: `_clean_all_tables` iterates
# it, and `test_schema_matches_models.py` compares it against the database. Run a
# single test file in isolation and the metadata is otherwise nearly empty, so
# both degrade silently to doing almost nothing. The same explicit-import list
# `alembic/env.py` keeps, for the same reason.
from verion.modules.identity.adapters.outbound.db import models as _identity_models  # noqa: F401
from verion.modules.normalization.adapters.outbound.db import (  # noqa: F401
    models as _normalization_models,
)
from verion.modules.projects.adapters.outbound.db import models as _projects_models  # noqa: F401
from verion.modules.scanning.adapters.outbound.db import models as _scanning_models  # noqa: F401
from verion.platform.db import Base
from verion.platform.settings import get_settings

_REPO_ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="session")
def migrated_schema() -> None:
    """Build the test schema with Alembic, not `Base.metadata.create_all`.

    **The schema under test is now the one production runs.** It used to be built
    from the models, which meant a constraint declared on a model and missing
    from its migration passed the entire suite and failed in production. That was
    caught in CI only by an accident of step ordering — `ci.yml` runs
    `alembic upgrade head` before `pytest` against the same service, and
    `create_all` defaults to `checkfirst=True`, so it silently skipped every
    already-migrated table, constraints included. Nothing stated that ordering,
    nothing enforced it, and locally the opposite happened: a fresh database got
    a models-built schema and a green run.

    A side effect worth knowing about: rule 8 had no mechanical check at all
    until this change, and now has a partial one — a model on a second
    `DeclarativeBase` gets no migration, so its table does not exist and its
    tests fail loudly. That covers any model an integration test touches, and no
    other. CLAUDE.md's Tier 1 table records it on the `pytest` row.

    Sync and out-of-process, both deliberately: `alembic/env.py` drives itself
    with `asyncio.run()`, which raises inside a running event loop, and this
    suite's loops are session-scoped. A sync fixture runs before any loop exists,
    and a subprocess is also exactly how migrations are applied for real.

    If this fails with "relation already exists", the database was built by the
    old `create_all` path and has no `alembic_version` row: run
    `uv run alembic stamp head`, or drop and recreate the database.
    """
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
    )


@pytest_asyncio.fixture(scope="session")
async def engine(migrated_schema: None) -> AsyncEngine:
    test_engine = create_async_engine(get_settings().database_url)
    yield test_engine
    await test_engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_all_tables(engine: AsyncEngine):
    yield
    # Generic over every table registered on Base.metadata (not one model
    # import per table) — route tests commit real rows (platform/db.py's
    # get_db_session commits on success), so any table can accumulate
    # cross-test state; reversed(sorted_tables) respects FK dependency order.
    # Deliberately driven by the metadata rather than by reflection, so it never
    # touches alembic_version: truncating that would strand the schema at head
    # with no record of it.
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
