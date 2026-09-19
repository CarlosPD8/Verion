from collections.abc import AsyncIterator, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from verion.platform.settings import get_settings


class Base(DeclarativeBase):
    pass


# Both public: the arq worker (platform/worker.py, M3.3) has no FastAPI
# Depends() graph to build a per-job session through, so it opens its own
# session per job directly from this shared factory instead of going
# through get_db_session()'s per-request generator below (FastAPI
# `scope="function"`, declared on di.py's DbSessionDep), and disposes
# `engine` itself on worker shutdown.
engine = create_async_engine(get_settings().database_url)
session_factory = async_sessionmaker(engine, expire_on_commit=False)

_AFTER_COMMIT = "verion.after_commit"


def after_commit(session: AsyncSession, callback: Callable[[], Awaitable[None]]) -> None:
    """Run `callback` once this request's transaction has committed, and not otherwise.

    For work that must not be seen before the rows it is about: a job enqueued inside the
    transaction can be taken by a worker before the commit, and find nothing (ADR-0035
    decision 5). `platform/worker.py`'s normalization handoff solves the same problem by
    enqueueing after its own `commit()`; this is that shape for a request, where the commit
    belongs to `get_db_session` and a use case cannot express "after the commit".

    Callbacks run in registration order. A rollback discards them. One that raises
    propagates, so the request answers 500 over a committed transaction — which is why this
    is only for work whose loss is recoverable or registered (G87).
    """
    session.info.setdefault(_AFTER_COMMIT, []).append(callback)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        for callback in session.info.pop(_AFTER_COMMIT, []):
            await callback()
