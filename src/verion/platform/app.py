from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from arq.connections import RedisSettings, create_pool
from fastapi import FastAPI

from verion.modules.identity.adapters.inbound.api.router import router as identity_router
from verion.modules.projects.adapters.inbound.api.router import router as projects_router
from verion.modules.scanning.adapters.inbound.api.router import router as scanning_router
from verion.platform.settings import get_settings


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # This project's first FastAPI lifespan handler. Mirrors
    # platform/worker.py's on_startup/on_shutdown shape (build-once-at-
    # process-start, dispose-once-at-process-end) for the same kind of
    # shared, stateless connection pool — created exactly once here, never
    # lazily on first request, so di.py's get_job_queue only ever reads it
    # (see that function's own comment). A pool-creation failure here fails
    # the process at startup, before it accepts any traffic, rather than
    # surfacing as a late per-request error.
    app.state.arq_redis = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    yield
    await app.state.arq_redis.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=_lifespan)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(identity_router, prefix="/auth", tags=["auth"])
    app.include_router(projects_router, prefix="/projects", tags=["projects"])
    app.include_router(scanning_router, prefix="/scanning", tags=["scanning"])

    return app


app = create_app()
