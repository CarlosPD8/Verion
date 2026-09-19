from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from arq.connections import RedisSettings, create_pool
from fastapi import FastAPI

from verion.modules.brief.adapters.inbound.api.router import router as briefs_router
from verion.modules.correlation.adapters.inbound.api.router import router as risks_router
from verion.modules.history.adapters.inbound.api.router import router as risk_dismissals_router
from verion.modules.identity.adapters.inbound.api.router import router as identity_router
from verion.modules.normalization.adapters.inbound.api.router import router as findings_router
from verion.modules.projects.adapters.inbound.api.router import router as projects_router
from verion.modules.risk_engine.adapters.inbound.api.router import router as scored_risks_router
from verion.modules.scanning.adapters.inbound.api.router import (
    project_scans_router,
)
from verion.modules.scanning.adapters.inbound.api.router import router as scanning_router
from verion.platform.settings import get_settings


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # This project's first FastAPI lifespan handler. Mirrors
    # platform/worker.py's on_startup/on_shutdown shape (build-once-at-
    # process-start, dispose-once-at-process-end) for the same kind of
    # shared, stateless connection pool — created exactly once here, never
    # lazily on first request, so di.py's get_arq_pool (get_job_queue's until
    # M8.8) only ever reads it (see that function's own comment). A pool-creation failure here fails
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
    # `normalization`'s routes share the /projects prefix rather than getting one
    # of their own, because the resource they hang off IS a project:
    # /projects/{id}/findings. Two routers under one prefix is fine — their paths
    # are disjoint, so nothing shadows anything — and the alternative would be a
    # URL that named the module instead of the resource.
    app.include_router(findings_router, prefix="/projects", tags=["findings"])
    # `correlation`'s route hangs off a project too, so it shares the prefix for
    # the same reason `findings_router` does. Paths stay disjoint: /risks here,
    # /findings there.
    app.include_router(risks_router, prefix="/projects", tags=["risks"])
    # `risk_engine`'s scored read, M6.3. Same prefix and the same reason again; the
    # path is /scored-risks, disjoint from /risks. It deliberately does NOT hang off
    # /risks/{something} — ADR-0025 decision 1 gives a candidate Risk no id, and a
    # literal segment sitting where a future {risk_id} would go is a collision
    # waiting for M8.1 (ADR-0030 decision 1).
    app.include_router(scored_risks_router, prefix="/projects", tags=["risks"])
    # `brief`'s routes, M7.2. Same prefix again; /briefs is disjoint from /risks and
    # /scored-risks. Both are project-scoped and take no Risk in the path, because a Risk has
    # no identifier and a member set is not an address (ADR-0033 decisions 1 and 4).
    app.include_router(briefs_router, prefix="/projects", tags=["briefs"])
    # `scanning`'s project-scoped routes, M8.8. Same prefix and the same reason: /scans is
    # disjoint from every path above. The webhook keeps /scanning (ADR-0035 decision 1).
    app.include_router(project_scans_router, prefix="/projects", tags=["scans"])
    # `history`'s routes, M8.1. Same prefix; /risk-dismissals is disjoint from /risks and
    # /scored-risks, and deliberately not /risks/{id}/…, because the id is a dismissal record's,
    # never a Risk's, which still has none (ADR-0036 decisions 1 and 12).
    app.include_router(risk_dismissals_router, prefix="/projects", tags=["history"])
    app.include_router(scanning_router, prefix="/scanning", tags=["scanning"])

    return app


app = create_app()
