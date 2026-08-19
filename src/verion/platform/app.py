from fastapi import FastAPI

from verion.modules.identity.adapters.inbound.api.router import router as identity_router
from verion.modules.projects.adapters.inbound.api.router import router as projects_router
from verion.platform.settings import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, debug=settings.debug)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(identity_router, prefix="/auth", tags=["auth"])
    app.include_router(projects_router, prefix="/projects", tags=["projects"])

    return app


app = create_app()
