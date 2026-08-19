from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_ONLY_JWT_SECRET_KEY = "dev-secret-change-in-production-32b"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="infra/.env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "verion"
    app_env: str = "local"
    debug: bool = True
    log_level: str = "info"

    database_url: str = "postgresql+asyncpg://verion:verion@localhost:5432/verion"

    # Dev-only default. Not a secrets-management solution (that's M10) — just
    # a safe local default, with a fail-fast guard below so a real deployment
    # can't silently start with this well-known, publicly-visible value.
    jwt_secret_key: str = _DEV_ONLY_JWT_SECRET_KEY
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 30

    # Note: this is currently a one-off pattern (only jwt_secret_key needs it).
    # If a second sensitive setting needs the same "insecure default, fail
    # outside local" guard (e.g. a future GitHub OAuth client secret), extract
    # this into a reusable validator instead of copy-pasting a third
    # model_validator. Revisit at the second instance, not before.
    @model_validator(mode="after")
    def _reject_dev_secret_outside_local(self) -> "Settings":
        if self.app_env != "local" and self.jwt_secret_key == _DEV_ONLY_JWT_SECRET_KEY:
            raise ValueError(
                "JWT_SECRET_KEY is still the dev-only default outside app_env='local'. "
                "Set a real JWT_SECRET_KEY env var before running in this environment."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
