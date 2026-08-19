from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_ONLY_JWT_SECRET_KEY = "dev-secret-change-in-production-32b"
_DEV_ONLY_GITHUB_CLIENT_SECRET = "dev-github-client-secret-placeholder"

# Sensitive settings that must never silently boot with their dev-only
# placeholder outside app_env='local'. Add a new (field_name, dev_value)
# pair here for any future sensitive setting instead of writing a new
# model_validator — this generalization is the "second instance" the
# original jwt_secret_key-only validator's comment said to watch for.
_DEV_ONLY_DEFAULTS = {
    "jwt_secret_key": _DEV_ONLY_JWT_SECRET_KEY,
    "github_client_secret": _DEV_ONLY_GITHUB_CLIENT_SECRET,
}


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

    # Same dev-only-default treatment as jwt_secret_key, see _DEV_ONLY_DEFAULTS.
    github_client_id: str = "dev-github-client-id"
    github_client_secret: str = _DEV_ONLY_GITHUB_CLIENT_SECRET
    github_oauth_redirect_uri: str = "http://localhost:8000/auth/github/callback"

    # No real frontend exists yet — placeholder like database_url's default.
    oauth_success_redirect_url: str = "http://localhost:3000/dashboard"

    @model_validator(mode="after")
    def _reject_dev_secrets_outside_local(self) -> "Settings":
        if self.app_env != "local":
            for field_name, dev_value in _DEV_ONLY_DEFAULTS.items():
                if getattr(self, field_name) == dev_value:
                    raise ValueError(
                        f"{field_name} is still the dev-only default outside app_env='local'. "
                        f"Set a real {field_name.upper()} env var before running in this "
                        "environment."
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
