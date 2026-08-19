from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="infra/.env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "verion"
    app_env: str = "local"
    debug: bool = True
    log_level: str = "info"


@lru_cache
def get_settings() -> Settings:
    return Settings()
