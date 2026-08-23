from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Absolute, not CWD-relative like env_file below — this is read by the arq
# worker process (platform/worker.py, M3.3), which has no guarantee of
# running from the repo root the way `uv run uvicorn`/pytest do.
_DEFAULT_SEMGREP_RULESET = str(
    Path(__file__).resolve().parents[1]
    / "modules"
    / "scanning"
    / "adapters"
    / "outbound"
    / "scanners"
    / "rulesets"
    / "default.yml"
)

_DEV_ONLY_JWT_SECRET_KEY = "dev-secret-change-in-production-32b"
_DEV_ONLY_GITHUB_CLIENT_SECRET = "dev-github-client-secret-placeholder"
_DEV_ONLY_GITHUB_WEBHOOK_SECRET = "dev-github-webhook-secret-placeholder"

# Sensitive settings that must never silently boot with their dev-only
# placeholder outside app_env='local'. Add a new (field_name, dev_value)
# pair here for any future sensitive setting instead of writing a new
# model_validator — this generalization is the "second instance" the
# original jwt_secret_key-only validator's comment said to watch for.
_DEV_ONLY_DEFAULTS = {
    "jwt_secret_key": _DEV_ONLY_JWT_SECRET_KEY,
    "github_client_secret": _DEV_ONLY_GITHUB_CLIENT_SECRET,
    "github_webhook_secret": _DEV_ONLY_GITHUB_WEBHOOK_SECRET,
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
    redis_url: str = "redis://localhost:6379/0"

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

    # Same dev-only-default treatment as jwt_secret_key/github_client_secret,
    # see _DEV_ONLY_DEFAULTS. Used both to verify inbound GitHub webhook
    # deliveries (HMAC-SHA256 over the raw payload) and to sign outbound
    # webhook registration calls (GitHubAdapter.register_webhook, M3.6).
    github_webhook_secret: str = _DEV_ONLY_GITHUB_WEBHOOK_SECRET
    # Not sensitive — just the public callback path GitHub delivers push
    # events to. Same placeholder-URL shape as github_oauth_redirect_uri.
    github_webhook_url: str = "http://localhost:8000/scanning/webhooks/github"

    # Deliberately a small, bundled, version-controlled ruleset — not
    # "auto"/"p/*", which fetch from Semgrep's cloud registry over the
    # network on every scan. Determinism/no-network-dependency at scan time
    # is an accepted MVP trade-off over registry-level coverage breadth (see
    # the ruleset file's own comment). The same file backs both this
    # production default and the scanning integration tests.
    semgrep_ruleset: str = _DEFAULT_SEMGREP_RULESET

    # How long a normalization_runs row may sit pending or running before the
    # reconciliation sweep re-enqueues it (ADR-0021).
    #
    # **900 is derived from WorkerSettings.job_timeout (600), not picked**, and
    # the relationship is a CONSTRAINT rather than slack: a job arq has already
    # killed cannot still be running, so every row over this threshold either has
    # no live job — which is what the sweep is for — or was claimed late behind a
    # queue, which is bounded by concurrent job count rather than by backlog
    # depth. Raise job_timeout past this and the sweep starts continuously
    # re-enqueuing live work instead. `test_sweep_settings.py` asserts the
    # ordering so that bump cannot be made silently.
    normalization_sweep_stale_after_seconds: int = 900
    # Bounds one tick's enqueue burst; the next tick takes the rest. Large enough
    # that a real backlog drains in a few ticks, small enough that a pathological
    # table cannot turn one cron firing into an unbounded Redis write storm.
    normalization_sweep_batch_size: int = 200

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
