"""Rule 11: a dev-only placeholder secret must not boot outside `app_env='local'`.

Each rejection test sets every OTHER secret to a real-looking value and matches on the
failing field's own NAME. Matching the shared phrase "dev-only default" alone would pass
when a different field failed first in `_DEV_ONLY_DEFAULTS`' order, which became a live
possibility once the dict held more than one entry.

**Nothing here asserts that the error message leaves the other secrets out**, because it
does not: pydantic's `input_value` carries them. That is **G71**, registered and not fixed,
and an assertion written now would fail on a defect this issue deliberately does not fix.

**Every construction below is isolated from both settings sources** — `_env_file=None`, and an
autouse fixture that deletes the four variables — because `Settings` reads `infra/.env`, which
is exactly where this project keeps a real key. Observed 2026-09-17 (M7.3's capture runbook puts
a real `OPENAI_API_KEY` there): the first test below failed, and pydantic's assertion diff
printed the key's whole value. That is **G81**, whose subject is the rest of the unit suite.
"""

import pytest
from pydantic import ValidationError

from verion.platform.settings import Settings

_REAL = {
    "jwt_secret_key": "a-real-production-secret-value",
    "github_client_secret": "a-real-github-client-secret-value",
    "github_webhook_secret": "a-real-webhook-secret-value",
    "openai_api_key": "a-real-openai-api-key-value",
}


@pytest.fixture(autouse=True)
def _isolate_from_the_developers_environment(monkeypatch):
    """The env file is disabled per construction; this closes the other source."""
    for field_name in _REAL:
        monkeypatch.delenv(field_name.upper(), raising=False)


def _settings(**overrides: str) -> Settings:
    """`Settings` built from defaults and `overrides` only, never from `infra/.env`."""
    return Settings(_env_file=None, **overrides)


def _all_real_except(field_name: str) -> dict[str, str]:
    return {name: value for name, value in _REAL.items() if name != field_name}


def test_dev_secrets_are_fine_for_local():
    settings = _settings(app_env="local")

    assert settings.jwt_secret_key == "dev-secret-change-in-production-32b"
    assert settings.github_client_secret == "dev-github-client-secret-placeholder"
    assert settings.github_webhook_secret == "dev-github-webhook-secret-placeholder"
    assert settings.openai_api_key == "dev-openai-api-key-placeholder"


@pytest.mark.parametrize("field_name", sorted(_REAL))
def test_each_dev_secret_is_rejected_outside_local_by_name(field_name):
    with pytest.raises(ValidationError, match=f"{field_name} is still the dev-only default"):
        _settings(app_env="production", **_all_real_except(field_name))


def test_real_secrets_are_accepted_outside_local():
    settings = _settings(app_env="production", **_REAL)

    assert settings.jwt_secret_key == "a-real-production-secret-value"
    assert settings.github_client_secret == "a-real-github-client-secret-value"
    assert settings.github_webhook_secret == "a-real-webhook-secret-value"
    assert settings.openai_api_key == "a-real-openai-api-key-value"
