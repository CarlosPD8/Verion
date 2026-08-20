import pytest
from pydantic import ValidationError

from verion.platform.settings import Settings


def test_dev_secrets_are_fine_for_local():
    settings = Settings(app_env="local")

    assert settings.jwt_secret_key == "dev-secret-change-in-production-32b"
    assert settings.github_client_secret == "dev-github-client-secret-placeholder"
    assert settings.github_webhook_secret == "dev-github-webhook-secret-placeholder"


def test_dev_jwt_secret_is_rejected_outside_local():
    with pytest.raises(ValidationError, match="dev-only default"):
        Settings(
            app_env="production",
            github_client_secret="a-real-github-client-secret-value",
            github_webhook_secret="a-real-webhook-secret-value",
        )


def test_dev_github_client_secret_is_rejected_outside_local():
    with pytest.raises(ValidationError, match="dev-only default"):
        Settings(
            app_env="production",
            jwt_secret_key="a-real-production-secret-value",
            github_webhook_secret="a-real-webhook-secret-value",
        )


def test_dev_github_webhook_secret_is_rejected_outside_local():
    with pytest.raises(ValidationError, match="dev-only default"):
        Settings(
            app_env="production",
            jwt_secret_key="a-real-production-secret-value",
            github_client_secret="a-real-github-client-secret-value",
        )


def test_real_secrets_are_accepted_outside_local():
    settings = Settings(
        app_env="production",
        jwt_secret_key="a-real-production-secret-value",
        github_client_secret="a-real-github-client-secret-value",
        github_webhook_secret="a-real-webhook-secret-value",
    )

    assert settings.jwt_secret_key == "a-real-production-secret-value"
    assert settings.github_client_secret == "a-real-github-client-secret-value"
    assert settings.github_webhook_secret == "a-real-webhook-secret-value"
