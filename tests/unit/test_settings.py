import pytest
from pydantic import ValidationError

from verion.platform.settings import Settings


def test_dev_secret_is_fine_for_local():
    settings = Settings(app_env="local")

    assert settings.jwt_secret_key == "dev-secret-change-in-production-32b"


def test_dev_secret_is_rejected_outside_local():
    with pytest.raises(ValidationError, match="dev-only default"):
        Settings(app_env="production")


def test_a_real_secret_is_accepted_outside_local():
    settings = Settings(app_env="production", jwt_secret_key="a-real-production-secret-value")

    assert settings.jwt_secret_key == "a-real-production-secret-value"
