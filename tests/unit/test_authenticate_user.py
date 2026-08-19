import pytest

from verion.modules.identity.application.authenticate_user import AuthenticateUserUseCase
from verion.modules.identity.application.register_user import RegisterUserUseCase
from verion.modules.identity.domain.exceptions import InvalidCredentials


def _register(user_repository, password_hasher, clock, id_generator, email, plaintext_password):
    RegisterUserUseCase(
        users=user_repository,
        password_hasher=password_hasher,
        clock=clock,
        id_generator=id_generator,
    ).execute(email=email, plaintext_password=plaintext_password)


def test_authenticates_with_correct_password(user_repository, password_hasher, clock, id_generator):
    _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    user = use_case.execute(email="dev@example.com", plaintext_password="correct horse")

    assert str(user.email) == "dev@example.com"


def test_rejects_wrong_password(user_repository, password_hasher, clock, id_generator):
    _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials):
        use_case.execute(email="dev@example.com", plaintext_password="wrong password")


def test_rejects_unknown_email_with_same_generic_error(user_repository, password_hasher):
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials) as exc_info:
        use_case.execute(email="ghost@example.com", plaintext_password="whatever")

    assert "ghost@example.com" not in str(exc_info.value)


def test_no_plaintext_password_leaks_into_the_exception(
    user_repository, password_hasher, clock, id_generator
):
    _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials) as exc_info:
        use_case.execute(email="dev@example.com", plaintext_password="super-secret-wrong-guess")

    assert "super-secret-wrong-guess" not in str(exc_info.value)
