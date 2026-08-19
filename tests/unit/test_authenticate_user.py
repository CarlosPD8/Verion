import pytest

from verion.modules.identity.application.authenticate_user import AuthenticateUserUseCase
from verion.modules.identity.application.register_user import RegisterUserUseCase
from verion.modules.identity.domain.exceptions import InvalidCredentials


async def _register(
    user_repository, password_hasher, clock, id_generator, email, plaintext_password
):
    await RegisterUserUseCase(
        users=user_repository,
        password_hasher=password_hasher,
        clock=clock,
        id_generator=id_generator,
    ).execute(email=email, plaintext_password=plaintext_password)


async def test_authenticates_with_correct_password(
    user_repository, password_hasher, clock, id_generator
):
    await _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    user = await use_case.execute(email="dev@example.com", plaintext_password="correct horse")

    assert str(user.email) == "dev@example.com"


async def test_rejects_wrong_password(user_repository, password_hasher, clock, id_generator):
    await _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials):
        await use_case.execute(email="dev@example.com", plaintext_password="wrong password")


async def test_rejects_unknown_email_with_same_generic_error(user_repository, password_hasher):
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials) as exc_info:
        await use_case.execute(email="ghost@example.com", plaintext_password="whatever")

    assert "ghost@example.com" not in str(exc_info.value)


async def test_no_plaintext_password_leaks_into_the_exception(
    user_repository, password_hasher, clock, id_generator
):
    await _register(
        user_repository, password_hasher, clock, id_generator, "dev@example.com", "correct horse"
    )
    use_case = AuthenticateUserUseCase(users=user_repository, password_hasher=password_hasher)

    with pytest.raises(InvalidCredentials) as exc_info:
        await use_case.execute(
            email="dev@example.com", plaintext_password="super-secret-wrong-guess"
        )

    assert "super-secret-wrong-guess" not in str(exc_info.value)
