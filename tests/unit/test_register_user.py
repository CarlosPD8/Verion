import pytest

from verion.modules.identity.application.register_user import RegisterUserUseCase
from verion.modules.identity.domain.exceptions import EmailAlreadyRegistered, InvalidEmail


def _use_case(user_repository, password_hasher, clock, id_generator) -> RegisterUserUseCase:
    return RegisterUserUseCase(
        users=user_repository,
        password_hasher=password_hasher,
        clock=clock,
        id_generator=id_generator,
    )


async def test_registers_a_new_user(user_repository, password_hasher, clock, id_generator):
    use_case = _use_case(user_repository, password_hasher, clock, id_generator)

    user = await use_case.execute(
        email="dev@example.com", plaintext_password="correct horse battery staple"
    )

    assert str(user.email) == "dev@example.com"
    assert user.created_at == clock.now()
    assert await user_repository.get_by_email("dev@example.com") == user


async def test_rejects_duplicate_email(user_repository, password_hasher, clock, id_generator):
    use_case = _use_case(user_repository, password_hasher, clock, id_generator)
    await use_case.execute(email="dev@example.com", plaintext_password="first-password")

    with pytest.raises(EmailAlreadyRegistered):
        await use_case.execute(email="dev@example.com", plaintext_password="second-password")


async def test_rejects_malformed_email(user_repository, password_hasher, clock, id_generator):
    use_case = _use_case(user_repository, password_hasher, clock, id_generator)

    with pytest.raises(InvalidEmail):
        await use_case.execute(
            email="not-an-email", plaintext_password="correct horse battery staple"
        )


async def test_never_persists_the_plaintext_password(
    user_repository, password_hasher, clock, id_generator
):
    use_case = _use_case(user_repository, password_hasher, clock, id_generator)
    plaintext = "correct horse battery staple"

    user = await use_case.execute(email="dev@example.com", plaintext_password=plaintext)

    assert user.hashed_password != plaintext
    stored = await user_repository.get_by_id(user.id)
    assert stored.hashed_password != plaintext
