from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.identity.adapters.outbound.db.repository import PostgresUserRepository
from verion.modules.identity.adapters.outbound.security.argon2_hasher import Argon2PasswordHasher
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.application.authenticate_user import AuthenticateUserUseCase
from verion.modules.identity.application.register_user import RegisterUserUseCase
from verion.modules.identity.ports.access_token_issuer import AccessTokenIssuer
from verion.modules.identity.ports.password_hasher import PasswordHasherPort
from verion.modules.identity.ports.user_repository import UserRepositoryPort
from verion.platform.clock import SystemClock
from verion.platform.db import get_db_session
from verion.platform.id_generator import UuidIdGenerator
from verion.platform.settings import Settings, get_settings
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


@lru_cache
def get_clock() -> ClockPort:
    return SystemClock()


@lru_cache
def get_id_generator() -> IdGeneratorPort:
    return UuidIdGenerator()


ClockDep = Annotated[ClockPort, Depends(get_clock)]
IdGeneratorDep = Annotated[IdGeneratorPort, Depends(get_id_generator)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


@lru_cache
def get_password_hasher() -> PasswordHasherPort:
    return Argon2PasswordHasher()


PasswordHasherDep = Annotated[PasswordHasherPort, Depends(get_password_hasher)]


def get_access_token_issuer(settings: SettingsDep, clock: ClockDep) -> AccessTokenIssuer:
    return JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=clock,
    )


AccessTokenIssuerDep = Annotated[AccessTokenIssuer, Depends(get_access_token_issuer)]


def get_user_repository(session: DbSessionDep) -> UserRepositoryPort:
    return PostgresUserRepository(session)


UserRepositoryDep = Annotated[UserRepositoryPort, Depends(get_user_repository)]


def get_register_user_use_case(
    users: UserRepositoryDep,
    password_hasher: PasswordHasherDep,
    clock: ClockDep,
    id_generator: IdGeneratorDep,
) -> RegisterUserUseCase:
    return RegisterUserUseCase(
        users=users, password_hasher=password_hasher, clock=clock, id_generator=id_generator
    )


RegisterUserUseCaseDep = Annotated[RegisterUserUseCase, Depends(get_register_user_use_case)]


def get_authenticate_user_use_case(
    users: UserRepositoryDep, password_hasher: PasswordHasherDep
) -> AuthenticateUserUseCase:
    return AuthenticateUserUseCase(users=users, password_hasher=password_hasher)


AuthenticateUserUseCaseDep = Annotated[
    AuthenticateUserUseCase, Depends(get_authenticate_user_use_case)
]
