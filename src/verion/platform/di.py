from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
    PostgresUserRepository,
)
from verion.modules.identity.adapters.outbound.oauth.github_oauth_client import GitHubOAuthClient
from verion.modules.identity.adapters.outbound.oauth.state_signer import GitHubOAuthStateSigner
from verion.modules.identity.adapters.outbound.security.argon2_hasher import Argon2PasswordHasher
from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.identity.application.authenticate_user import AuthenticateUserUseCase
from verion.modules.identity.application.register_user import RegisterUserUseCase
from verion.modules.identity.domain.exceptions import InvalidAccessToken
from verion.modules.identity.ports.access_token_issuer import AccessTokenIssuer
from verion.modules.identity.ports.github_connection_repository import (
    GitHubConnectionRepositoryPort,
)
from verion.modules.identity.ports.github_oauth_client import GitHubOAuthClientPort
from verion.modules.identity.ports.oauth_state_signer import OAuthStateSignerPort
from verion.modules.identity.ports.password_hasher import PasswordHasherPort
from verion.modules.identity.ports.user_repository import UserRepositoryPort
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
)
from verion.modules.projects.application.connect_repository import ConnectRepositoryUseCase
from verion.modules.projects.application.create_project import CreateProjectUseCase
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
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


_bearer_scheme = HTTPBearer()


async def get_current_user_id(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer_scheme)],
    token_issuer: AccessTokenIssuerDep,
) -> str:
    try:
        return token_issuer.decode(credentials.credentials)
    except InvalidAccessToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        ) from exc


CurrentUserIdDep = Annotated[str, Depends(get_current_user_id)]


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


def get_project_repository(session: DbSessionDep) -> ProjectRepositoryPort:
    return PostgresProjectRepository(session)


ProjectRepositoryDep = Annotated[ProjectRepositoryPort, Depends(get_project_repository)]


def get_project_membership_repository(session: DbSessionDep) -> ProjectMembershipRepositoryPort:
    return PostgresProjectMembershipRepository(session)


ProjectMembershipRepositoryDep = Annotated[
    ProjectMembershipRepositoryPort, Depends(get_project_membership_repository)
]


def get_connected_repo_repository(session: DbSessionDep) -> ConnectedRepoRepositoryPort:
    return PostgresConnectedRepoRepository(session)


ConnectedRepoRepositoryDep = Annotated[
    ConnectedRepoRepositoryPort, Depends(get_connected_repo_repository)
]


def get_create_project_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    clock: ClockDep,
    id_generator: IdGeneratorDep,
) -> CreateProjectUseCase:
    return CreateProjectUseCase(
        projects=projects, memberships=memberships, clock=clock, id_generator=id_generator
    )


CreateProjectUseCaseDep = Annotated[CreateProjectUseCase, Depends(get_create_project_use_case)]


def get_connect_repository_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
    id_generator: IdGeneratorDep,
) -> ConnectRepositoryUseCase:
    return ConnectRepositoryUseCase(
        projects=projects,
        memberships=memberships,
        connected_repos=connected_repos,
        id_generator=id_generator,
    )


ConnectRepositoryUseCaseDep = Annotated[
    ConnectRepositoryUseCase, Depends(get_connect_repository_use_case)
]


def get_github_connection_repository(session: DbSessionDep) -> GitHubConnectionRepositoryPort:
    return PostgresGitHubConnectionRepository(session)


GitHubConnectionRepositoryDep = Annotated[
    GitHubConnectionRepositoryPort, Depends(get_github_connection_repository)
]


def get_oauth_state_signer(settings: SettingsDep, clock: ClockDep) -> OAuthStateSignerPort:
    return GitHubOAuthStateSigner(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=10,
        clock=clock,
    )


OAuthStateSignerDep = Annotated[OAuthStateSignerPort, Depends(get_oauth_state_signer)]


def get_github_oauth_client(settings: SettingsDep) -> GitHubOAuthClientPort:
    return GitHubOAuthClient(
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        redirect_uri=settings.github_oauth_redirect_uri,
    )


GitHubOAuthClientDep = Annotated[GitHubOAuthClientPort, Depends(get_github_oauth_client)]
