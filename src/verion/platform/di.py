from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
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
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.application.get_finding_evidence import (
    GetFindingEvidenceUseCase,
)
from verion.modules.normalization.application.list_project_findings import (
    ListProjectFindingsUseCase,
)
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectAccessReader,
    PostgresProjectMembershipRepository,
    PostgresProjectRepository,
    PostgresScannerConfigRepository,
    PostgresSecurityContextRepository,
)
from verion.modules.projects.adapters.outbound.vcs.github_adapter import GitHubAdapter
from verion.modules.projects.application.build_security_context import (
    BuildSecurityContextUseCase,
)
from verion.modules.projects.application.build_security_context_from_github import (
    BuildSecurityContextFromGitHubUseCase,
)
from verion.modules.projects.application.connect_repository import ConnectRepositoryUseCase
from verion.modules.projects.application.connect_repository_via_github import (
    ConnectRepositoryViaGitHubUseCase,
)
from verion.modules.projects.application.create_project import CreateProjectUseCase
from verion.modules.projects.application.get_security_context import GetSecurityContextUseCase
from verion.modules.projects.application.update_exposure_tags import UpdateExposureTagsUseCase
from verion.modules.projects.application.update_scanner_config import UpdateScannerConfigUseCase
from verion.modules.projects.domain.context_detection import detect_stack
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.scanner_config_repository import ScannerConfigRepositoryPort
from verion.modules.projects.ports.security_context_repository import (
    SecurityContextRepositoryPort,
)
from verion.modules.projects.ports.vcs_provider import VcsProviderPort
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
    PostgresWebhookDeliveryRepository,
)
from verion.modules.scanning.adapters.outbound.queue.arq_job_queue import ArqJobQueue
from verion.modules.scanning.application.handle_github_webhook import HandleGitHubWebhookUseCase
from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.ports.job_queue import JobQueuePort
from verion.modules.scanning.ports.scan_repository import ScanRepositoryPort
from verion.modules.scanning.ports.scan_result_repository import ScanResultRepositoryPort
from verion.modules.scanning.ports.webhook_delivery_repository import WebhookDeliveryRepositoryPort
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


async def get_current_github_access_token(
    user_id: CurrentUserIdDep, connections: GitHubConnectionRepositoryDep
) -> str:
    connection = await connections.get_by_user_id(user_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No GitHub account connected"
        )
    return connection.access_token


CurrentGitHubAccessTokenDep = Annotated[str, Depends(get_current_github_access_token)]


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


def get_vcs_provider(settings: SettingsDep) -> VcsProviderPort:
    # Not @lru_cache: unlike the old zero-arg factory, this now takes
    # SettingsDep — a pydantic BaseSettings instance isn't hashable
    # (no frozen=True), so lru_cache would raise on the first request.
    # Every other settings-dependent factory in this file (e.g.
    # get_access_token_issuer, get_github_oauth_client) is uncached for the
    # same reason; get_settings() is itself already an lru_cache'd
    # singleton, so this stays cheap without needing its own cache.
    return GitHubAdapter(
        webhook_url=settings.github_webhook_url, webhook_secret=settings.github_webhook_secret
    )


VcsProviderDep = Annotated[VcsProviderPort, Depends(get_vcs_provider)]


def get_connect_repository_via_github_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
    vcs_provider: VcsProviderDep,
    id_generator: IdGeneratorDep,
) -> ConnectRepositoryViaGitHubUseCase:
    return ConnectRepositoryViaGitHubUseCase(
        projects=projects,
        memberships=memberships,
        connected_repos=connected_repos,
        vcs_provider=vcs_provider,
        id_generator=id_generator,
    )


ConnectRepositoryViaGitHubUseCaseDep = Annotated[
    ConnectRepositoryViaGitHubUseCase, Depends(get_connect_repository_via_github_use_case)
]


def get_security_context_repository(session: DbSessionDep) -> SecurityContextRepositoryPort:
    return PostgresSecurityContextRepository(session)


SecurityContextRepositoryDep = Annotated[
    SecurityContextRepositoryPort, Depends(get_security_context_repository)
]


def get_build_security_context_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    security_contexts: SecurityContextRepositoryDep,
    id_generator: IdGeneratorDep,
    clock: ClockDep,
) -> BuildSecurityContextUseCase:
    return BuildSecurityContextUseCase(
        projects=projects,
        memberships=memberships,
        security_contexts=security_contexts,
        detector=detect_stack,
        id_generator=id_generator,
        clock=clock,
    )


BuildSecurityContextUseCaseDep = Annotated[
    BuildSecurityContextUseCase, Depends(get_build_security_context_use_case)
]


def get_build_security_context_from_github_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
    vcs_provider: VcsProviderDep,
    build_security_context: BuildSecurityContextUseCaseDep,
) -> BuildSecurityContextFromGitHubUseCase:
    return BuildSecurityContextFromGitHubUseCase(
        projects=projects,
        memberships=memberships,
        connected_repos=connected_repos,
        vcs_provider=vcs_provider,
        build_security_context=build_security_context,
    )


BuildSecurityContextFromGitHubUseCaseDep = Annotated[
    BuildSecurityContextFromGitHubUseCase, Depends(get_build_security_context_from_github_use_case)
]


def get_get_security_context_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    security_contexts: SecurityContextRepositoryDep,
) -> GetSecurityContextUseCase:
    return GetSecurityContextUseCase(
        projects=projects, memberships=memberships, security_contexts=security_contexts
    )


GetSecurityContextUseCaseDep = Annotated[
    GetSecurityContextUseCase, Depends(get_get_security_context_use_case)
]


def get_update_exposure_tags_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    security_contexts: SecurityContextRepositoryDep,
    id_generator: IdGeneratorDep,
    clock: ClockDep,
) -> UpdateExposureTagsUseCase:
    return UpdateExposureTagsUseCase(
        projects=projects,
        memberships=memberships,
        security_contexts=security_contexts,
        id_generator=id_generator,
        clock=clock,
    )


UpdateExposureTagsUseCaseDep = Annotated[
    UpdateExposureTagsUseCase, Depends(get_update_exposure_tags_use_case)
]


def get_scanner_config_repository(session: DbSessionDep) -> ScannerConfigRepositoryPort:
    return PostgresScannerConfigRepository(session)


ScannerConfigRepositoryDep = Annotated[
    ScannerConfigRepositoryPort, Depends(get_scanner_config_repository)
]


def get_update_scanner_config_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    scanner_configs: ScannerConfigRepositoryDep,
    id_generator: IdGeneratorDep,
    clock: ClockDep,
) -> UpdateScannerConfigUseCase:
    return UpdateScannerConfigUseCase(
        projects=projects,
        memberships=memberships,
        scanner_configs=scanner_configs,
        id_generator=id_generator,
        clock=clock,
    )


UpdateScannerConfigUseCaseDep = Annotated[
    UpdateScannerConfigUseCase, Depends(get_update_scanner_config_use_case)
]


def get_scan_repository(session: DbSessionDep) -> ScanRepositoryPort:
    return PostgresScanRepository(session)


ScanRepositoryDep = Annotated[ScanRepositoryPort, Depends(get_scan_repository)]


def get_scan_result_repository(session: DbSessionDep) -> ScanResultRepositoryPort:
    return PostgresScanResultRepository(session)


ScanResultRepositoryDep = Annotated[ScanResultRepositoryPort, Depends(get_scan_result_repository)]


def get_webhook_secret(settings: SettingsDep) -> str:
    return settings.github_webhook_secret


WebhookSecretDep = Annotated[str, Depends(get_webhook_secret)]


def get_webhook_delivery_repository(session: DbSessionDep) -> WebhookDeliveryRepositoryPort:
    return PostgresWebhookDeliveryRepository(session)


WebhookDeliveryRepositoryDep = Annotated[
    WebhookDeliveryRepositoryPort, Depends(get_webhook_delivery_repository)
]


def get_job_queue(request: Request) -> JobQueuePort:
    # Reads the already-constructed arq pool from app.state — never
    # constructs one itself. The pool is created exactly once, at process
    # startup, by app.py's lifespan handler (the first in this project);
    # by the time any request reaches this dependency, lifespan's startup
    # phase has already completed. This preserves ArqJobQueue's own
    # "pool creation is the caller's responsibility, no lazy-init race"
    # contract — di.py is that caller, and it constructs the pool once at
    # a well-defined point, not scattered across first-request-wins logic.
    return ArqJobQueue(request.app.state.arq_redis)


JobQueueDep = Annotated[JobQueuePort, Depends(get_job_queue)]


def get_trigger_scan_use_case(
    scans: ScanRepositoryDep, job_queue: JobQueueDep, id_generator: IdGeneratorDep
) -> TriggerScanUseCase:
    return TriggerScanUseCase(scans=scans, job_queue=job_queue, id_generator=id_generator)


TriggerScanUseCaseDep = Annotated[TriggerScanUseCase, Depends(get_trigger_scan_use_case)]


def get_handle_github_webhook_use_case(
    webhook_deliveries: WebhookDeliveryRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
    projects: ProjectRepositoryDep,
    trigger_scan: TriggerScanUseCaseDep,
) -> HandleGitHubWebhookUseCase:
    return HandleGitHubWebhookUseCase(
        webhook_deliveries=webhook_deliveries,
        connected_repos=connected_repos,
        projects=projects,
        trigger_scan=trigger_scan,
    )


HandleGitHubWebhookUseCaseDep = Annotated[
    HandleGitHubWebhookUseCase, Depends(get_handle_github_webhook_use_case)
]


# A factory's PORT-annotated return type is the only place `mypy --strict` ever
# verifies that an adapter satisfies its Protocol (CLAUDE.md's Tier 1 table). This
# one shipped in M4.3 with no route depending on it, for that reason alone; since
# M4.5 the two use cases below consume it and the route is real.
def get_finding_repository(session: DbSessionDep) -> FindingRepositoryPort:
    return PostgresFindingRepository(session)


FindingRepositoryDep = Annotated[FindingRepositoryPort, Depends(get_finding_repository)]


# New in M4.5. `worker.py` has always constructed its own for the job path; the
# read API needs a request-scoped one, and routing it through here is also what
# puts PostgresNormalizationRunRepository against its Protocol at a second
# checked site.
def get_normalization_run_repository(session: DbSessionDep) -> NormalizationRunRepositoryPort:
    return PostgresNormalizationRunRepository(session)


NormalizationRunRepositoryDep = Annotated[
    NormalizationRunRepositoryPort, Depends(get_normalization_run_repository)
]


# `projects`' authorization verdict, consumed by `normalization`'s routes. Not
# PostgresProjectMembershipRepository, which is a persistence port — see
# ProjectAccessPort's docstring and ADR-0022 decision 2 for why the difference
# matters more than the one line of code it saves.
def get_project_access(session: DbSessionDep) -> ProjectAccessPort:
    return PostgresProjectAccessReader(session)


ProjectAccessDep = Annotated[ProjectAccessPort, Depends(get_project_access)]


def get_list_project_findings_use_case(
    project_access: ProjectAccessDep,
    findings: FindingRepositoryDep,
    normalization_runs: NormalizationRunRepositoryDep,
) -> ListProjectFindingsUseCase:
    return ListProjectFindingsUseCase(
        project_access=project_access,
        findings=findings,
        normalization_runs=normalization_runs,
    )


ListProjectFindingsUseCaseDep = Annotated[
    ListProjectFindingsUseCase, Depends(get_list_project_findings_use_case)
]


def get_get_finding_evidence_use_case(
    project_access: ProjectAccessDep, findings: FindingRepositoryDep
) -> GetFindingEvidenceUseCase:
    return GetFindingEvidenceUseCase(project_access=project_access, findings=findings)


GetFindingEvidenceUseCaseDep = Annotated[
    GetFindingEvidenceUseCase, Depends(get_get_finding_evidence_use_case)
]
