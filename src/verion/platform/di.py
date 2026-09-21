from functools import lru_cache
from typing import Annotated

from arq.connections import ArqRedis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.brief.adapters.outbound.db.repository import (
    PostgresBriefGenerationRepository,
    PostgresSecurityBriefRepository,
)
from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.queue.after_commit_brief_generation_queue import (
    AfterCommitBriefGenerationQueue,
)
from verion.modules.brief.adapters.outbound.queue.arq_brief_generation_queue import (
    ArqBriefGenerationQueue,
)
from verion.modules.brief.application.generate_security_brief import (
    GenerateSecurityBriefUseCase,
)
from verion.modules.brief.application.get_brief_generation import GetBriefGenerationUseCase
from verion.modules.brief.application.list_security_briefs import ListSecurityBriefsUseCase
from verion.modules.brief.application.request_security_brief import RequestSecurityBriefUseCase
from verion.modules.brief.ports.brief_generation_queue import BriefGenerationQueuePort
from verion.modules.brief.ports.brief_generation_repository import BriefGenerationRepositoryPort
from verion.modules.brief.ports.explanation_provider import ExplanationProviderPort
from verion.modules.brief.ports.security_brief_repository import SecurityBriefRepositoryPort
from verion.modules.correlation.application.candidate_risk_provider import (
    CorrelationCandidateRisks,
)
from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.application.list_project_risks import ListProjectRisksUseCase
from verion.modules.correlation.ports.candidate_risk import CandidateRiskPort
from verion.modules.history.adapters.outbound.db.repository import (
    PostgresRiskDismissalRepository,
)
from verion.modules.history.application.dismiss_risk import DismissRiskUseCase
from verion.modules.history.application.list_risk_dismissals import ListRiskDismissalsUseCase
from verion.modules.history.application.undismiss_risk import UndismissRiskUseCase
from verion.modules.history.ports.risk_dismissal_repository import RiskDismissalRepositoryPort
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
    PostgresRouteMapReader,
    PostgresRouteMapRepository,
    PostgresScannerConfigRepository,
    PostgresSecurityContextRepository,
    PostgresServingDeclarationRepository,
    PostgresServingDeclarationVerdictReader,
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
from verion.modules.projects.application.declare_serving import DeclareServingUseCase
from verion.modules.projects.application.get_security_context import GetSecurityContextUseCase
from verion.modules.projects.application.get_serving_declaration import (
    GetServingDeclarationUseCase,
)
from verion.modules.projects.application.update_exposure_tags import UpdateExposureTagsUseCase
from verion.modules.projects.application.update_scanner_config import UpdateScannerConfigUseCase
from verion.modules.projects.domain.context_detection import detect_stack
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.route_map import RouteMapPort
from verion.modules.projects.ports.route_map_repository import RouteMapRepositoryPort
from verion.modules.projects.ports.scanner_config_repository import ScannerConfigRepositoryPort
from verion.modules.projects.ports.security_context_repository import (
    SecurityContextRepositoryPort,
)
from verion.modules.projects.ports.serving_declaration import ServingDeclarationPort
from verion.modules.projects.ports.serving_declaration_repository import (
    ServingDeclarationRepositoryPort,
)
from verion.modules.projects.ports.vcs_provider import VcsProviderPort
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.application.explainable_risk_provider import (
    ScoredExplainableRisks,
)
from verion.modules.risk_engine.application.list_scored_risks import ListScoredRisksUseCase
from verion.modules.risk_engine.ports.explainable_risk import ExplainableRiskPort
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
    PostgresWebhookDeliveryRepository,
)
from verion.modules.scanning.adapters.outbound.queue.after_commit_job_queue import (
    AfterCommitJobQueue,
)
from verion.modules.scanning.adapters.outbound.queue.arq_job_queue import ArqJobQueue
from verion.modules.scanning.application.get_scan import GetScanUseCase
from verion.modules.scanning.application.handle_github_webhook import HandleGitHubWebhookUseCase
from verion.modules.scanning.application.start_scan import StartScanUseCase
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
# `scope="function"` is what makes a 2xx mean "committed". Without it FastAPI exits this yield
# dependency after the response is sent, so a client holds its 201 before the row exists and a
# commit that raises follows a success already on the wire (G86). ADR-0008's 2026-09-19 note;
# proven by tests/integration/test_session_commit_precedes_response.py.
DbSessionDep = Annotated[AsyncSession, Depends(get_db_session, scope="function")]


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


# M5.6 commit 4. Request-scoped — it depends on DbSessionDep — so not @lru_cache'd (rule 15).
def get_route_map_repository(session: DbSessionDep) -> RouteMapRepositoryPort:
    return PostgresRouteMapRepository(session)


RouteMapRepositoryDep = Annotated[RouteMapRepositoryPort, Depends(get_route_map_repository)]


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
    route_maps: RouteMapRepositoryDep,
    id_generator: IdGeneratorDep,
    clock: ClockDep,
) -> BuildSecurityContextFromGitHubUseCase:
    return BuildSecurityContextFromGitHubUseCase(
        projects=projects,
        memberships=memberships,
        connected_repos=connected_repos,
        vcs_provider=vcs_provider,
        build_security_context=build_security_context,
        route_maps=route_maps,
        id_generator=id_generator,
        clock=clock,
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


# `projects`' serving-declaration factories (M5.5 commit 2). All three request-scoped,
# so none is @lru_cache'd — each depends on DbSessionDep transitively and caching one
# would leak a stale session across requests (rule 15).
#
# ADR-0028 decision 4's cross-module `ServingDeclarationPort` is NOT among these: it is a
# verdict port for `correlation`, not part of `projects`' own read surface, and it is wired
# beside `correlation`'s factories below. It shipped at M5.6 commit 3 with its consumer,
# which is what resolved **G48**.
def get_serving_declaration_repository(session: DbSessionDep) -> ServingDeclarationRepositoryPort:
    return PostgresServingDeclarationRepository(session)


ServingDeclarationRepositoryDep = Annotated[
    ServingDeclarationRepositoryPort, Depends(get_serving_declaration_repository)
]


def get_declare_serving_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    serving_declarations: ServingDeclarationRepositoryDep,
    scanner_configs: ScannerConfigRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
    id_generator: IdGeneratorDep,
    clock: ClockDep,
) -> DeclareServingUseCase:
    return DeclareServingUseCase(
        projects=projects,
        memberships=memberships,
        serving_declarations=serving_declarations,
        scanner_configs=scanner_configs,
        connected_repos=connected_repos,
        id_generator=id_generator,
        clock=clock,
    )


DeclareServingUseCaseDep = Annotated[DeclareServingUseCase, Depends(get_declare_serving_use_case)]


def get_get_serving_declaration_use_case(
    projects: ProjectRepositoryDep,
    memberships: ProjectMembershipRepositoryDep,
    serving_declarations: ServingDeclarationRepositoryDep,
    scanner_configs: ScannerConfigRepositoryDep,
    connected_repos: ConnectedRepoRepositoryDep,
) -> GetServingDeclarationUseCase:
    return GetServingDeclarationUseCase(
        projects=projects,
        memberships=memberships,
        serving_declarations=serving_declarations,
        scanner_configs=scanner_configs,
        connected_repos=connected_repos,
    )


GetServingDeclarationUseCaseDep = Annotated[
    GetServingDeclarationUseCase, Depends(get_get_serving_declaration_use_case)
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


def get_arq_pool(request: Request) -> ArqRedis:
    # Reads the already-constructed arq pool from app.state — never
    # constructs one itself. The pool is created exactly once, at process
    # startup, by app.py's lifespan handler (the first in this project);
    # by the time any request reaches this dependency, lifespan's startup
    # phase has already completed. This preserves ArqJobQueue's own
    # "pool creation is the caller's responsibility, no lazy-init race"
    # contract — di.py is that caller, and it constructs the pool once at
    # a well-defined point, not scattered across first-request-wins logic.
    # A factory of its own since M8.8, so a test overrides the POOL and still
    # exercises the real deferral in get_job_queue below.
    pool: ArqRedis = request.app.state.arq_redis
    return pool


ArqPoolDep = Annotated[ArqRedis, Depends(get_arq_pool)]


def get_job_queue(pool: ArqPoolDep, session: DbSessionDep) -> JobQueuePort:
    # Deferred to after the request's commit, so a worker never takes a job
    # whose Scan row it cannot see yet (ADR-0035 decision 5). Session-dependent,
    # so never @lru_cache (rule 15).
    return AfterCommitJobQueue(ArqJobQueue(pool), session)


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


# A factory's PORT-annotated return type is ~~the only place~~ **one of two places**
# `mypy --strict` ever
# verifies that an adapter satisfies its Protocol. *(Narrowed 2026-09-21, M8.6 commit 3.
# CLAUDE.md's Tier 1 table always said both — "a `di.py` factory's return type, **or an
# explicit annotation**" — so this comment misreported the row it cites. The other place is
# an explicit annotation at a construction site, and `platform/worker.py` now has several:
# `on_startup`'s `explanations: ExplanationProviderPort = ...`, and every port-annotated
# constructor parameter `generate_brief` fills by keyword, which the guardian verified by
# mutation. The practical point this comment exists to make survives: an adapter constructed
# into an `Any` is unchecked, so wiring it somewhere port-annotated is what buys the check.)*
# This
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


# M8.8, ADR-0035. Below ProjectAccessDep because both consume it; the trigger they
# delegate to is wired above, beside the webhook's.
def get_start_scan_use_case(
    project_access: ProjectAccessDep, trigger_scan: TriggerScanUseCaseDep
) -> StartScanUseCase:
    return StartScanUseCase(project_access=project_access, trigger_scan=trigger_scan)


StartScanUseCaseDep = Annotated[StartScanUseCase, Depends(get_start_scan_use_case)]


def get_get_scan_use_case(
    project_access: ProjectAccessDep, scans: ScanRepositoryDep
) -> GetScanUseCase:
    return GetScanUseCase(project_access=project_access, scans=scans)


GetScanUseCaseDep = Annotated[GetScanUseCase, Depends(get_get_scan_use_case)]


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


# The two `projects` ports `correlation` reads for the derivation gate (M5.6 commits 3 and 4).
# Neither is @lru_cache'd: both depend on DbSessionDep, so caching either would leak a stale
# session across requests (rule 15). Until commit 4 the route-map factory took no argument
# and wired a placeholder; it was left uncached then precisely so this change would not
# have a cache to forget.
def get_serving_declaration_port(session: DbSessionDep) -> ServingDeclarationPort:
    return PostgresServingDeclarationVerdictReader(session)


ServingDeclarationPortDep = Annotated[ServingDeclarationPort, Depends(get_serving_declaration_port)]


def get_route_map_port(session: DbSessionDep) -> RouteMapPort:
    return PostgresRouteMapReader(session)


RouteMapPortDep = Annotated[RouteMapPort, Depends(get_route_map_port)]


# `correlation`'s first two factories (M5.2). Both request-scoped, so neither is
# @lru_cache'd — rule 15. The grouping use case is wired separately from the
# listing because M6 consumes it without an envelope; ADR-0025 decision 4.
def get_correlate_findings_use_case(
    project_access: ProjectAccessDep,
    findings: FindingRepositoryDep,
    serving: ServingDeclarationPortDep,
    route_maps: RouteMapPortDep,
) -> CorrelateFindingsUseCase:
    return CorrelateFindingsUseCase(
        project_access=project_access, findings=findings, serving=serving, route_maps=route_maps
    )


CorrelateFindingsUseCaseDep = Annotated[
    CorrelateFindingsUseCase, Depends(get_correlate_findings_use_case)
]


def get_list_project_risks_use_case(
    correlate: CorrelateFindingsUseCaseDep,
    normalization_runs: NormalizationRunRepositoryDep,
) -> ListProjectRisksUseCase:
    return ListProjectRisksUseCase(correlate=correlate, normalization_runs=normalization_runs)


ListProjectRisksUseCaseDep = Annotated[
    ListProjectRisksUseCase, Depends(get_list_project_risks_use_case)
]


# `correlation`'s first PUBLISHED port and `risk_engine`'s first factory (M6.2, ADR-0005
# decision 2). Neither is @lru_cache'd: both reach DbSessionDep through the use case they
# depend on, so caching either would leak a stale session across requests (rule 15).
#
# This factory is also the ONLY place `mypy --strict` checks CorrelationCandidateRisks
# against CandidateRiskPort — the reason given above `get_finding_repository`, and the
# reason this is wired now rather than at M6.3: without a port-annotated return type
# somewhere, the Protocol conformance is unverified no matter how many tests pass.
def get_candidate_risk_port(correlate: CorrelateFindingsUseCaseDep) -> CandidateRiskPort:
    return CorrelationCandidateRisks(correlate)


CandidateRiskPortDep = Annotated[CandidateRiskPort, Depends(get_candidate_risk_port)]


# Consumed by `get_list_scored_risks_use_case` below, which M6.3's route consumes. Until
# that route shipped this factory had no consumer at all and was wired so the conformance
# site above would exist alongside the code it checks; that is no longer the reason it is
# here. ADR-0005 decision 3 still has this use case persist nothing, so ~~there is no worker
# path — the only caller is the read surface~~ *(struck 2026-09-21, M8.6 commit 3: there is now
# a worker path. `platform/worker.py`'s `generate_brief` builds this use case per job, beneath
# `ScoredExplainableRisks`, to narrate a Brief off the request path — ADR-0038 decision 9. What
# survives is the persistence clause: it still persists nothing, which is why the worker
# recomputes the project's whole scored set on every job — **G61**.)*
def get_compute_risk_use_case(
    candidate_risks: CandidateRiskPortDep, findings: FindingRepositoryDep
) -> ComputeRiskUseCase:
    return ComputeRiskUseCase(candidate_risks=candidate_risks, findings=findings)


ComputeRiskUseCaseDep = Annotated[ComputeRiskUseCase, Depends(get_compute_risk_use_case)]


# M6.3's read surface. Request-scoped, so not @lru_cache'd: it reaches `DbSessionDep`
# through both of its dependencies, and caching it would leak a stale session across
# requests (rule 15).
def get_list_scored_risks_use_case(
    compute: ComputeRiskUseCaseDep,
    normalization_runs: NormalizationRunRepositoryDep,
) -> ListScoredRisksUseCase:
    return ListScoredRisksUseCase(compute=compute, normalization_runs=normalization_runs)


ListScoredRisksUseCaseDep = Annotated[
    ListScoredRisksUseCase, Depends(get_list_scored_risks_use_case)
]


# `brief`'s outbound port to an LLM (M7.1, ADR-0032). Not @lru_cache'd, for the reason
# `get_vcs_provider` gives: it takes SettingsDep, which is not hashable.
#
# Wired at M7.1 with no consumer, on M6.2's precedent of wiring a conformance site before its
# consumer. Since M7.2 it is consumed by `get_generate_security_brief_use_case` below, the
# first production caller of `explain`. ~~This return annotation is still the only place
# `mypy --strict` checks OpenAIExplanationProvider against ExplanationProviderPort.~~ *(Struck
# 2026-09-21, M8.6 commit 3: `platform/worker.py`'s `on_startup` now annotates
# `explanations: ExplanationProviderPort = OpenAIExplanationProvider(...)` before putting it in
# `ctx`, which is a second checked site — and the one that matters in the worker process, where
# every `ctx` read is `Any`. The same sentence has a copy in `tests/unit/test_di_wiring.py`,
# struck there too.)*
# That checks SHAPE only: both constructor arguments are `str`, so swapping them type-checks,
# which is why `tests/unit/test_di_wiring.py` sends a request through this factory and
# asserts which value landed in the header and which in the body (G65).
def get_explanation_provider(settings: SettingsDep) -> ExplanationProviderPort:
    return OpenAIExplanationProvider(api_key=settings.openai_api_key, model=settings.openai_model)


ExplanationProviderDep = Annotated[ExplanationProviderPort, Depends(get_explanation_provider)]


# `risk_engine`'s second published port and `brief`'s first use cases (M7.2, ADR-0033). None is
# @lru_cache'd: each reaches DbSessionDep, directly or through what it depends on, and caching
# one would leak a stale session across requests (rule 15).
#
# ~~The port factory's return annotation is the only place `mypy --strict` checks
# ScoredExplainableRisks against ExplainableRiskPort.~~ *(Struck 2026-09-21, M8.6 commit 3:
# `platform/worker.py`'s `generate_brief` passes `ScoredExplainableRisks(...)` into
# `GenerateSecurityBriefUseCase`'s `explainable_risks: ExplainableRiskPort` parameter, a second
# checked site. The clause below about swapped wiring is unaffected and still holds.)*
# Unlike `get_explanation_provider`, no factory below takes two arguments of one type, so a
# swapped wiring fails the type check rather than needing a test to see it.
def get_explainable_risk_port(compute: ComputeRiskUseCaseDep) -> ExplainableRiskPort:
    return ScoredExplainableRisks(compute)


ExplainableRiskPortDep = Annotated[ExplainableRiskPort, Depends(get_explainable_risk_port)]


def get_security_brief_repository(session: DbSessionDep) -> SecurityBriefRepositoryPort:
    return PostgresSecurityBriefRepository(session)


SecurityBriefRepositoryDep = Annotated[
    SecurityBriefRepositoryPort, Depends(get_security_brief_repository)
]


def get_brief_generation_repository(session: DbSessionDep) -> BriefGenerationRepositoryPort:
    return PostgresBriefGenerationRepository(session)


BriefGenerationRepositoryDep = Annotated[
    BriefGenerationRepositoryPort, Depends(get_brief_generation_repository)
]


# M8.6, ADR-0038 decision 3. `get_job_queue`'s shape one module over, and the same reasoning:
# deferred to after the request's commit so a worker never takes a job whose row it cannot see
# (ADR-0035 decision 5). Session-dependent, so never @lru_cache (rule 15).
#
# The wrapper is `brief`'s OWN, not `scanning`'s `AfterCommitJobQueue` — the class is typed to
# one port and one method name, so no module enqueueing anything else can reuse it. Registered
# as **G99**, which also names why this file could have handed the existing class over if the
# types had allowed: no import-linter contract names `verion.platform`.
def get_brief_generation_queue(pool: ArqPoolDep, session: DbSessionDep) -> BriefGenerationQueuePort:
    return AfterCommitBriefGenerationQueue(ArqBriefGenerationQueue(pool), session)


BriefGenerationQueueDep = Annotated[BriefGenerationQueuePort, Depends(get_brief_generation_queue)]


def get_request_security_brief_use_case(
    project_access: ProjectAccessDep,
    generations: BriefGenerationRepositoryDep,
    queue: BriefGenerationQueueDep,
    clock: ClockDep,
    ids: IdGeneratorDep,
) -> RequestSecurityBriefUseCase:
    return RequestSecurityBriefUseCase(
        project_access=project_access,
        generations=generations,
        queue=queue,
        clock=clock,
        ids=ids,
    )


RequestSecurityBriefUseCaseDep = Annotated[
    RequestSecurityBriefUseCase, Depends(get_request_security_brief_use_case)
]


def get_get_brief_generation_use_case(
    project_access: ProjectAccessDep, generations: BriefGenerationRepositoryDep
) -> GetBriefGenerationUseCase:
    return GetBriefGenerationUseCase(project_access=project_access, generations=generations)


GetBriefGenerationUseCaseDep = Annotated[
    GetBriefGenerationUseCase, Depends(get_get_brief_generation_use_case)
]


# **No request builds this use case since M8.6.** The POST answers 202, and
# `platform/worker.py`'s `generate_brief` constructs the whole graph per job from
# `session_factory()` instead.
#
# It stays wired, with no consumer, on `get_explanation_provider`'s precedent above — M6.2's
# rule of wiring a conformance site before its consumer. ~~this factory's return annotation and
# its six port-annotated parameters are the only place `mypy --strict` checks any of that
# graph's conformance at all. The worker assembles it through `ctx` and local variables, where
# `ctx["..."]` arrives as `Any` and nothing is checked.~~
#
# **That was false and the guardian disproved it by mutation**: swapping `briefs=` for the
# wrong repository in `generate_brief` makes `mypy` fail at `worker.py`, because
# `GenerateSecurityBriefUseCase.__init__`'s parameters are port-annotated and the worker calls
# it by keyword with really-typed adapters. **Five of the six are checked there too.** The one
# that is not is `explanations=ctx["explanations"]`, which arrives as `Any` and satisfies its
# annotation vacuously — and `on_startup` annotates it as `ExplanationProviderPort` on
# assignment precisely to cover that one. So what this factory uniquely buys is not the
# conformance check; it is a single site where the whole graph is declared in port terms, which
# is worth keeping and is a smaller claim.
def get_generate_security_brief_use_case(
    explainable_risks: ExplainableRiskPortDep,
    findings: FindingRepositoryDep,
    explanations: ExplanationProviderDep,
    briefs: SecurityBriefRepositoryDep,
    clock: ClockDep,
    ids: IdGeneratorDep,
) -> GenerateSecurityBriefUseCase:
    return GenerateSecurityBriefUseCase(
        explainable_risks=explainable_risks,
        findings=findings,
        explanations=explanations,
        briefs=briefs,
        clock=clock,
        ids=ids,
    )


GenerateSecurityBriefUseCaseDep = Annotated[
    GenerateSecurityBriefUseCase, Depends(get_generate_security_brief_use_case)
]


def get_list_security_briefs_use_case(
    project_access: ProjectAccessDep, briefs: SecurityBriefRepositoryDep
) -> ListSecurityBriefsUseCase:
    return ListSecurityBriefsUseCase(project_access=project_access, briefs=briefs)


ListSecurityBriefsUseCaseDep = Annotated[
    ListSecurityBriefsUseCase, Depends(get_list_security_briefs_use_case)
]


# `history`'s first factories (M8.1, ADR-0036). None is @lru_cache'd: each reaches DbSessionDep,
# directly or through what it depends on (rule 15). Dismissal reuses `ExplainableRiskPortDep`,
# so it validates through the same real `ScoredExplainableRisks` that Brief generation does.
def get_risk_dismissal_repository(session: DbSessionDep) -> RiskDismissalRepositoryPort:
    return PostgresRiskDismissalRepository(session)


RiskDismissalRepositoryDep = Annotated[
    RiskDismissalRepositoryPort, Depends(get_risk_dismissal_repository)
]


def get_dismiss_risk_use_case(
    explainable_risks: ExplainableRiskPortDep,
    dismissals: RiskDismissalRepositoryDep,
    clock: ClockDep,
    ids: IdGeneratorDep,
) -> DismissRiskUseCase:
    return DismissRiskUseCase(
        explainable_risks=explainable_risks, dismissals=dismissals, clock=clock, ids=ids
    )


DismissRiskUseCaseDep = Annotated[DismissRiskUseCase, Depends(get_dismiss_risk_use_case)]


def get_undismiss_risk_use_case(
    project_access: ProjectAccessDep,
    dismissals: RiskDismissalRepositoryDep,
    clock: ClockDep,
    ids: IdGeneratorDep,
) -> UndismissRiskUseCase:
    return UndismissRiskUseCase(
        project_access=project_access, dismissals=dismissals, clock=clock, ids=ids
    )


UndismissRiskUseCaseDep = Annotated[UndismissRiskUseCase, Depends(get_undismiss_risk_use_case)]


def get_list_risk_dismissals_use_case(
    project_access: ProjectAccessDep, dismissals: RiskDismissalRepositoryDep
) -> ListRiskDismissalsUseCase:
    return ListRiskDismissalsUseCase(project_access=project_access, dismissals=dismissals)


ListRiskDismissalsUseCaseDep = Annotated[
    ListRiskDismissalsUseCase, Depends(get_list_risk_dismissals_use_case)
]
