from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.projects.adapters.outbound.db.models import (
    ConnectedRepoModel,
    ProjectMembershipModel,
    ProjectModel,
    ScannerConfigModel,
    SecurityContextModel,
    ServingDeclarationModel,
)
from verion.modules.projects.domain.authorization import may_read
from verion.modules.projects.domain.exceptions import SecurityContextNotFound
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.domain.serving_declaration import ServingDeclaration
from verion.shared_kernel.scanner_tools import ScannerTool


def _project_to_domain(model: ProjectModel) -> Project:
    return Project(
        id=model.id, owner_id=model.owner_id, name=model.name, created_at=model.created_at
    )


def _project_from_domain(project: Project) -> ProjectModel:
    return ProjectModel(
        id=project.id,
        owner_id=project.owner_id,
        name=project.name,
        created_at=project.created_at,
    )


def _connected_repo_to_domain(model: ConnectedRepoModel) -> ConnectedRepo:
    return ConnectedRepo(
        id=model.id,
        project_id=model.project_id,
        provider=model.provider,
        url=model.url,
        default_branch=model.default_branch,
    )


def _connected_repo_from_domain(connected_repo: ConnectedRepo) -> ConnectedRepoModel:
    return ConnectedRepoModel(
        id=connected_repo.id,
        project_id=connected_repo.project_id,
        provider=connected_repo.provider,
        url=connected_repo.url,
        default_branch=connected_repo.default_branch,
    )


def _membership_to_domain(model: ProjectMembershipModel) -> ProjectMembership:
    return ProjectMembership(
        project_id=model.project_id, user_id=model.user_id, role=Role(model.role)
    )


def _membership_from_domain(membership: ProjectMembership) -> ProjectMembershipModel:
    return ProjectMembershipModel(
        project_id=membership.project_id,
        user_id=membership.user_id,
        role=str(membership.role),
    )


def _security_context_to_domain(model: SecurityContextModel) -> SecurityContext:
    return SecurityContext(
        id=model.id,
        project_id=model.project_id,
        language=model.language,
        framework=model.framework,
        database=model.database,
        deployment_target=model.deployment_target,
        ci_provider=model.ci_provider,
        exposure_tags=list(model.exposure_tags),
        created_at=model.created_at,
    )


def _security_context_from_domain(context: SecurityContext) -> SecurityContextModel:
    return SecurityContextModel(
        id=context.id,
        project_id=context.project_id,
        language=context.language,
        framework=context.framework,
        database=context.database,
        deployment_target=context.deployment_target,
        ci_provider=context.ci_provider,
        exposure_tags=list(context.exposure_tags),
        created_at=context.created_at,
    )


class PostgresProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, project: Project) -> None:
        self._session.add(_project_from_domain(project))
        await self._session.flush()

    async def get_by_id(self, project_id: str) -> Project | None:
        model = await self._session.get(ProjectModel, project_id)
        return _project_to_domain(model) if model is not None else None


class PostgresConnectedRepoRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, connected_repo: ConnectedRepo) -> None:
        self._session.add(_connected_repo_from_domain(connected_repo))
        await self._session.flush()

    async def get_by_id(self, connected_repo_id: str) -> ConnectedRepo | None:
        model = await self._session.get(ConnectedRepoModel, connected_repo_id)
        return _connected_repo_to_domain(model) if model is not None else None

    async def get_by_project_id(self, project_id: str) -> ConnectedRepo | None:
        result = await self._session.execute(
            select(ConnectedRepoModel).where(ConnectedRepoModel.project_id == project_id)
        )
        model = result.scalar_one_or_none()
        return _connected_repo_to_domain(model) if model is not None else None

    async def get_by_url(self, url: str) -> ConnectedRepo | None:
        result = await self._session.execute(
            select(ConnectedRepoModel).where(ConnectedRepoModel.url == url)
        )
        model = result.scalar_one_or_none()
        return _connected_repo_to_domain(model) if model is not None else None


class PostgresProjectMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, membership: ProjectMembership) -> None:
        self._session.add(_membership_from_domain(membership))
        await self._session.flush()

    async def get_by_project_and_user(
        self, project_id: str, user_id: str
    ) -> ProjectMembership | None:
        model = await self._session.get(ProjectMembershipModel, (project_id, user_id))
        return _membership_to_domain(model) if model is not None else None


class PostgresProjectAccessReader:
    """`ProjectAccessPort` over `project_memberships`. See that port's docstring.

    Reads the membership and hands the decision to `may_read`, rather than
    returning `model is not None` directly. The extra hop is the point: the rule
    lives in `domain/authorization.py` and this adapter only fetches what the rule
    needs, so a VIEWER role would change one function and not this file.

    One statement, served by the composite primary key. It does not check that the
    project row exists, and does not need to: a membership is created with the
    project (`CreateProjectUseCase`), so a membership implies one, and the port
    deliberately cannot report the difference anyway.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        model = await self._session.get(ProjectMembershipModel, (project_id, user_id))
        return may_read(_membership_to_domain(model) if model is not None else None)


class PostgresSecurityContextRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, context: SecurityContext) -> None:
        self._session.add(_security_context_from_domain(context))
        await self._session.flush()

    async def get_by_project_id(self, project_id: str) -> SecurityContext | None:
        result = await self._session.execute(
            select(SecurityContextModel).where(SecurityContextModel.project_id == project_id)
        )
        model = result.scalar_one_or_none()
        return _security_context_to_domain(model) if model is not None else None

    async def update(self, context: SecurityContext) -> None:
        model = await self._session.get(SecurityContextModel, context.id)
        if model is None:
            # get_by_project_id three methods up already guards its lookup; this
            # one simply missed it. Without the guard a stale id raises an opaque
            # AttributeError instead of the 404 the router already knows how to
            # translate SecurityContextNotFound into.
            raise SecurityContextNotFound(f"No security context with id '{context.id}'")
        model.language = context.language
        model.framework = context.framework
        model.database = context.database
        model.deployment_target = context.deployment_target
        model.ci_provider = context.ci_provider
        model.exposure_tags = list(context.exposure_tags)
        await self._session.flush()


def _scanner_config_to_domain(model: ScannerConfigModel) -> ScannerConfig:
    return ScannerConfig(
        id=model.id,
        project_id=model.project_id,
        # Parsed back into the enum at the boundary, so an unknown name stored
        # by some future hand-edit fails here rather than silently reaching
        # dispatch as a tool nothing answers to.
        enabled_tools=tuple(ScannerTool(name) for name in model.enabled_tools),
        zap_target_url=model.zap_target_url,
        updated_at=model.updated_at,
        active_scan_consent_target=model.active_scan_consent_target,
        active_scan_consent_granted_at=model.active_scan_consent_granted_at,
        active_scan_consent_granted_by=model.active_scan_consent_granted_by,
    )


class PostgresScannerConfigRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_project_id(self, project_id: str) -> ScannerConfig | None:
        result = await self._session.execute(
            select(ScannerConfigModel).where(ScannerConfigModel.project_id == project_id)
        )
        model = result.scalar_one_or_none()
        return _scanner_config_to_domain(model) if model is not None else None

    async def upsert(self, config: ScannerConfig) -> None:
        # ON CONFLICT DO UPDATE on the project_id unique constraint, same idiom
        # as PostgresScanResultRepository.upsert — one row per project, and a
        # caller changing configuration doesn't have to know whether the
        # project has ever been configured before.
        statement = (
            insert(ScannerConfigModel)
            .values(
                id=config.id,
                project_id=config.project_id,
                enabled_tools=[str(tool) for tool in config.enabled_tools],
                zap_target_url=config.zap_target_url,
                updated_at=config.updated_at,
                active_scan_consent_target=config.active_scan_consent_target,
                active_scan_consent_granted_at=config.active_scan_consent_granted_at,
                active_scan_consent_granted_by=config.active_scan_consent_granted_by,
            )
            .on_conflict_do_update(
                constraint="uq_scanner_configs_project_id",
                set_={
                    "enabled_tools": [str(tool) for tool in config.enabled_tools],
                    # Set together with enabled_tools, never independently:
                    # disabling ZAP must not leave its stale target behind.
                    "zap_target_url": config.zap_target_url,
                    "updated_at": config.updated_at,
                    # Written on every upsert, never conditionally: the use case
                    # has already resolved what the three values should be, and
                    # omitting them here would leave a withdrawal unpersisted
                    # while reporting success.
                    "active_scan_consent_target": config.active_scan_consent_target,
                    "active_scan_consent_granted_at": config.active_scan_consent_granted_at,
                    "active_scan_consent_granted_by": config.active_scan_consent_granted_by,
                },
            )
        )
        await self._session.execute(statement)
        await self._session.flush()


def _serving_declaration_to_domain(model: ServingDeclarationModel) -> ServingDeclaration:
    return ServingDeclaration(
        id=model.id,
        project_id=model.project_id,
        declared_target_url=model.declared_target_url,
        declared_repo_url=model.declared_repo_url,
        declared_default_branch=model.declared_default_branch,
        declared_at=model.declared_at,
        declared_by=model.declared_by,
    )


class PostgresServingDeclarationRepository:
    """`ServingDeclarationRepositoryPort` over `serving_declarations`.

    No mapping of values in either direction beyond the field copy: ADR-0028
    decision 2 compares the stored strings verbatim, so anything this adapter
    normalized on the way in or out would be a second place for the two sides to
    disagree — the exact failure that decision's non-normalization rules out.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_project_id(self, project_id: str) -> ServingDeclaration | None:
        result = await self._session.execute(
            select(ServingDeclarationModel).where(ServingDeclarationModel.project_id == project_id)
        )
        model = result.scalar_one_or_none()
        return _serving_declaration_to_domain(model) if model is not None else None

    async def upsert(self, declaration: ServingDeclaration) -> None:
        # ON CONFLICT DO UPDATE on the project_id unique constraint, the same idiom
        # as PostgresScannerConfigRepository.upsert above. All FIVE columns in
        # `set_` move together and none conditionally: a re-declaration replaces the
        # whole claim, and leaving one of the three declared values behind would
        # produce a row asserting a pair nobody ever declared.
        #
        # `id` is deliberately NOT in `set_`, so the row keeps its original identity
        # across re-declarations even though the caller mints a fresh
        # IdGeneratorPort.new_id() for each. The same is true of
        # PostgresScannerConfigRepository.upsert above. It is the right way round:
        # `project_id` is the conflict key and there is one row per project, so a
        # stable surrogate is what anything that ever references this row would
        # want, and a caller cannot learn the winning id from a `-> None` method in
        # any case. Pinned by test_re_declaring_replaces_the_row_but_keeps_its_id.
        statement = (
            insert(ServingDeclarationModel)
            .values(
                id=declaration.id,
                project_id=declaration.project_id,
                declared_target_url=declaration.declared_target_url,
                declared_repo_url=declaration.declared_repo_url,
                declared_default_branch=declaration.declared_default_branch,
                declared_at=declaration.declared_at,
                declared_by=declaration.declared_by,
            )
            .on_conflict_do_update(
                constraint="uq_serving_declarations_project_id",
                set_={
                    "declared_target_url": declaration.declared_target_url,
                    "declared_repo_url": declaration.declared_repo_url,
                    "declared_default_branch": declaration.declared_default_branch,
                    # Refreshed on every re-declaration, both of them: a new claim
                    # is a new assertion by a person at a time, and carrying the
                    # first declaration's author and timestamp forward would
                    # attribute the current claim to somebody who did not make it.
                    "declared_at": declaration.declared_at,
                    "declared_by": declaration.declared_by,
                },
            )
        )
        await self._session.execute(statement)
        await self._session.flush()
