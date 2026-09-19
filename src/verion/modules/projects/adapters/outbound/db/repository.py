from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from verion.modules.projects.adapters.outbound.db.models import (
    ConnectedRepoModel,
    ProjectMembershipModel,
    ProjectModel,
    RouteMapModel,
    ScannerConfigModel,
    SecurityContextModel,
    ServingDeclarationModel,
)
from verion.modules.projects.domain.authorization import may_manage, may_read
from verion.modules.projects.domain.exceptions import SecurityContextNotFound
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.route_extraction import (
    RouteMap,
    RouteSpan,
    UnreadTree,
    UnresolvedRoute,
)
from verion.modules.projects.domain.route_map_record import RouteMapRecord
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.domain.serving_declaration import (
    ServingDeclaration,
    declaration_in_force,
)
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

    Reads the membership and hands the decision to `may_read` or `may_manage`,
    rather than deciding here. The extra hop is the point: the rules live in
    `domain/authorization.py` and this adapter only fetches what they need, so a
    VIEWER role would change one function and not this file.

    One statement per verdict, served by the composite primary key. It does not check that the
    project row exists, and does not need to: a membership is created with the
    project (`CreateProjectUseCase`), so a membership implies one, and the port
    deliberately cannot report the difference anyway.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        return may_read(await self._membership(project_id=project_id, user_id=user_id))

    async def may_manage_project(self, *, project_id: str, user_id: str) -> bool:
        return may_manage(await self._membership(project_id=project_id, user_id=user_id))

    async def _membership(self, *, project_id: str, user_id: str) -> ProjectMembership | None:
        model = await self._session.get(ProjectMembershipModel, (project_id, user_id))
        return _membership_to_domain(model) if model is not None else None


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


class PostgresServingDeclarationVerdictReader:
    """`ServingDeclarationPort` — fetches what `declaration_in_force` needs and asks it.

    `PostgresProjectAccessReader`'s shape: this adapter only reads, and the rule stays the
    domain function ADR-0028 decision 2 makes the single evaluation site. It composes the
    three repositories above rather than re-querying, so the row-to-entity mapping has one
    copy and ADR-0028's verbatim comparison meets exactly the strings those adapters return.

    **The declaration is read first and a missing one short-circuits**, before either live
    row is touched. That is not only a saved query. `PostgresConnectedRepoRepository.
    get_by_project_id` raises on a project holding two connected repositories (**G51**), and
    this adapter sits on `GET /projects/{id}/risks`, a member-level read — so reading the
    repository row first would turn that exposure into a failing dashboard for every such
    project. With the short-circuit it reaches only projects that have declared, which the
    declare path could not have written while two repositories existed.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def url_serves_scanned_tree(self, *, project_id: str) -> bool:
        declaration = await PostgresServingDeclarationRepository(self._session).get_by_project_id(
            project_id
        )
        if declaration is None:
            return False
        return declaration_in_force(
            declaration=declaration,
            scanner_config=await PostgresScannerConfigRepository(self._session).get_by_project_id(
                project_id
            ),
            connected_repo=await PostgresConnectedRepoRepository(self._session).get_by_project_id(
                project_id
            ),
        )


def _json_str(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("A route_maps row holds a non-string where a string belongs")
    return value


def _json_int(value: object) -> int:
    # `bool` is an `int` subclass, and JSON `true` would otherwise pass as line 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("A route_maps row holds a non-integer where a line number belongs")
    return value


def _route_map_record_to_domain(model: RouteMapModel) -> RouteMapRecord:
    """Parse the JSONB back into domain types, and RAISE on a malformed element.

    The database does not type a span's fields, so this is where a bad row is caught — the
    `ScannerTool(name)` parse-back precedent in `_scanner_config_to_domain`. Raising rather
    than skipping is ADR-0021 decision 4's other side: a stored row is state this project
    wrote and controls, not upstream data, so a malformed one is a defect to surface.
    """
    return RouteMapRecord(
        id=model.id,
        project_id=model.project_id,
        framework=model.framework,
        source_archive_commit_sha=model.source_archive_commit_sha,
        derived_at=model.derived_at,
        route_map=RouteMap(
            routes=tuple(
                RouteSpan(
                    path=_json_str(route["path"]),
                    file_path=_json_str(route["file_path"]),
                    start_line=_json_int(route["start_line"]),
                    end_line=_json_int(route["end_line"]),
                )
                for route in model.routes
            ),
            unparsed_files=tuple(model.unparsed_files),
            unresolved_routes=tuple(
                UnresolvedRoute(
                    file_path=_json_str(route["file_path"]),
                    function_name=_json_str(route["function_name"]),
                    decorator_line=_json_int(route["decorator_line"]),
                )
                for route in model.unresolved_routes
            ),
            unread_tree=UnreadTree(model.unread_tree) if model.unread_tree is not None else None,
        ),
    )


def _routes_to_json(route_map: RouteMap) -> list[dict[str, str | int]]:
    return [
        {
            "path": route.path,
            "file_path": route.file_path,
            "start_line": route.start_line,
            "end_line": route.end_line,
        }
        for route in route_map.routes
    ]


def _unresolved_routes_to_json(route_map: RouteMap) -> list[dict[str, str | int]]:
    return [
        {
            "file_path": route.file_path,
            "function_name": route.function_name,
            "decorator_line": route.decorator_line,
        }
        for route in route_map.unresolved_routes
    ]


class PostgresRouteMapRepository:
    """`RouteMapRepositoryPort` over `route_maps`. One row per project. M5.6 commit 4.

    **Effectively written once per project today, because of G55 and not because of anything
    here.** `upsert` replaces a map faithfully. But the only writer is Security Context build,
    and a second build also writes a duplicate `security_contexts` row, after which that
    project's context reads raise. So a map cannot be refreshed without breaking the project,
    and a stored `UnreadTree` failure is in practice permanent.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_project_id(self, project_id: str) -> RouteMapRecord | None:
        result = await self._session.execute(
            select(RouteMapModel).where(RouteMapModel.project_id == project_id)
        )
        model = result.scalar_one_or_none()
        return _route_map_record_to_domain(model) if model is not None else None

    async def upsert(self, record: RouteMapRecord) -> None:
        # ON CONFLICT DO UPDATE on the project_id constraint, the ServingDeclaration idiom.
        # **Every column but `id` and `project_id` moves in `set_`, none conditionally**: the map
        # is a snapshot of one tree, and keeping any column from the previous row would pair
        # an old tree's value with a new one's — the SHA with the wrong routes, say. `id` stays,
        # as it does for the two upserts above, so the row keeps a stable identity.
        routes = _routes_to_json(record.route_map)
        unresolved_routes = _unresolved_routes_to_json(record.route_map)
        unparsed_files = list(record.route_map.unparsed_files)
        unread_tree = (
            str(record.route_map.unread_tree) if record.route_map.unread_tree is not None else None
        )
        statement = (
            insert(RouteMapModel)
            .values(
                id=record.id,
                project_id=record.project_id,
                framework=record.framework,
                source_archive_commit_sha=record.source_archive_commit_sha,
                unread_tree=unread_tree,
                routes=routes,
                unresolved_routes=unresolved_routes,
                unparsed_files=unparsed_files,
                derived_at=record.derived_at,
            )
            .on_conflict_do_update(
                constraint="uq_route_maps_project_id",
                set_={
                    "framework": record.framework,
                    "source_archive_commit_sha": record.source_archive_commit_sha,
                    "unread_tree": unread_tree,
                    "routes": routes,
                    "unresolved_routes": unresolved_routes,
                    "unparsed_files": unparsed_files,
                    "derived_at": record.derived_at,
                },
            )
        )
        await self._session.execute(statement)
        await self._session.flush()


class PostgresRouteMapReader:
    """`RouteMapPort` — the stored map, or `NOT_BUILT` for a project that has none. M5.6 commit 4.

    `PostgresServingDeclarationVerdictReader`'s shape: it composes the repository above rather
    than re-querying, so the JSONB parse-back has one copy.

    **A missing row answers `RouteMap.not_read(UnreadTree.NOT_BUILT)`, not a raise and not a
    plain empty map.** Not a raise, because this sits on `GET /projects/{id}/risks`, a
    member-level read, and every project detected before this commit has no row. Not a plain
    empty map, because that would read as "built, and no routes" — the ambiguity the residue
    fields exist to refuse.

    **Every project that ran detect before this commit reads `NOT_BUILT` indefinitely**, because
    obtaining a map needs a second detect, and G55 makes that break its context reads.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def route_map_for(self, *, project_id: str) -> RouteMap:
        record = await PostgresRouteMapRepository(self._session).get_by_project_id(project_id)
        if record is None:
            return RouteMap.not_read(UnreadTree.NOT_BUILT)
        return record.route_map
