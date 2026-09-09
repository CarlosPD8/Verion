from verion.modules.projects.domain.authorization import require_member
from verion.modules.projects.domain.exceptions import ProjectNotFound, ServingDeclarationNotFound
from verion.modules.projects.domain.serving_declaration import (
    ServingDeclaration,
    declaration_in_force,
)
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.scanner_config_repository import ScannerConfigRepositoryPort
from verion.modules.projects.ports.serving_declaration_repository import (
    ServingDeclarationRepositoryPort,
)


class GetServingDeclarationUseCase:
    """Read a project's declaration and whether it is still in force.

    Member-level, matching `GetSecurityContextUseCase`: this module's uniform split is
    that writes require OWNER and reads require membership.

    **Returns the verdict alongside the stored values, never instead of them**, which is
    `ScannerConfigResponse`'s decision applied one entity over and for its reason: an
    owner whose declaration has gone out of force needs to see both that it has and what
    it was declared against, or the false verdict reads as a bug. It also means the
    caller never has to re-derive the comparison — reimplementing it on the far side of
    an API is the same failure `ServingDeclarationRepositoryPort`'s docstring rules out
    one boundary over.

    **This is `projects` publishing its own answer, not ADR-0028 decision 4's
    cross-module port.** That one ships at M5.6 with its consumer; **G48** is the entry
    that keeps the gap visible.
    """

    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        serving_declarations: ServingDeclarationRepositoryPort,
        scanner_configs: ScannerConfigRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._serving_declarations = serving_declarations
        self._scanner_configs = scanner_configs
        self._connected_repos = connected_repos

    async def execute(self, project_id: str, user_id: str) -> tuple[ServingDeclaration, bool]:
        """Authorize, then read. Raises when nothing was ever declared.

        A never-declared project raises rather than returning a null row with
        `in_force=False`, on `GetSecurityContextUseCase`'s precedent: this module answers
        404 for a sub-resource that does not exist, and the two states are worth telling
        apart. "Nobody has declared anything" and "somebody declared something that has
        since gone stale" call for different acts by the owner.

        The verdict is `declaration_in_force`'s, computed against the configuration as it
        is at read time. Nothing is persisted here and no value is cached — ADR-0028
        decision 2's rule is read-time by construction, which is what lets the same row
        answer differently on two reads with no write between them.
        """
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_member(membership)

        declaration = await self._serving_declarations.get_by_project_id(project_id)
        if declaration is None:
            raise ServingDeclarationNotFound(f"No serving declaration for project '{project_id}'")

        scanner_config = await self._scanner_configs.get_by_project_id(project_id)
        connected_repo = await self._connected_repos.get_by_project_id(project_id)

        return declaration, declaration_in_force(
            declaration=declaration,
            scanner_config=scanner_config,
            connected_repo=connected_repo,
        )
