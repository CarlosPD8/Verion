from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.exceptions import InvalidScannerConfig, ProjectNotFound
from verion.modules.projects.domain.scanner_config import (
    ScannerConfig,
    parse_enabled_tools,
    validate_zap_target_url,
)
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.scanner_config_repository import ScannerConfigRepositoryPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort
from verion.shared_kernel.scanner_tools import ScannerTool


class UpdateScannerConfigUseCase:
    """Owner-gated, matching M2.3's precedent that write actions on project
    data require OWNER while reads are member-level. Enabling a scanner costs
    real compute and can point an attack tool at a URL — squarely a write.
    """

    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        scanner_configs: ScannerConfigRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._scanner_configs = scanner_configs
        self._id_generator = id_generator
        self._clock = clock

    async def execute(
        self,
        project_id: str,
        user_id: str,
        enabled_tools: list[str],
        zap_target_url: str | None,
    ) -> ScannerConfig:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

        tools = parse_enabled_tools(enabled_tools)

        if zap_target_url is not None:
            validate_zap_target_url(zap_target_url)

        # Enabling ZAP without giving it somewhere to point is rejected here
        # rather than discovered at scan time. Dispatch still handles the
        # combination defensively (it surfaces as ZAP's own failure_reason,
        # leaving the other scanners' output intact) — the two are not
        # redundant: this one is feedback, that one is the guarantee that a
        # config written around this use case cannot take a whole scan down.
        if ScannerTool.ZAP in tools and zap_target_url is None:
            raise InvalidScannerConfig("Enabling ZAP requires a zap_target_url")

        existing = await self._scanner_configs.get_by_project_id(project_id)
        config = ScannerConfig(
            # Reuses the existing row's id when there is one: this is one
            # configuration per project being edited, not a new record each
            # time it changes.
            id=existing.id if existing is not None else self._id_generator.new_id(),
            project_id=project_id,
            enabled_tools=tools,
            zap_target_url=zap_target_url,
            updated_at=self._clock.now(),
        )
        await self._scanner_configs.upsert(config)
        return config
