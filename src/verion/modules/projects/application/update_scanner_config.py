from datetime import datetime

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
        active_scan_consent: bool | None = None,
    ) -> ScannerConfig:
        """`active_scan_consent` is tri-state, and that is what makes ADR-0024
        decision 3's rule reachable rather than vacuous.

        `True` grants against the target in *this* request, `False` withdraws, and
        `None` leaves the stored grant untouched — which is the case the rule exists
        for. If every write restated consent, the stored consent target would always
        equal the target written beside it and the comparison could never be false.
        `None` is what lets an owner change `zap_target_url` without re-deciding, and
        decision 3 is what makes that change void the grant instead of carrying it
        across to a host nobody agreed to attack.
        """
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

        # Granting against nothing is rejected rather than accepted and silently
        # inert. Stored with a None target the grant would fail the domain's own
        # in-force check and read as "consent absent", which is the right answer
        # arrived at by a route that tells the owner nothing.
        if active_scan_consent is True and zap_target_url is None:
            raise InvalidScannerConfig("Granting active-scan consent requires a zap_target_url")

        existing = await self._scanner_configs.get_by_project_id(project_id)
        consent_target, consent_granted_at, consent_granted_by = self._resolve_consent(
            active_scan_consent, zap_target_url, user_id, existing
        )
        config = ScannerConfig(
            # Reuses the existing row's id when there is one: this is one
            # configuration per project being edited, not a new record each
            # time it changes.
            id=existing.id if existing is not None else self._id_generator.new_id(),
            project_id=project_id,
            enabled_tools=tools,
            zap_target_url=zap_target_url,
            updated_at=self._clock.now(),
            active_scan_consent_target=consent_target,
            active_scan_consent_granted_at=consent_granted_at,
            active_scan_consent_granted_by=consent_granted_by,
        )
        await self._scanner_configs.upsert(config)
        return config

    def _resolve_consent(
        self,
        active_scan_consent: bool | None,
        zap_target_url: str | None,
        user_id: str,
        existing: ScannerConfig | None,
    ) -> tuple[str | None, datetime | None, str | None]:
        """The three columns' next values. All-None is both "never granted" and
        "withdrawn", which ADR-0024 decision 1 requires them to be — the two states
        are not distinguished anywhere and must not become distinguishable here.

        Carrying the previous grant forward on `None` is not the same as keeping
        consent: the carried target is compared against the new `zap_target_url` by
        `ScannerConfig.active_scan_consent_in_force`, so a write that repoints the
        target leaves the row intact and the verdict false.
        """
        if active_scan_consent is True:
            # The target in THIS request, never `existing`'s: consent is granted
            # against what the owner is looking at as they grant it.
            return zap_target_url, self._clock.now(), user_id
        if active_scan_consent is False or existing is None:
            return None, None, None
        return (
            existing.active_scan_consent_target,
            existing.active_scan_consent_granted_at,
            existing.active_scan_consent_granted_by,
        )
