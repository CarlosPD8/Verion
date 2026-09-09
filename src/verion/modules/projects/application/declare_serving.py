from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    InvalidScannerConfig,
    ProjectNotFound,
    ServingDeclarationMismatch,
)
from verion.modules.projects.domain.scanner_config import validate_zap_target_url
from verion.modules.projects.domain.serving_declaration import (
    ServingDeclaration,
    declaration_in_force,
    validate_declared_repo_url,
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
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class DeclareServingUseCase:
    """Record ADR-0028's claim that the scanned URL serves the scanned tree.

    **Owner-gated (ADR-0028 decision 3)**, on the same M2.3 precedent
    `UpdateScannerConfigUseCase` cites: writes on project data require OWNER while
    reads are member-level. Decision 3 chose owner as the *narrower* of the two roles
    `projects` can express rather than as a match for M5.4's "whoever knows the
    deployment" — **G49** carries what that does not implement.

    **The write is a compare-and-set, not a validation**, and that framing is the whole
    of ADR-0028's 2026-09-09 amendment A: the owner sends three values they were shown,
    and this asserts nothing moved between their read and their write. A declaration
    whose values did not match would be void from birth — an attestation carrying a real
    name and a real timestamp on a claim the system can show was false at the instant it
    was made. A stale row is honest about its staleness; a born-false row is not.

    **What that check does NOT prevent, so nothing here implies it does:** the same
    declaration returning to in force after the target is changed away and back, with
    nobody re-asserting anything. **G50**, and the identical property already ships in
    ADR-0024's consent.
    """

    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        serving_declarations: ServingDeclarationRepositoryPort,
        scanner_configs: ScannerConfigRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._serving_declarations = serving_declarations
        self._scanner_configs = scanner_configs
        self._connected_repos = connected_repos
        self._id_generator = id_generator
        self._clock = clock

    async def execute(
        self,
        project_id: str,
        user_id: str,
        declared_target_url: str,
        declared_repo_url: str,
        declared_default_branch: str,
    ) -> tuple[ServingDeclaration, bool]:
        """Authorize, validate, then compare-and-set. Returns the row and its verdict.

        **Every step below the gate is below it deliberately**, which is
        `UpdateScannerConfigUseCase`'s own ordering property: an unauthorized caller
        learns nothing about their payload, not whether the URLs were well-formed and not
        whether the values were current. Both halves of that are pinned —
        `test_declaring_authorizes_before_it_touches_any_of_the_three_post_gate_ports` for
        the repositories and
        `test_a_member_declaring_a_credentialed_url_is_refused_for_the_membership_not_the_url`
        for the validators, the second because moving a validator above the gate is
        otherwise invisible to every test in the suite.

        **Both validators run before the match check**, and the ordering is one of two
        independent protections rather than the only one. They are the rule-12 branches
        that refuse `user:pass@host`, and a mismatch reported first could otherwise be the
        thing that surfaces for a credential-bearing URL. The second protection is
        structural and does not depend on this order: **no message raised on this path
        interpolates a declared value.** `validate_declared_repo_url` exists because
        `ConnectedRepo.url` is stored completely unvalidated (`ConnectRepositoryUseCase`
        takes a `str` and constructs the entity with no parse) and this row's value is
        returned to any member, which is a wider audience than that field otherwise
        reaches.

        **The verdict comes from `declaration_in_force` rather than from three
        comparisons written again here**, so that function stays what its own docstring
        calls it — the single place ADR-0028 decision 2's rule is evaluated. The two
        absences it folds into `False` are separated first, because "you have not
        connected a repository" and "your values are stale" are different answers and
        that function cannot tell them apart by design.
        """
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

        validate_zap_target_url(declared_target_url)
        validate_declared_repo_url(declared_repo_url)

        connected_repo = await self._connected_repos.get_by_project_id(project_id)
        if connected_repo is None:
            raise ConnectedRepoNotFound(
                f"Project '{project_id}' has no connected repository to declare against"
            )

        scanner_config = await self._scanner_configs.get_by_project_id(project_id)
        if scanner_config is None or scanner_config.zap_target_url is None:
            # The same shape as M5.4's "Granting active-scan consent requires a
            # zap_target_url": a declaration against nothing would be stored, be
            # immediately void, and read as "never declared" — the right answer
            # arrived at by a route that tells the owner nothing.
            raise InvalidScannerConfig(
                "Declaring that a URL serves this tree requires a configured zap_target_url"
            )

        candidate = ServingDeclaration(
            id=self._id_generator.new_id(),
            project_id=project_id,
            declared_target_url=declared_target_url,
            declared_repo_url=declared_repo_url,
            declared_default_branch=declared_default_branch,
            declared_at=self._clock.now(),
            declared_by=user_id,
        )

        in_force = declaration_in_force(
            declaration=candidate,
            scanner_config=scanner_config,
            connected_repo=connected_repo,
        )
        if not in_force:
            # Quotes nothing the caller sent. The owner can read the current values
            # from the scanner-config and repository resources they already have.
            raise ServingDeclarationMismatch(
                "The declared values are not this project's current configuration. "
                "Re-read the scanner config and the connected repository, then declare again"
            )

        await self._serving_declarations.upsert(candidate)
        return candidate, in_force
