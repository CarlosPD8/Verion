from dataclasses import dataclass

from verion.modules.history.domain.exceptions import RiskDismissalAccessDenied
from verion.modules.history.domain.risk import RiskDismissal
from verion.modules.history.ports.risk_dismissal_repository import RiskDismissalRepositoryPort

# `projects`' verdict port, never its persistence ports (ADR-0022 decision 2).
from verion.modules.projects.ports.project_access import ProjectAccessPort

# M4.5's values, declared here rather than imported from another module's `application/`,
# which would pass `lint-imports` green and violate rule 3 (**G35**). The same choice
# `ListSecurityBriefsUseCase` made.
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


@dataclass(frozen=True)
class ProjectRiskDismissals:
    """One page of a project's dismissal records.

    In `application/` because `limit`, `offset` and `total` describe how the question was asked,
    not facts about dismissals (ADR-0022 decision 1's criterion). No completeness envelope: every
    record exists because a request wrote it, so the list owes nothing to a pipeline.
    """

    items: list[RiskDismissal]
    total: int
    limit: int
    offset: int


class ListRiskDismissalsUseCase:
    """A project's dismissal records, newest first, with each one's latest event. ADR-0036.

    **The mitigation for member-level dismissal** (decision 10): every record is listed to every
    member, the owner included. While a record is dismissed, it shows who dismissed it, why and
    when. It lists records, not current surfaces: showing a ranked Risk as dismissed is M8.2's
    overlay.
    """

    def __init__(
        self, project_access: ProjectAccessPort, dismissals: RiskDismissalRepositoryPort
    ) -> None:
        self._project_access = project_access
        self._dismissals = dismissals

    async def execute(
        self,
        *,
        project_id: str,
        user_id: str,
        limit: int = DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> ProjectRiskDismissals:
        # Before any read, so a refused caller learns nothing from what the repository does.
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise RiskDismissalAccessDenied(f"No readable project with id '{project_id}'")

        return ProjectRiskDismissals(
            items=await self._dismissals.list_for_project(
                project_id=project_id, limit=limit, offset=offset
            ),
            total=await self._dismissals.count_for_project(project_id),
            limit=limit,
            offset=offset,
        )
