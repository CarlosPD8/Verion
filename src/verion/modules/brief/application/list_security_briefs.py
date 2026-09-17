from dataclasses import dataclass

from verion.modules.brief.domain.exceptions import SecurityBriefAccessDenied
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.brief.ports.security_brief_repository import SecurityBriefRepositoryPort

# `projects`' verdict port, never its persistence ports (ADR-0022 decision 2).
from verion.modules.projects.ports.project_access import ProjectAccessPort

# M4.5's values, declared here rather than imported from another module's `application/`,
# which would pass `lint-imports` green and violate rule 3 (**G35**). The same choice
# `ListProjectRisksUseCase` and `ListScoredRisksUseCase` made.
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


@dataclass(frozen=True)
class ProjectSecurityBriefs:
    """One page of a project's Briefs.

    In `application/` because `limit`, `offset` and `total` describe how the question was asked,
    not facts about Briefs (ADR-0022 decision 1's criterion).

    **No completeness envelope** (ADR-0033 decision 4). The envelope answers whether a list may
    be missing items a pipeline owes, and no pipeline owes a Brief: every row exists because a
    request wrote it. Whether a Brief's decision was computed over complete findings is a
    per-row, historical question that a live envelope cannot answer (**G76**).
    """

    items: list[SecurityBrief]
    total: int
    limit: int
    offset: int


class ListSecurityBriefsUseCase:
    """A project's Briefs, newest first, for a caller allowed to read the project. M7.2.

    **Consumes `ProjectAccessPort` directly**, unlike generation, which inherits the verdict
    through `ExplainableRiskPort`. This reads only `brief`'s own table, so no path already
    reaches the verdict for ADR-0030 decision 1's *"second copy of one authorization rule"*
    to describe.

    A client joins the items against `/scored-risks` on `finding_ids`: the first item whose
    set equals a surface's is that surface's current Brief, and later ones are history
    (ADR-0033 decision 3).
    """

    def __init__(
        self, project_access: ProjectAccessPort, briefs: SecurityBriefRepositoryPort
    ) -> None:
        self._project_access = project_access
        self._briefs = briefs

    async def execute(
        self,
        *,
        project_id: str,
        user_id: str,
        limit: int = DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> ProjectSecurityBriefs:
        # Before any read, so a refused caller learns nothing from what the repository does.
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise SecurityBriefAccessDenied(f"No readable project with id '{project_id}'")

        return ProjectSecurityBriefs(
            items=await self._briefs.list_for_project(
                project_id=project_id, limit=limit, offset=offset
            ),
            total=await self._briefs.count_for_project(project_id),
            limit=limit,
            offset=offset,
        )
