from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from verion.modules.correlation.adapters.inbound.api.schemas import (
    MatchKeyResponse,
    NormalizationRunResponse,
    NormalizationStateResponse,
    ProjectRisksResponse,
    RiskResponse,
)
from verion.modules.correlation.application.list_project_risks import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    ProjectRisks,
)
from verion.modules.correlation.domain.exceptions import ProjectAccessDenied
from verion.platform.di import CurrentUserIdDep, ListProjectRisksUseCaseDep

router = APIRouter()


def _risks_response(risks: ProjectRisks) -> ProjectRisksResponse:
    latest = risks.latest_run
    return ProjectRisksResponse(
        items=[
            RiskResponse(
                match=MatchKeyResponse(package=group.key.package, url=group.key.url),
                finding_ids=list(group.finding_ids),
                finding_count=len(group.finding_ids),
            )
            for group in risks.items
        ],
        total=risks.total,
        limit=risks.limit,
        offset=risks.offset,
        normalization=NormalizationStateResponse(
            latest_run=None
            if latest is None
            else NormalizationRunResponse(
                scan_id=latest.scan_id,
                status=latest.status,
                requested_at=latest.requested_at,
                started_at=latest.started_at,
                finished_at=latest.finished_at,
                failure_reason=latest.failure_reason,
            ),
            unfinished_runs=risks.unfinished_runs,
        ),
    )


@router.get(
    "/{project_id}/risks",
    status_code=status.HTTP_200_OK,
    response_model=ProjectRisksResponse,
)
async def list_project_risks(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: ListProjectRisksUseCaseDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectRisksResponse:
    """A project's candidate Risks: findings grouped by what they share.

    Each item carries its constituent `finding_ids` and nothing about the findings themselves;
    fetch those from `GET /projects/{project_id}/findings` and its evidence route.

    **A Risk here is a candidate and is unscored** — no priority, no confidence, no reasoning,
    and no claim that any of it is resolved. It is also not stored, so it carries no id and no
    item is addressable on its own; ADR-0025 decisions 1 and 5.

    Ordered deterministically, and that order is **not** a ranking.
    """
    try:
        risks = await use_case.execute(
            project_id=project_id, user_id=user_id, limit=limit, offset=offset
        )
    except ProjectAccessDenied as exc:
        # 404 for both denials, inherited from ADR-0022 decision 2 rather than re-decided.
        # Widens G17 by one route; the convergence is G18's at M10.2.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return _risks_response(risks)
