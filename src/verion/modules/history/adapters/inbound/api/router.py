from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Query, status
from fastapi.responses import JSONResponse

from verion.modules.history.adapters.inbound.api.schemas import (
    DismissRiskRequest,
    ProjectRiskDismissalsResponse,
    RiskAlreadyDismissedResponse,
    RiskDismissalResponse,
    UndoRiskDismissalRequest,
)
from verion.modules.history.application.list_risk_dismissals import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
)
from verion.modules.history.domain.exceptions import (
    RiskAlreadyDismissed,
    RiskDismissalAccessDenied,
    RiskDismissalNotFound,
    RiskEventConflict,
    RiskNotDismissed,
)
from verion.modules.history.domain.risk import RiskDismissal

# `risk_engine`'s PORT module, never its domain: the denials are declared there so this route
# can catch them by type.
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)
from verion.platform.di import (
    CurrentUserIdDep,
    DismissRiskUseCaseDep,
    ListRiskDismissalsUseCaseDep,
    UndismissRiskUseCaseDep,
)

router = APIRouter()

# Fixed details for every failure whose message is not built from the caller's own path ids.
_NO_CURRENT_RISK = (
    "No current Risk in this project has exactly these findings. Re-read the scored Risks."
)
_INCONSISTENT = "This project's Risks could not be scored consistently."
_NOT_DISMISSED = "This dismissal is already undone."
_CONFLICT = "This dismissal changed during the request. Re-read it."


def _dismissal_response(dismissal: RiskDismissal) -> RiskDismissalResponse:
    return RiskDismissalResponse(
        id=dismissal.risk.id,
        finding_ids=list(dismissal.risk.finding_ids),
        state=str(dismissal.state),
        reason=dismissal.latest.reason,
        actor_user_id=dismissal.latest.actor_user_id,
        occurred_at=dismissal.latest.occurred_at,
    )


@router.post(
    "/{project_id}/risk-dismissals",
    status_code=status.HTTP_201_CREATED,
    response_model=RiskDismissalResponse,
    responses={status.HTTP_409_CONFLICT: {"model": RiskAlreadyDismissedResponse}},
)
async def dismiss_risk(
    project_id: str,
    body: DismissRiskRequest,
    user_id: CurrentUserIdDep,
    use_case: DismissRiskUseCaseDep,
) -> RiskDismissalResponse | JSONResponse:
    """Dismiss the current Risk whose members are exactly `finding_ids`, with a reason.

    **The set selects; it does not address.** If findings joined or left the surface since the
    caller read `/scored-risks`, this answers 404 and writes nothing. What is stored is the
    surface's own sorted ids, as the engine scored them (ADR-0036 decision 1).

    **Member-level**, inherited from the read verdict through `risk_engine`'s port, as Brief
    generation is. That coincides with owner-gating today only because nothing creates a
    non-owner membership (**G75**). Every record is listed to every member, and while it is
    dismissed it shows who dismissed it, why and when.

    **409 when an active dismissal already covers this surface**, naming it in
    `covering_dismissal_id`, so the client can find the record to undo (decision 11).
    """
    try:
        dismissal = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            finding_ids=tuple(body.finding_ids),
            reason=body.reason,
        )
    except ExplainableRiskAccessDenied as exc:
        # 404 for both denials (ADR-0022 decision 2), inherited through the port. G17.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except NoCurrentRisk as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NO_CURRENT_RISK) from exc
    except ExplainableRiskInconsistent as exc:
        # A broken server-side invariant, never a client error (ADR-0030 decision 5).
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_INCONSISTENT
        ) from exc
    except RiskAlreadyDismissed as exc:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=RiskAlreadyDismissedResponse(
                covering_dismissal_id=exc.covering_dismissal_id
            ).model_dump(),
        )

    return _dismissal_response(dismissal)


@router.post(
    "/{project_id}/risk-dismissals/{dismissal_id}/undo",
    status_code=status.HTTP_201_CREATED,
    response_model=RiskDismissalResponse,
)
async def undo_risk_dismissal(
    project_id: str,
    dismissal_id: str,
    user_id: CurrentUserIdDep,
    use_case: UndismissRiskUseCaseDep,
    body: Annotated[UndoRiskDismissalRequest | None, Body()] = None,
) -> RiskDismissalResponse:
    """Undo a dismissal by appending an `undismissed` event. Nothing is mutated or deleted.

    The body is optional, and so is its `reason`. **Member-level**, the same verdict as
    dismissing (ADR-0036 decision 10). 404 for a project the caller may not read, an absent
    record, or another project's record. 409 when the record is already undone, or a concurrent
    undo appended first.
    """
    try:
        dismissal = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            dismissal_id=dismissal_id,
            reason=None if body is None else body.reason,
        )
    except (RiskDismissalAccessDenied, RiskDismissalNotFound) as exc:
        # Both messages are built from the path's own ids. G17.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RiskNotDismissed as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_NOT_DISMISSED) from exc
    except RiskEventConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_CONFLICT) from exc

    return _dismissal_response(dismissal)


@router.get(
    "/{project_id}/risk-dismissals",
    status_code=status.HTTP_200_OK,
    response_model=ProjectRiskDismissalsResponse,
)
async def list_risk_dismissals(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: ListRiskDismissalsUseCaseDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectRiskDismissalsResponse:
    """A project's dismissal records, newest dismissal first, each with its latest event.

    **Records, not current Risks.** A record reading `dismissed` whose surface has since gained a
    member no longer dismisses anything (ADR-0036 decision 2). Showing a ranked Risk as dismissed
    is M8.2's overlay.
    """
    try:
        page = await use_case.execute(
            project_id=project_id, user_id=user_id, limit=limit, offset=offset
        )
    except RiskDismissalAccessDenied as exc:
        # 404 for both denials, consumed directly from ProjectAccessPort. G17.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ProjectRiskDismissalsResponse(
        items=[_dismissal_response(dismissal) for dismissal in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )
