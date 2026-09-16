from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

# `correlation`'s PORT module, never its domain. `CandidateRiskAccessDenied` is declared
# there precisely so this route can name the denial without importing `correlation.domain`,
# which rule 3 forbids and `cross-module-risk-engine` enforces — see that class's docstring
# and **G35**.
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied
from verion.modules.risk_engine.adapters.inbound.api.schemas import (
    MatchKeyResponse,
    NormalizationRunResponse,
    NormalizationStateResponse,
    RiskReasoningResponse,
    ScoredProjectRisksResponse,
    ScoredRiskResponse,
    SignalResponse,
    ThresholdsResponse,
)
from verion.modules.risk_engine.application.list_scored_risks import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    ScoredProjectRisks,
)
from verion.modules.risk_engine.domain.exceptions import MemberFindingMissing
from verion.modules.risk_engine.domain.scoring import FIX_NOW_AT, PLAN_AT, ScoredSurface, Signal
from verion.platform.di import CurrentUserIdDep, ListScoredRisksUseCaseDep

router = APIRouter()


def _signal_response(signal: Signal) -> SignalResponse:
    return SignalResponse(
        name=signal.name,
        value=signal.value,
        produced_by=list(signal.produced_by),
        note=signal.note,
    )


def _scored_risk_response(surface: ScoredSurface) -> ScoredRiskResponse:
    return ScoredRiskResponse(
        match=MatchKeyResponse(package=surface.package, url=surface.url),
        finding_ids=list(surface.finding_ids),
        finding_count=len(surface.finding_ids),
        priority_score=surface.priority_score,
        priority=str(surface.priority),
        reasoning=RiskReasoningResponse(
            severity=_signal_response(surface.reasoning.severity),
            exposure=_signal_response(surface.reasoning.exposure),
            corroboration=_signal_response(surface.reasoning.corroboration),
        ),
    )


def _scored_risks_response(risks: ScoredProjectRisks) -> ScoredProjectRisksResponse:
    latest = risks.latest_run
    return ScoredProjectRisksResponse(
        items=[_scored_risk_response(surface) for surface in risks.items],
        total=risks.total,
        limit=risks.limit,
        offset=risks.offset,
        # By name from the domain's own constants, never literals — the one place the
        # thresholds are declared, so this field cannot drift from `bucket_for`.
        thresholds=ThresholdsResponse(fix_now_at=FIX_NOW_AT, plan_at=PLAN_AT),
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
    "/{project_id}/scored-risks",
    status_code=status.HTTP_200_OK,
    response_model=ScoredProjectRisksResponse,
)
async def list_scored_risks(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: ListScoredRisksUseCaseDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScoredProjectRisksResponse:
    """A project's Risks, scored and ranked most urgent first (FR-7).

    Each item carries its `priority`, the `priority_score` behind it, and the three signals
    that produced it — each with the member it came from. **The bucket is re-derivable by
    hand**: the signals sum to `priority_score`, and `thresholds` on the envelope says where
    the boundaries are. That is rule 5 at the surface, and it is why no signal is summarised
    away.

    **A Risk here is a SURFACE** — the package or route path its match key names — not a
    vulnerability, and nothing here says two tools found the same thing (ADR-0005 decision 0,
    **G62**).

    **The top bucket is closed to every dependency finding, however severe.** `fix_now` has
    exactly one reachable decomposition: a route-path surface carrying both a SAST and a DAST
    member with at least one `HIGH` member, which may come from either tool. A `CRITICAL`
    package CVE therefore tops out at `plan`, and that is a property of the scoring function
    rather than of any one Risk — **G64**.

    Not stored: a Risk carries no id and no item is addressable on its own (ADR-0025
    decision 1). The constituent findings are at `GET /projects/{project_id}/findings` and its
    evidence route, which is FR-9's link.

    The unscored companion, `GET /projects/{project_id}/risks`, returns the same surfaces in
    `correlation`'s deterministic group order, which is **not** a ranking. Within one bucket
    the two agree, because this route's tiebreak is that order.
    """
    try:
        risks = await use_case.execute(
            project_id=project_id, user_id=user_id, limit=limit, offset=offset
        )
    except CandidateRiskAccessDenied as exc:
        # 404 for both denials, inherited from ADR-0022 decision 2 rather than re-decided.
        # The port returns a verdict with no vocabulary for which denial applied, so this
        # cannot drift back to a 403. Widens G17 by one route — the fourth — and the
        # convergence is G18's at M10.2.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except MemberFindingMissing as exc:
        # 500 CHOSEN, not inherited from the framework's default handler (ADR-0030
        # decision 5). The two findings reads disagreed, which is a broken server-side
        # invariant rather than anything the caller did or can retry: nothing deletes a
        # finding today (G11). Caught here so the mapping is a line a test can point at —
        # §9 puts the domain-error-to-status translation in the inbound adapter — and the
        # detail is generic because the message names an internal invariant.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="This project's Risks could not be scored consistently.",
        ) from exc

    return _scored_risks_response(risks)
