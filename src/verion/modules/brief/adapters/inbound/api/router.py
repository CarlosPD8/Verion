from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from verion.modules.brief.adapters.inbound.api.schemas import (
    BriefGenerationAcceptedResponse,
    BriefGenerationResponse,
    BriefReasoningResponse,
    BriefSignalResponse,
    BriefThresholdsResponse,
    ConfidenceResponse,
    GenerateSecurityBriefRequest,
    ProjectSecurityBriefsResponse,
    SecurityBriefResponse,
    WhatHappenedResponse,
)
from verion.modules.brief.application.list_security_briefs import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
)
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationFailureKind,
)
from verion.modules.brief.domain.exceptions import (
    BriefGenerationAccessDenied,
    SecurityBriefAccessDenied,
    StoredBriefUnreadable,
)
from verion.modules.brief.domain.security_brief import SecurityBrief

# `correlation`'s PORT module, which `cross-module-brief` permits (it forbids that module's
# `.domain` and `.adapters`). The definition is declared once there and forwarded verbatim.
from verion.modules.correlation.ports.candidate_risk import CONFIDENCE_DEFINITION

# `risk_engine`'s PORT module, never its domain.
from verion.modules.risk_engine.ports.explainable_decision import ExplainableSignal
from verion.platform.di import (
    CurrentUserIdDep,
    GetBriefGenerationUseCaseDep,
    ListSecurityBriefsUseCaseDep,
    RequestSecurityBriefUseCaseDep,
)

router = APIRouter()

# Fixed details, never `str(exc)`, for every failure whose message is not the caller's own
# input.
_UNREADABLE = "A stored Brief for this project could not be read."

# **One fixed sentence per `failure_kind`, DERIVED here rather than stored** (ADR-0038 decision
# 6). Two things follow, both deliberate: no provider text can reach a client, because none of
# these strings is built from an exception's message (rule 12, and `ExplanationUnavailable`'s
# own message is safe by ADR-0032 decision 6 but still has nothing a client can use — **G71**'s
# second path); and the table needs no `detail` column, which would have sat outside
# `ck_brief_generations_outcome_shape` as a correlation held by convention.
#
# Each says what the client should DO, because that is the axis the vocabulary was chosen on.
# The first is the wording the route used to return as a 404 body, preserved: it is the same
# refusal, reported later (ADR-0033 decision 1).
_FAILURE_DETAIL: dict[BriefGenerationFailureKind, str] = {
    BriefGenerationFailureKind.SURFACE_CHANGED: (
        "No current Risk in this project has exactly these findings. Re-read the scored Risks."
    ),
    BriefGenerationFailureKind.PROVIDER_UNAVAILABLE: (
        "The Brief could not be generated. Nothing was stored. Asking again may succeed."
    ),
    BriefGenerationFailureKind.INTERNAL_ERROR: (
        "This Brief could not be generated. Asking again will not help."
    ),
}


def _signal_response(signal: ExplainableSignal) -> BriefSignalResponse:
    return BriefSignalResponse(
        name=signal.name,
        value=signal.value,
        produced_by=list(signal.produced_by),
        note=signal.note,
        definition=signal.definition,
    )


def _brief_response(brief: SecurityBrief) -> SecurityBriefResponse:
    decision = brief.decision
    return SecurityBriefResponse(
        id=brief.id,
        finding_ids=list(brief.finding_ids),
        why_it_matters=brief.explanation.text,
        what_happened=(
            None
            if brief.what_happened is None
            else WhatHappenedResponse(
                text=brief.what_happened.text,
                model=brief.what_happened.model,
                prompt_version=brief.what_happened.prompt_version,
            )
        ),
        confidence=(
            None
            if brief.confidence is None
            # `correlation`'s single declaration, forwarded verbatim. The value is the STORED
            # one; the definition is today's, because no narrator was shown it and so there
            # is nothing to keep checkable against what was narrated.
            else ConfidenceResponse(value=str(brief.confidence), definition=CONFIDENCE_DEFINITION)
        ),
        priority=decision.priority,
        priority_score=decision.priority_score,
        # The STORED thresholds, never today's constants: this is the decision as narrated.
        thresholds=BriefThresholdsResponse(
            fix_now_at=decision.fix_now_at, plan_at=decision.plan_at
        ),
        reasoning=BriefReasoningResponse(
            severity=_signal_response(decision.severity),
            exposure=_signal_response(decision.exposure),
            corroboration=_signal_response(decision.corroboration),
        ),
        model=brief.explanation.model,
        prompt_version=brief.explanation.prompt_version,
        generated_at=brief.generated_at,
    )


def _generation_response(generation: BriefGeneration) -> BriefGenerationResponse:
    return BriefGenerationResponse(
        id=generation.id,
        status=str(generation.status),
        failure_kind=(None if generation.failure_kind is None else str(generation.failure_kind)),
        # Derived, never stored. A kind with no entry here would be a `KeyError` rather than a
        # `null` a client would read as "no detail", which is the loud failure of the two.
        detail=(
            None if generation.failure_kind is None else _FAILURE_DETAIL[generation.failure_kind]
        ),
        brief_id=generation.brief_id,
    )


@router.post(
    "/{project_id}/briefs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=BriefGenerationAcceptedResponse,
)
async def request_security_brief(
    project_id: str,
    body: GenerateSecurityBriefRequest,
    user_id: CurrentUserIdDep,
    use_case: RequestSecurityBriefUseCaseDep,
) -> BriefGenerationAcceptedResponse:
    """Ask for the current Risk whose members are exactly `finding_ids` to be narrated.

    **202, not 201: this enqueues a job and returns an addressable generation** (ADR-0038
    decision 1, replacing ADR-0033 decision 8). Poll
    `GET /projects/{project_id}/brief-generations/{id}` for the outcome, and read the Brief
    itself on `GET /projects/{project_id}/briefs` once `brief_id` is set.

    **Every accepted request is still two billed provider calls and one new row** (ADR-0034
    decision 3): one narrates what the members report, one why the priority is what it is. Both
    succeed or nothing is stored. Generation is append-only, so a second request for the same
    set is a regeneration, not a no-op (ADR-0033 decision 3) — and **nothing bounds repeats**
    (**G100**), which this route makes cheaper to exercise, not dearer, because it returns
    before the work.

    **The set selects; it does not address** (ADR-0033 decision 1). What changed at M8.6 is
    *when*: the set is stored here and resolved in the worker, so a set that no longer names a
    surface is a `surface_changed` generation rather than this route's 404.

    **Two authorization gates, in two processes** (ADR-0038 decision 4). This route asks
    `may_read_project` before it writes anything; the job re-authorizes through
    `risk_engine`'s port with the stored `user_id`, which is what catches a membership revoked
    between enqueue and run. The second is defence in depth, not an inherited verdict.

    **Member-level**, which coincides with owner-gating today only because nothing creates a
    non-owner membership (**G75**). It does **not** refuse while normalization is unfinished,
    because a failed run counts and is never retried, so that refusal would be permanent
    (ADR-0033 decision 5, **G76**).
    """
    try:
        generation = await use_case.execute(
            project_id=project_id, user_id=user_id, finding_ids=tuple(body.finding_ids)
        )
    except BriefGenerationAccessDenied as exc:
        # 404 for both denials (ADR-0022 decision 2). **G17**: the same body the list route
        # and the poll return, so no refusal is distinguishable from another.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return BriefGenerationAcceptedResponse(id=generation.id, status=str(generation.status))


@router.get(
    "/{project_id}/brief-generations/{generation_id}",
    status_code=status.HTTP_200_OK,
    response_model=BriefGenerationResponse,
)
async def get_brief_generation(
    project_id: str,
    generation_id: str,
    user_id: CurrentUserIdDep,
    use_case: GetBriefGenerationUseCaseDep,
) -> BriefGenerationResponse:
    """What became of one generation. M8.6, ADR-0038 decision 8.

    `status` is `pending`, `running`, `succeeded` or `failed`. On `succeeded`, `brief_id` names
    the row to read on `GET /projects/{project_id}/briefs`. On `failed`, `failure_kind` is one
    of three values chosen on **what the client should do** — `surface_changed` (re-read
    `/scored-risks` and ask again), `provider_unavailable` (retry), `internal_error` (do not
    retry) — and `detail` is a fixed sentence derived from it, never a provider's words.

    **Readable only by the caller who requested it.** This route authorizes on its own and
    inherits nothing from the POST, which may have been answered long before: `may_read_project`
    **and** an actor match. Another member of the same project, an absent id, a generation of
    another project and a non-member are one 404 with one body (**G17**).

    **A `pending` row can stay `pending` forever** if its enqueue was lost after the commit.
    Nothing re-drives it — ADR-0038 decision 11 declines a sweep, on the ground that a
    generation is user-initiated and the user is already polling — so this route is what makes
    that visible, and the recovery is asking again (**G87**).
    """
    try:
        generation = await use_case.execute(
            project_id=project_id, user_id=user_id, generation_id=generation_id
        )
    except BriefGenerationAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return _generation_response(generation)


@router.get(
    "/{project_id}/briefs",
    status_code=status.HTTP_200_OK,
    response_model=ProjectSecurityBriefsResponse,
)
async def list_security_briefs(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: ListSecurityBriefsUseCaseDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectSecurityBriefsResponse:
    """A project's Briefs, newest first, each carrying the `finding_ids` it narrated.

    **Join this against `/scored-risks` on `finding_ids`.** A surface's current Brief is the
    first item whose set equals the surface's; later items for that set are history. No item is
    addressable by a Risk, because a Risk has no identifier (ADR-0025 decision 1), and no URL
    carries a member set (ADR-0033 decision 4).

    **No completeness envelope.** No pipeline owes a Brief, so this list is complete by
    construction. Whether a given Brief's decision was computed over complete findings is not
    recorded (**G76**); `/scored-risks` carries today's normalization state.

    **One unreadable stored row fails the whole read** with a 500, rather than being skipped,
    which would hide data loss behind a shorter page (ADR-0033 decision 9).
    """
    try:
        page = await use_case.execute(
            project_id=project_id, user_id=user_id, limit=limit, offset=offset
        )
    except SecurityBriefAccessDenied as exc:
        # 404 for both denials, consumed directly from ProjectAccessPort (ADR-0022 decision 2).
        # G17: the other of the two routes this issue adds.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StoredBriefUnreadable as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_UNREADABLE
        ) from exc

    return ProjectSecurityBriefsResponse(
        items=[_brief_response(brief) for brief in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )
