from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from verion.modules.brief.adapters.inbound.api.schemas import (
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
from verion.modules.brief.domain.exceptions import (
    BriefMemberMissing,
    ExplanationUnavailable,
    SecurityBriefAccessDenied,
    StoredBriefUnreadable,
)
from verion.modules.brief.domain.security_brief import SecurityBrief

# `correlation`'s PORT module, which `cross-module-brief` permits (it forbids that module's
# `.domain` and `.adapters`). The definition is declared once there and forwarded verbatim.
from verion.modules.correlation.ports.candidate_risk import CONFIDENCE_DEFINITION

# `risk_engine`'s PORT module, never its domain: the denials are declared there so this route
# can catch them by type.
from verion.modules.risk_engine.ports.explainable_decision import ExplainableSignal
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)
from verion.platform.di import (
    CurrentUserIdDep,
    GenerateSecurityBriefUseCaseDep,
    ListSecurityBriefsUseCaseDep,
)

router = APIRouter()

# Fixed details, never `str(exc)`, for every failure whose message is not the caller's own
# input. In particular `ExplanationUnavailable`: its message is safe by ADR-0032 decision 6,
# and the client still has no use for a provider's status code (G71's second path).
_NO_CURRENT_RISK = (
    "No current Risk in this project has exactly these findings. Re-read the scored Risks."
)
_INCONSISTENT = "This project's Risks could not be scored consistently."
_NARRATION_UNAVAILABLE = "The Brief could not be generated. Nothing was stored."
_UNREADABLE = "A stored Brief for this project could not be read."
_MEMBER_MISSING = "A finding in this Risk could not be read."


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


@router.post(
    "/{project_id}/briefs",
    status_code=status.HTTP_201_CREATED,
    response_model=SecurityBriefResponse,
)
async def generate_security_brief(
    project_id: str,
    body: GenerateSecurityBriefRequest,
    user_id: CurrentUserIdDep,
    use_case: GenerateSecurityBriefUseCaseDep,
) -> SecurityBriefResponse:
    """Narrate the current Risk whose members are exactly `finding_ids`, and store the Brief.

    **Every call is two billed provider calls and writes a new row** (ADR-0034 decision 3): one
    narrates what the members report, one why the priority is what it is. Both succeed or
    nothing is stored. Generation is append-only,
    so a second call for the same set is a regeneration, not a no-op (ADR-0033 decision 3). It
    is synchronous, holding this request open across both calls, and nothing bounds repeats
    (**G73**).

    **The set selects; it does not address.** If findings joined or left the surface since the
    caller read `/scored-risks`, this answers 404 and stores nothing (ADR-0033 decision 1). The
    Brief's own identity is the `id` it returns.

    **Member-level**, inherited from the read verdict through `risk_engine`'s port. That
    coincides with owner-gating today only because nothing creates a non-owner membership
    (**G75**). It does **not** refuse while normalization is unfinished, because a failed run
    counts and is never retried, so that refusal would be permanent (ADR-0033 decision 5,
    **G76**).
    """
    try:
        brief = await use_case.execute(
            project_id=project_id, user_id=user_id, finding_ids=tuple(body.finding_ids)
        )
    except ExplainableRiskAccessDenied as exc:
        # 404 for both denials (ADR-0022 decision 2), inherited through the port as M6.3's
        # route inherits it. G17: one of the two routes this issue adds.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except NoCurrentRisk as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NO_CURRENT_RISK) from exc
    except ExplainableRiskInconsistent as exc:
        # A broken server-side invariant, chosen as a 500 rather than left to the framework's
        # default handler (ADR-0030 decision 5).
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_INCONSISTENT
        ) from exc
    except BriefMemberMissing as exc:
        # The same class of broken invariant, one read later (ADR-0034 decision 2). Raised
        # before any provider call, so nothing was billed.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_MEMBER_MISSING
        ) from exc
    except ExplanationUnavailable as exc:
        # Also `WhatHappenedRejected`, its subclass: a narrative failing output validation is,
        # to the caller, no usable narrative (ADR-0034 decision 5).
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=_NARRATION_UNAVAILABLE
        ) from exc

    return _brief_response(brief)


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
