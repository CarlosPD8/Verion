from verion.modules.risk_engine.domain.scoring import (
    CORROBORATION_DEFINITION,
    EXPOSURE_DEFINITION,
    FIX_NOW_AT,
    PLAN_AT,
    SEVERITY_DEFINITION,
    ScoredSurface,
    Signal,
)
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)


def _explainable(signal: Signal, *, definition: str) -> ExplainableSignal:
    return ExplainableSignal(
        name=signal.name,
        value=signal.value,
        produced_by=signal.produced_by,
        note=signal.note,
        definition=definition,
    )


def explainable_decision(surface: ScoredSurface) -> ExplainableDecision:
    """The copy of a scored surface's decision that `brief` is allowed to receive.

    **The one site that fills the carrier, and it lives in `risk_engine`** — both ends of
    the copy in the module `mypy --strict` checks them in, so a renamed `Signal` field fails
    here rather than in another module (ADR-0032 decision 1). In `application/` rather than
    `ports/` for the reason `CorrelationCandidateRisks` constructs `CandidateRiskAccessDenied`
    in `correlation/application/`: a port module declares; it does not compute.

    **Nothing in `src/` calls this at M7.1.** The port that hands the result to `brief` is
    M7.2's, because what it returns must also carry a Risk address, and that is **G68**'s
    decision rather than this issue's.
    """
    reasoning = surface.reasoning
    return ExplainableDecision(
        priority=surface.priority.value,
        priority_score=surface.priority_score,
        fix_now_at=FIX_NOW_AT,
        plan_at=PLAN_AT,
        severity=_explainable(reasoning.severity, definition=SEVERITY_DEFINITION),
        exposure=_explainable(reasoning.exposure, definition=EXPOSURE_DEFINITION),
        corroboration=_explainable(reasoning.corroboration, definition=CORROBORATION_DEFINITION),
    )
