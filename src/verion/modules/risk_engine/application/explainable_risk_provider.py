# `correlation`'s PORT module, never its domain: the denial is declared there so this module
# can catch it by type (G35).
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.exceptions import MemberFindingMissing
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRisk,
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)


class ScoredExplainableRisks:
    """`ExplainableRiskPort` over `ComputeRiskUseCase` (M7.2, ADR-0033 decision 6).

    A wrapper on `CorrelationCandidateRisks`' precedent, for the same two reasons: the
    published name says what the consumer asks for, and the translations below are the
    load-bearing lines, because `brief` may name nothing under `risk_engine.domain` or
    `correlation`.

    **`ComputeRiskUseCase`, not `ListScoredRisksUseCase`.** One Risk needs neither a ranking
    nor the completeness envelope, and ADR-0033 decision 4 gives a Brief none, so the two
    envelope reads would be spent for nothing.

    Holds no state and takes no session; the use case it wraps owns both.
    """

    def __init__(self, compute: ComputeRiskUseCase) -> None:
        self._compute = compute

    async def explainable_risk(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> ExplainableRisk:
        try:
            surfaces = await self._compute.execute(project_id=project_id, user_id=user_id)
        except CandidateRiskAccessDenied as denied:
            raise ExplainableRiskAccessDenied(str(denied)) from denied
        except MemberFindingMissing as missing:
            raise ExplainableRiskInconsistent(str(missing)) from missing

        # EXACT equality over sorted ids, and never a subset or the nearest surface: a membership
        # change since the caller's read must refuse rather than narrate a different Risk
        # (ADR-0033 decision 1). A surface's ids are sorted and unique, so a request repeating
        # an id matches nothing, rather than being silently collapsed into a set. A no-signal
        # surface is a singleton whose key equals every other no-signal key, which is why the
        # key is never what is compared.
        requested = tuple(sorted(finding_ids))
        for surface in surfaces:
            if surface.finding_ids == requested:
                return ExplainableRisk(
                    finding_ids=surface.finding_ids,
                    decision=explainable_decision(surface),
                    # The engine's value for the surface it scored, never the caller's.
                    confidence=surface.confidence,
                )

        raise NoCurrentRisk(
            f"No current Risk in project '{project_id}' has exactly these findings; "
            "re-read the scored Risks"
        )
