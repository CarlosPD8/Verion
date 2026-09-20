from dataclasses import dataclass
from typing import Protocol

from verion.modules.risk_engine.domain.exceptions import RiskEngineError
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision
from verion.shared_kernel.confidence import Confidence


@dataclass(frozen=True, kw_only=True)
class ExplainableRisk:
    """One current scored Risk as `brief` may receive it: its members, and its decision.

    **`finding_ids` are the Risk's members as DATA, not an address** (ADR-0033 decision 1).
    They are the surface's own, sorted, as `ScoredSurface` carries them. They are never the
    caller's input echoed back, so a Brief stores what the engine scored rather than what a
    client sent. They are FR-9's link: each one is reachable at `normalization`'s evidence
    route.

    Declared in `ports/`, like `ExplainableDecision`, so a consumer can name it.

    **`confidence` sits HERE and not on `ExplainableDecision`** (M8.5, ADR-0037 decision 8),
    and the placement is rule 6 rather than taste: that carrier's docstring says it is
    *"everything a narrator may see"* and it is frozen so rule 6 holds by the type, while
    **no prompt receives this value**. Putting it there would make that sentence false and
    degrade rule 6 to a convention. It also belongs beside `finding_ids`, which IS the
    grouping this value describes.

    The knock-on is the point: `ExplainableDecision` is unchanged, so the stored decision's
    version does not move and every Brief written before M8.5 still reads back.
    """

    finding_ids: tuple[str, ...]
    decision: ExplainableDecision
    confidence: Confidence


class ExplainableRiskAccessDenied(RiskEngineError):
    """The caller may not read this project.

    Declared here rather than in `domain/` for `CandidateRiskAccessDenied`'s reason: the
    consumer may not name `risk_engine.domain`, so a port that can deny must carry its denial
    where the consumer can catch it by type. Like the verdict beneath it, it does not
    distinguish "no such project" from "not a member".
    """


class NoCurrentRisk(RiskEngineError):
    """No scored surface in this project has exactly these finding ids right now.

    **This is the fail-closed case ADR-0033 decision 1 relies on.** A finding joining or leaving
    the surface since the caller read its listing changes the set, and the answer is a refusal
    rather than the nearest match. Re-reading `/scored-risks` is the remedy.
    """


class ExplainableRiskInconsistent(RiskEngineError):
    """The two findings reads behind scoring disagreed (`MemberFindingMissing`, **G61**).

    Translated rather than re-raised, because the consumer may not name the domain exception.
    It is a broken server-side invariant, never a client error (ADR-0030 decision 5).
    """


class ExplainableRiskPort(Protocol):
    """One current scored Risk, selected by its exact member set. `risk_engine`'s port to `brief`.

    M7.2, ADR-0033 decision 6. **This is the port ADR-0032 decision 1 left to this issue**: it
    delivers `ExplainableDecision` together with the members that decision was computed over.
    """

    async def explainable_risk(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> ExplainableRisk:
        """The surface whose sorted finding ids equal `finding_ids` sorted, scored now.

        Order does not matter and repetition does: a repeated id matches no surface, because a
        surface's ids are unique.

        Authorizes before reading anything, then recomputes the project's whole scored set.
        There is no Risk identity to look one up by (ADR-0025 decision 1), so this is the
        doubled findings read of **G61**, once per call.

        Raises `ExplainableRiskAccessDenied`, `NoCurrentRisk` or `ExplainableRiskInconsistent`,
        and nothing else of this module's.
        """
        ...
