from verion.modules.history.domain.exceptions import RiskAlreadyDismissed
from verion.modules.history.domain.risk import (
    Risk,
    RiskDismissal,
    RiskEvent,
    RiskEventKind,
    covering_dismissal,
)
from verion.modules.history.ports.risk_dismissal_repository import RiskDismissalRepositoryPort

# `risk_engine`'s PORT, never its application or domain (rule 3). Its denials are declared in the
# port module and propagate from here uncaught, so the route catches them by type, as `brief`'s
# does.
from verion.modules.risk_engine.ports.explainable_risk import ExplainableRiskPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class DismissRiskUseCase:
    """Dismiss the current Risk whose members are exactly `finding_ids`. M8.1, ADR-0036.

    **Validated through `ExplainableRiskPort`, which also authorizes.** It selects the surface by
    exact set, fails closed with `NoCurrentRisk` when membership has moved, and asks
    `may_read_project` beneath it, so dismissal is member-level (decision 10). Each call runs the
    doubled findings read once (**G61**).

    **The snapshot is the port's `finding_ids`, never the request's.** The request is a selector;
    what is stored is what the engine scored.

    **A surface an active snapshot already covers is refused** with `RiskAlreadyDismissed`,
    naming the covering record (decision 11). That is the same-Risk rule's first use in `src/`.
    It is a read, then an insert, so two concurrent dismissals of one uncovered surface can both
    pass (**G92**).
    """

    def __init__(
        self,
        explainable_risks: ExplainableRiskPort,
        dismissals: RiskDismissalRepositoryPort,
        clock: ClockPort,
        ids: IdGeneratorPort,
    ) -> None:
        self._explainable_risks = explainable_risks
        self._dismissals = dismissals
        self._clock = clock
        self._ids = ids

    async def execute(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...], reason: str
    ) -> RiskDismissal:
        # Authorizes before reading anything, and refuses a stale set before any write.
        current = await self._explainable_risks.explainable_risk(
            project_id=project_id, user_id=user_id, finding_ids=finding_ids
        )

        covering = covering_dismissal(
            current.finding_ids, await self._dismissals.snapshots_for_project(project_id)
        )
        if covering is not None:
            raise RiskAlreadyDismissed(covering)

        risk = Risk(id=self._ids.new_id(), project_id=project_id, finding_ids=current.finding_ids)
        dismissal = RiskEvent(
            id=self._ids.new_id(),
            risk_id=risk.id,
            ordinal=1,
            kind=RiskEventKind.DISMISSED,
            actor_user_id=user_id,
            reason=reason,
            occurred_at=self._clock.now(),
        )
        await self._dismissals.add(risk, dismissal)
        return RiskDismissal(risk=risk, latest=dismissal)
