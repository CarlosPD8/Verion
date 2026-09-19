from verion.modules.history.domain.exceptions import (
    RiskDismissalAccessDenied,
    RiskDismissalNotFound,
    RiskEventConflict,
    RiskNotDismissed,
)
from verion.modules.history.domain.risk import RiskDismissal, RiskEvent, RiskEventKind
from verion.modules.history.ports.risk_dismissal_repository import RiskDismissalRepositoryPort

# `projects`' verdict port, never its persistence ports (ADR-0022 decision 2).
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class UndismissRiskUseCase:
    """Undo a dismissal by appending an `undismissed` event. M8.1, ADR-0036 decision 10.

    **Nothing is mutated or deleted.** The dismissal event stays in the log, and the record's
    current state becomes `undismissed` because its latest event is.

    **Member-level, asked before any read**, directly on `ProjectAccessPort`, because undo reads
    only `history`'s own tables. It does not recompute the surface: an undo refers to a record,
    not to the live Risk.

    **A record is undone at most once.** A record whose latest event is already `undismissed`
    is refused, and a later dismissal of the same surface writes a new record.
    """

    def __init__(
        self,
        project_access: ProjectAccessPort,
        dismissals: RiskDismissalRepositoryPort,
        clock: ClockPort,
        ids: IdGeneratorPort,
    ) -> None:
        self._project_access = project_access
        self._dismissals = dismissals
        self._clock = clock
        self._ids = ids

    async def execute(
        self, *, project_id: str, user_id: str, dismissal_id: str, reason: str | None
    ) -> RiskDismissal:
        # Before any read, so a refused caller learns nothing from what the repository does.
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise RiskDismissalAccessDenied(f"No readable project with id '{project_id}'")

        current = await self._dismissals.get(project_id=project_id, risk_id=dismissal_id)
        if current is None:
            raise RiskDismissalNotFound(f"No dismissal with id '{dismissal_id}' in this project")
        if current.state is not RiskEventKind.DISMISSED:
            raise RiskNotDismissed(f"Dismissal '{dismissal_id}' is already undone")

        undo = RiskEvent(
            id=self._ids.new_id(),
            risk_id=current.risk.id,
            ordinal=current.latest.ordinal + 1,
            kind=RiskEventKind.UNDISMISSED,
            actor_user_id=user_id,
            reason=reason,
            occurred_at=self._clock.now(),
        )
        if not await self._dismissals.append_event(undo):
            # A concurrent undo took this ordinal first. Nothing was written here.
            raise RiskEventConflict(f"Dismissal '{dismissal_id}' changed during this request")
        return RiskDismissal(risk=current.risk, latest=undo)
