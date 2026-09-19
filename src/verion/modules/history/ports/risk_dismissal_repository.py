from typing import Protocol

from verion.modules.history.domain.risk import Risk, RiskDismissal, RiskEvent, Snapshot


class RiskDismissalRepositoryPort(Protocol):
    """Persistence for dismissal records and their append-only event log. ADR-0036.

    **Append-only by contract.** No method updates or deletes a record or an event, and no
    method writes a record from anything but a dismissal, which is what keeps **G37** resolved.
    Adding one of either kind reopens it.
    """

    async def add(self, risk: Risk, first_event: RiskEvent) -> None:
        """Store a new record and its first event, which is a dismissal at ordinal 1."""
        ...

    async def append_event(self, event: RiskEvent) -> bool:
        """Append an event at its ordinal. `False`, writing nothing, if that ordinal is taken.

        Race-safe through `UNIQUE(risk_id, ordinal)`: of two concurrent appends at one ordinal,
        exactly one is stored and the other returns `False`, never an `IntegrityError`.
        """
        ...

    async def get(self, *, project_id: str, risk_id: str) -> RiskDismissal | None:
        """The record with its latest event, or `None` if absent or of another project."""
        ...

    async def snapshots_for_project(self, project_id: str) -> list[Snapshot]:
        """Every record in the project with its current state, for the same-Risk rule."""
        ...

    async def list_for_project(
        self, *, project_id: str, limit: int, offset: int
    ) -> list[RiskDismissal]:
        """A page of records, newest dismissal first, then by record id."""
        ...

    async def count_for_project(self, project_id: str) -> int: ...
