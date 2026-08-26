from dataclasses import dataclass
from datetime import datetime

from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.domain.matching import MatchGroup

# `normalization`'s PORT — never its `application/`. Importing M4.5's paging
# constants from `list_project_findings` would pass `lint-imports` and violate
# rule 3: that is **G35**, and this is the first code that could have taken it.
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)

# M4.5's values, declared here rather than imported — see the note above.
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


@dataclass(frozen=True)
class LatestNormalizationRun:
    """The latest normalization run's state, in a type `correlation` owns.

    Exists because `correlation` may not name `NormalizationRun`. ADR-0025 decision 4.
    """

    scan_id: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None


@dataclass(frozen=True)
class ProjectRisks:
    """One page of a project's candidate Risks, plus what it says about its own completeness.

    In `application/` rather than `domain/` for the reason `ProjectFindings` is: `limit`,
    `offset` and `total` are artifacts of how a caller asked. ADR-0022 decision 1 states the
    criterion; `MatchGroup`'s docstring records passing it where this type fails it.
    """

    items: list[MatchGroup]
    total: int
    limit: int
    offset: int
    latest_run: LatestNormalizationRun | None
    unfinished_runs: int


class ListProjectRisksUseCase:
    """A page of a project's candidate Risks, with the normalization state behind them.

    Composes `CorrelateFindingsUseCase` rather than re-reading findings itself: that one is the
    grouping and owns the access check, and M6 calls it without wanting an envelope.

    **Persists nothing, and returns no Risk identifier** — ADR-0025 decision 1.
    """

    def __init__(
        self,
        correlate: CorrelateFindingsUseCase,
        normalization_runs: NormalizationRunRepositoryPort,
    ) -> None:
        self._correlate = correlate
        self._normalization_runs = normalization_runs

    async def execute(
        self,
        *,
        project_id: str,
        user_id: str,
        limit: int = DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> ProjectRisks:
        """Correlate first, then read the envelope. The order is the security property.

        `CorrelateFindingsUseCase.execute` authorizes as its first statement, so both envelope
        reads below sit after the gate. Fakes that raise when touched pin it — the placement
        ADR-0013 established and `ExplodingFindingRepository` already serves.
        """
        groups = await self._correlate.execute(project_id=project_id, user_id=user_id)
        run = await self._normalization_runs.get_latest_by_project_id(project_id)
        return ProjectRisks(
            items=groups[offset : offset + limit],
            # Exact, not a second statement's answer: the whole group set is in hand, so the
            # READ COMMITTED skew `ProjectFindingsResponse` documents cannot arise.
            total=len(groups),
            limit=limit,
            offset=offset,
            # Field by field off the port's return value, never naming its type.
            latest_run=None
            if run is None
            else LatestNormalizationRun(
                scan_id=run.scan_id,
                status=str(run.status),
                requested_at=run.requested_at,
                started_at=run.started_at,
                finished_at=run.finished_at,
                failure_reason=run.failure_reason,
            ),
            unfinished_runs=await self._normalization_runs.count_unfinished_by_project_id(
                project_id
            ),
        )
