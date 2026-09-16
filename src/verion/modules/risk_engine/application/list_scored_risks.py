from dataclasses import dataclass
from datetime import datetime

# `normalization`'s PORT, never its domain or adapters. The port's signatures name
# `NormalizationRun`; this module never does, and takes the fields by attribute off the
# return value below — the `allow_indirect_imports = true` pattern, and the idiom
# `ListProjectRisksUseCase` uses one module over.
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.domain.scoring import ScoredSurface, rank_surfaces

# M4.5's values, declared here rather than imported from another module's `application/`.
# Importing `DEFAULT_PAGE_LIMIT`/`MAX_PAGE_LIMIT` from `normalization` or `correlation`
# would pass `lint-imports` green and violate rule 3 — that is **G35**, and
# `ListProjectRisksUseCase` declined the same shortcut for the same reason.
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


@dataclass(frozen=True)
class LatestNormalizationRun:
    """The latest normalization run's state, in a type `risk_engine` owns.

    Exists because this module may not name `NormalizationRun`: `cross-module-risk-engine`
    forbids `verion.modules.normalization.domain`.

    **This is the SECOND carrier of these six fields** — `correlation`'s
    `LatestNormalizationRun` is the first, and `normalization` holds the entity itself.
    Nothing requires two of them; they exist only because two modules may not name one
    entity. The obvious later repair, one shared structure in `shared_kernel/`, is the one
    ADR-0018's criterion forbids, since this is a structure being **transported** rather
    than a vocabulary being compared. **G67** carries that, and the field-by-field copy
    below is what makes a renamed field on `NormalizationRun` fail here under
    `mypy --strict` rather than propagate silently.
    """

    scan_id: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure_reason: str | None


@dataclass(frozen=True)
class ScoredProjectRisks:
    """One ranked page of a project's scored Risks, plus what it says about its completeness.

    In `application/` rather than `domain/` for the reason `ProjectRisks` and
    `ProjectFindings` are: `limit`, `offset` and `total` are artifacts of how a caller asked
    the question rather than facts about the Risks — ADR-0022 decision 1's criterion, which
    `ScoredSurface` passes and this type fails.
    """

    items: list[ScoredSurface]
    total: int
    limit: int
    offset: int
    latest_run: LatestNormalizationRun | None
    unfinished_runs: int


class ListScoredRisksUseCase:
    """A ranked page of a project's scored Risks, with the normalization state behind them.

    **Composes `ComputeRiskUseCase` rather than re-scoring anything**, the way
    `ListProjectRisksUseCase` composes `CorrelateFindingsUseCase`: that one scores and owns
    nothing about presentation, and ADR-0025 decision 4's reasoning puts the envelope on a
    second use case rather than on the one doing the work.

    **Ranking enters here and nowhere below it.** `ComputeRiskUseCase` returns
    `correlation`'s group order deliberately, and `test_compute_risk.py` carries a test
    named for exactly that; this use case applies `rank_surfaces` on top, so the scored
    route is the only place in this system where a priority order exists.

    **Persists nothing**: ADR-0005 decision 3, with ADR-0025 decisions 1 and 2 behind it.
    No `risks` table and no upsert, so **G37**'s protected-column obligation stays latent and
    M8.1 remains the first issue forced to write a Risk.
    """

    def __init__(
        self,
        compute: ComputeRiskUseCase,
        normalization_runs: NormalizationRunRepositoryPort,
    ) -> None:
        self._compute = compute
        self._normalization_runs = normalization_runs

    async def execute(
        self,
        *,
        project_id: str,
        user_id: str,
        limit: int = DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> ScoredProjectRisks:
        """Score, rank, then read the envelope. Both orders are properties.

        **The security order:** `ComputeRiskUseCase.execute` reaches `CandidateRiskPort`,
        which authorizes before reading anything and raises `CandidateRiskAccessDenied`, so
        both envelope reads below sit behind that gate. A run repository that raises when
        touched pins it — the placement ADR-0013 established, and the shape
        `ExplodingNormalizationRunRepository` already serves for M5.2.

        **The ranking order:** the whole set is ranked BEFORE paging, which is what makes a
        page mean anything. Paging first and ranking the page would return the top of an
        arbitrary order and label it a priority.
        """
        ranked = rank_surfaces(await self._compute.execute(project_id=project_id, user_id=user_id))
        run = await self._normalization_runs.get_latest_by_project_id(project_id)
        return ScoredProjectRisks(
            items=ranked[offset : offset + limit],
            # Exact, not a second statement's answer: the whole scored set is in hand, so
            # the READ COMMITTED skew `ProjectFindingsResponse` documents cannot arise here.
            total=len(ranked),
            limit=limit,
            offset=offset,
            # Field by field off the port's return value, never naming its type — G67.
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
