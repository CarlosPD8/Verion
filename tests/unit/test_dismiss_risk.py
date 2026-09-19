"""`DismissRiskUseCase` over in-memory ports. ADR-0036 decisions 1, 6, 10 and 11."""

from datetime import UTC, datetime

import pytest

from verion.modules.history.application.dismiss_risk import DismissRiskUseCase
from verion.modules.history.domain.exceptions import RiskAlreadyDismissed
from verion.modules.history.domain.risk import RiskEventKind
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRisk,
    ExplainableRiskAccessDenied,
    NoCurrentRisk,
)

_PROJECT = "project-1"
_USER = "user-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(name: str) -> ExplainableSignal:
    return ExplainableSignal(name=name, value=0, produced_by=(), note=None, definition=name)


_DECISION = ExplainableDecision(
    priority="plan",
    priority_score=4,
    fix_now_at=6,
    plan_at=4,
    severity=_signal("severity"),
    exposure=_signal("exposure"),
    corroboration=_signal("corroboration"),
)


class _FakeExplainableRisks:
    """`ExplainableRiskPort` over one fixed surface, or a fixed denial.

    Returns the surface's own ids, SORTED, whatever order the request used, as the real port
    does. So a test can tell the stored snapshot from the request's echo.
    """

    def __init__(
        self, surface: tuple[str, ...] = ("f-1", "f-2"), *, deny: Exception | None = None
    ) -> None:
        self._surface = surface
        self._deny = deny
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    async def explainable_risk(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> ExplainableRisk:
        self.calls.append((project_id, user_id, finding_ids))
        if self._deny is not None:
            raise self._deny
        if tuple(sorted(finding_ids)) != self._surface:
            raise NoCurrentRisk("no current risk")
        return ExplainableRisk(finding_ids=self._surface, decision=_DECISION)


def _use_case(explainable, repository, clock_factory, id_generator):
    return DismissRiskUseCase(
        explainable_risks=explainable,
        dismissals=repository,
        clock=clock_factory(_AT),
        ids=id_generator,
    )


async def test_a_dismissal_stores_the_surfaces_sorted_ids_not_the_requests(
    risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills storing the request's echo: the request sends `f-2, f-1`."""
    repository = risk_dismissal_repository_factory()
    use_case = _use_case(_FakeExplainableRisks(), repository, clock_factory, id_generator)

    dismissal = await use_case.execute(
        project_id=_PROJECT, user_id=_USER, finding_ids=("f-2", "f-1"), reason="accepted"
    )

    assert dismissal.risk.finding_ids == ("f-1", "f-2")
    assert dismissal.state is RiskEventKind.DISMISSED
    assert (dismissal.latest.ordinal, dismissal.latest.actor_user_id) == (1, _USER)
    assert dismissal.latest.reason == "accepted"
    stored = await repository.get(project_id=_PROJECT, risk_id=dismissal.risk.id)
    assert stored == dismissal


async def test_occurred_at_is_the_injected_clocks_value(
    risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Rule 14. Kills a naked `datetime.now()` in the use case."""
    use_case = _use_case(
        _FakeExplainableRisks(), risk_dismissal_repository_factory(), clock_factory, id_generator
    )

    dismissal = await use_case.execute(
        project_id=_PROJECT, user_id=_USER, finding_ids=("f-1", "f-2"), reason="accepted"
    )

    assert dismissal.latest.occurred_at == _AT
    assert dismissal.latest.occurred_at.utcoffset() is not None


@pytest.mark.parametrize(
    "denial",
    [ExplainableRiskAccessDenied("denied"), NoCurrentRisk("stale")],
    ids=["denied", "stale"],
)
async def test_a_refusal_from_the_port_propagates_and_writes_nothing(
    denial, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills dismiss skipping validation: nothing may be stored for a set the port refused."""
    repository = risk_dismissal_repository_factory()
    use_case = _use_case(
        _FakeExplainableRisks(deny=denial), repository, clock_factory, id_generator
    )

    with pytest.raises(type(denial)):
        await use_case.execute(
            project_id=_PROJECT, user_id=_USER, finding_ids=("f-1", "f-2"), reason="accepted"
        )

    assert repository.writes == 0


async def test_a_covered_surface_is_refused_naming_the_covering_record(
    risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills dropping the coverage check, and a refusal that names no record."""
    repository = risk_dismissal_repository_factory()
    first = await _use_case(
        _FakeExplainableRisks(("f-1", "f-2")), repository, clock_factory, id_generator
    ).execute(project_id=_PROJECT, user_id=_USER, finding_ids=("f-1", "f-2"), reason="accepted")
    writes = repository.writes

    # The surface lost `f-2` since: a subset of the snapshot, so still dismissed.
    with pytest.raises(RiskAlreadyDismissed) as refused:
        await _use_case(
            _FakeExplainableRisks(("f-1",)), repository, clock_factory, id_generator
        ).execute(project_id=_PROJECT, user_id=_USER, finding_ids=("f-1",), reason="again")

    assert refused.value.covering_dismissal_id == first.risk.id
    assert repository.writes == writes


async def test_a_surface_that_gained_a_member_can_be_dismissed_again(
    risk_dismissal_repository_factory, clock_factory, id_generator
):
    repository = risk_dismissal_repository_factory()
    await _use_case(
        _FakeExplainableRisks(("f-1",)), repository, clock_factory, id_generator
    ).execute(project_id=_PROJECT, user_id=_USER, finding_ids=("f-1",), reason="accepted")

    second = await _use_case(
        _FakeExplainableRisks(("f-1", "f-2")), repository, clock_factory, id_generator
    ).execute(project_id=_PROJECT, user_id=_USER, finding_ids=("f-1", "f-2"), reason="again")

    assert second.risk.finding_ids == ("f-1", "f-2")
    assert await repository.count_for_project(_PROJECT) == 2


async def test_another_projects_dismissal_covers_nothing_here(
    risk_dismissal_repository_factory, clock_factory, id_generator
):
    repository = risk_dismissal_repository_factory()
    await _use_case(_FakeExplainableRisks(), repository, clock_factory, id_generator).execute(
        project_id="project-other", user_id=_USER, finding_ids=("f-1", "f-2"), reason="there"
    )

    here = await _use_case(
        _FakeExplainableRisks(), repository, clock_factory, id_generator
    ).execute(project_id=_PROJECT, user_id=_USER, finding_ids=("f-1", "f-2"), reason="here")

    assert here.risk.project_id == _PROJECT
