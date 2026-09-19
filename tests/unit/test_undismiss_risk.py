"""`UndismissRiskUseCase` over in-memory ports. ADR-0036 decisions 7, 10 and 11."""

from datetime import UTC, datetime, timedelta

import pytest

from verion.modules.history.application.undismiss_risk import UndismissRiskUseCase
from verion.modules.history.domain.exceptions import (
    RiskDismissalAccessDenied,
    RiskDismissalNotFound,
    RiskEventConflict,
    RiskNotDismissed,
)
from verion.modules.history.domain.risk import Risk, RiskEvent, RiskEventKind

_PROJECT = "project-1"
_OWNER = "user-owner"
_MEMBER = "user-member"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_LATER = _AT + timedelta(hours=1)


async def _dismissed(repository, *, risk_id="risk-1", project_id=_PROJECT) -> Risk:
    risk = Risk(id=risk_id, project_id=project_id, finding_ids=("f-1",))
    await repository.add(
        risk,
        RiskEvent(
            id=f"{risk_id}-event-1",
            risk_id=risk_id,
            ordinal=1,
            kind=RiskEventKind.DISMISSED,
            actor_user_id=_OWNER,
            reason="accepted",
            occurred_at=_AT,
        ),
    )
    return risk


def _use_case(project_access, repository, clock_factory, id_generator):
    return UndismissRiskUseCase(
        project_access=project_access,
        dismissals=repository,
        clock=clock_factory(_LATER),
        ids=id_generator,
    )


async def test_undo_appends_a_second_event_and_changes_nothing_else(
    project_access, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills undo deleting or rewriting the dismissal: both events survive, in order."""
    project_access.permit(_PROJECT, _MEMBER)
    repository = risk_dismissal_repository_factory()
    risk = await _dismissed(repository)
    first = repository.events_of(risk.id)[0]

    undone = await _use_case(project_access, repository, clock_factory, id_generator).execute(
        project_id=_PROJECT, user_id=_MEMBER, dismissal_id=risk.id, reason=None
    )

    assert undone.state is RiskEventKind.UNDISMISSED
    assert (undone.latest.ordinal, undone.latest.actor_user_id) == (2, _MEMBER)
    assert undone.latest.occurred_at == _LATER
    assert repository.events_of(risk.id) == [first, undone.latest]
    assert undone.risk == risk


async def test_a_denied_caller_is_refused_before_any_read(
    project_access, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills the verdict moving below the read: the repository must not be asked anything."""

    class _Exploding:
        def __getattr__(self, name):
            raise AssertionError(f"repository touched: {name}")

    with pytest.raises(RiskDismissalAccessDenied):
        await _use_case(project_access, _Exploding(), clock_factory, id_generator).execute(
            project_id=_PROJECT, user_id=_MEMBER, dismissal_id="risk-1", reason=None
        )

    assert project_access.calls == [(_PROJECT, _MEMBER)]


async def test_another_projects_record_is_not_found(
    project_access, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills undo not matching the project: a member here cannot undo a record elsewhere."""
    project_access.permit(_PROJECT, _MEMBER)
    repository = risk_dismissal_repository_factory()
    elsewhere = await _dismissed(repository, project_id="project-other")

    with pytest.raises(RiskDismissalNotFound):
        await _use_case(project_access, repository, clock_factory, id_generator).execute(
            project_id=_PROJECT, user_id=_MEMBER, dismissal_id=elsewhere.id, reason=None
        )

    assert len(repository.events_of(elsewhere.id)) == 1


async def test_an_undone_record_cannot_be_undone_again(
    project_access, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """Kills dropping the state check: a third event would be written."""
    project_access.permit(_PROJECT, _MEMBER)
    repository = risk_dismissal_repository_factory()
    risk = await _dismissed(repository)
    use_case = _use_case(project_access, repository, clock_factory, id_generator)
    await use_case.execute(project_id=_PROJECT, user_id=_MEMBER, dismissal_id=risk.id, reason=None)

    with pytest.raises(RiskNotDismissed):
        await use_case.execute(
            project_id=_PROJECT, user_id=_MEMBER, dismissal_id=risk.id, reason=None
        )

    assert len(repository.events_of(risk.id)) == 2


async def test_a_lost_ordinal_race_is_a_conflict(
    project_access, risk_dismissal_repository_factory, clock_factory, id_generator
):
    """The repository reports the ordinal taken; the use case must not claim success."""
    project_access.permit(_PROJECT, _MEMBER)
    repository = risk_dismissal_repository_factory()
    risk = await _dismissed(repository)

    async def _taken(event):
        return False

    repository.append_event = _taken

    with pytest.raises(RiskEventConflict):
        await _use_case(project_access, repository, clock_factory, id_generator).execute(
            project_id=_PROJECT, user_id=_MEMBER, dismissal_id=risk.id, reason="undo"
        )
