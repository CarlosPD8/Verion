"""`RiskDismissalRepositoryPort`'s contract, held by the fake AND the Postgres adapter alike.

**Why the fake is tested at all.** Every unit test of `history`'s use cases runs against
`InMemoryRiskDismissalRepository`, and a fake nobody checks against the real adapter proves only
the consumer's side of a contract (**G65**). This file runs one scenario both ways and asks both
the same questions.

The fake arrives through `risk_dismissal_repository_factory` (`tests/conftest.py`), so it is the
same class every unit test uses.
"""

from datetime import UTC, datetime, timedelta

import pytest

from verion.modules.history.adapters.outbound.db.repository import (
    PostgresRiskDismissalRepository,
)
from verion.modules.history.domain.risk import Risk, RiskEvent, RiskEventKind

_PROJECT = "project-contract"
_OTHER = "project-other"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _event(risk_id: str, ordinal: int, kind: RiskEventKind, at: datetime) -> RiskEvent:
    return RiskEvent(
        id=f"{risk_id}-event-{ordinal}",
        risk_id=risk_id,
        ordinal=ordinal,
        kind=kind,
        actor_user_id="user-1",
        reason="reason" if kind is RiskEventKind.DISMISSED else None,
        occurred_at=at,
    )


async def _postgres(db_session, _factory):
    return PostgresRiskDismissalRepository(db_session)


async def _fake(_db_session, factory):
    return factory()


@pytest.mark.parametrize("build", [_fake, _postgres], ids=["fake", "postgres"])
async def test_both_implementations_answer_the_same_questions(
    build, db_session, risk_dismissal_repository_factory
):
    """Kills a fake that drifts from the adapter: the latest event by `occurred_at` rather than by
    ordinal (the undo below is stamped EARLIER than the dismissal it follows), another project's
    record leaking into a read, a lost ordinal race reported as success, or the page order."""
    repository = await build(db_session, risk_dismissal_repository_factory)

    old = Risk(id="risk-old", project_id=_PROJECT, finding_ids=("f-1", "f-2"))
    new = Risk(id="risk-new", project_id=_PROJECT, finding_ids=("f-3",))
    elsewhere = Risk(id="risk-elsewhere", project_id=_OTHER, finding_ids=("f-1",))
    await repository.add(old, _event(old.id, 1, RiskEventKind.DISMISSED, _AT))
    await repository.add(
        new, _event(new.id, 1, RiskEventKind.DISMISSED, _AT + timedelta(minutes=5))
    )
    await repository.add(elsewhere, _event(elsewhere.id, 1, RiskEventKind.DISMISSED, _AT))

    # An undo stamped before the dismissal: only the ordinal can say it is the latest.
    undo = _event(old.id, 2, RiskEventKind.UNDISMISSED, _AT - timedelta(minutes=1))
    assert await repository.append_event(undo) is True
    # The same ordinal again: a lost race writes nothing and says so.
    assert await repository.append_event(_event(old.id, 2, RiskEventKind.UNDISMISSED, _AT)) is False

    got = await repository.get(project_id=_PROJECT, risk_id=old.id)
    assert got is not None
    assert (got.risk, got.latest, got.state) == (old, undo, RiskEventKind.UNDISMISSED)
    assert await repository.get(project_id=_PROJECT, risk_id=elsewhere.id) is None
    assert await repository.get(project_id=_PROJECT, risk_id="absent") is None

    snapshots = {
        snapshot.risk_id: snapshot for snapshot in await repository.snapshots_for_project(_PROJECT)
    }
    assert set(snapshots) == {old.id, new.id}
    assert (snapshots[old.id].finding_ids, snapshots[old.id].state) == (
        ("f-1", "f-2"),
        RiskEventKind.UNDISMISSED,
    )
    assert (snapshots[new.id].state, snapshots[new.id].state_since) == (
        RiskEventKind.DISMISSED,
        _AT + timedelta(minutes=5),
    )

    page = await repository.list_for_project(project_id=_PROJECT, limit=10, offset=0)
    assert [item.risk.id for item in page] == [new.id, old.id]
    assert page[1].latest == undo
    assert [
        item.risk.id
        for item in await repository.list_for_project(project_id=_PROJECT, limit=1, offset=1)
    ] == [old.id]
    assert await repository.count_for_project(_PROJECT) == 2
    assert await repository.count_for_project(_OTHER) == 1
