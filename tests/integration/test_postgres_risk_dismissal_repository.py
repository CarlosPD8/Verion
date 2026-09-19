"""`risks` and `risk_events` in Postgres: G37's partition, and the constraints the domain also
enforces. ADR-0036 decisions 7 and 8.

The CHECKs are exercised with raw inserts, around the domain type, because the domain type
refuses the same rows first. That is the point of enforcing an invariant twice: each half has
to be shown to hold without the other.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import DateTime, text
from sqlalchemy.exc import IntegrityError

from verion.modules.history.adapters.outbound.db.models import (
    RISK_IDENTITY_COLUMNS,
    RISK_PROTECTED_COLUMNS,
    RISK_REFRESHED_COLUMNS,
    RiskEventModel,
    RiskModel,
)
from verion.modules.history.domain.risk import is_blank_reason

_AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_risks_columns_partition_into_identity_protected_and_refreshed():
    """**G37's partition** (ADR-0036 decision 8, ADR-0020 decision 4's layer 1).

    Disjoint and total over `RiskModel`'s columns, with protected and refreshed both empty: user
    state has no column on the one table a projection writer could touch. Kills any column added
    to `risks` without being classified, and any user-state column added there at all.
    """
    columns = {column.name for column in RiskModel.__table__.columns}
    sets = (RISK_IDENTITY_COLUMNS, RISK_PROTECTED_COLUMNS, RISK_REFRESHED_COLUMNS)

    assert columns == RISK_IDENTITY_COLUMNS | RISK_PROTECTED_COLUMNS | RISK_REFRESHED_COLUMNS
    assert sum(len(part) for part in sets) == len(columns)
    assert RISK_PROTECTED_COLUMNS == RISK_REFRESHED_COLUMNS == frozenset()


def test_occurred_at_is_a_timezone_aware_column():
    """Rule 14. Kills a naive `DateTime` on the event log."""
    column_type = RiskEventModel.__table__.columns["occurred_at"].type
    assert isinstance(column_type, DateTime)
    assert column_type.timezone is True


async def _insert_risk(session, risk_id: str = "risk-1") -> None:
    await session.execute(
        text("INSERT INTO risks (id, project_id, finding_ids) VALUES (:id, 'p', ARRAY['f-1'])"),
        {"id": risk_id},
    )


async def _insert_event(session, **overrides) -> None:
    values = {
        "id": "event-1",
        "risk_id": "risk-1",
        "ordinal": 1,
        "kind": "dismissed",
        "actor": "user-1",
        "reason": "accepted",
        "at": _AT,
    }
    values.update(overrides)
    await session.execute(
        text(
            "INSERT INTO risk_events "
            "(id, risk_id, ordinal, kind, actor_user_id, reason, occurred_at) "
            "VALUES (:id, :risk_id, :ordinal, :kind, :actor, :reason, :at)"
        ),
        values,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"reason": None},
        {"reason": "   "},
        {"reason": "\t\n"},
        {"reason": "\x0b\x0c\r"},
        {"reason": "x" * 2001},
        {"kind": "undismissed", "reason": "x" * 2001},
        {"kind": "opened"},
        {"ordinal": 0},
    ],
    ids=[
        "dismissal-without-reason",
        "blank-spaces",
        "blank-tab-newline",
        "blank-vt-ff-cr",
        "over-2000",
        "over-2000-undo",
        "kind",
        "ordinal",
    ],
)
async def test_the_database_refuses_what_the_domain_refuses(db_session, overrides):
    """Kills each CHECK dropped from the migration. `test_schema_matches_models.py` kills the
    same drop from the model."""
    await _insert_risk(db_session)

    with pytest.raises(IntegrityError):
        await _insert_event(db_session, **overrides)
    await db_session.rollback()


@pytest.mark.parametrize("reason", ["   ", "\t\n", "\x0b\x0c\r", "\xa0", " ok "])
async def test_the_database_and_the_domain_agree_on_what_is_blank(db_session, reason):
    """The two halves of "enforced twice" must give ONE answer. `btrim` strips only the
    characters it is given, and Python's bare `strip()` strips all Unicode whitespace, so an
    unqualified `btrim(reason)` passed a tab-only reason the domain refused. Kills either side
    reverting to its default."""
    await _insert_risk(db_session)
    domain_accepts = not is_blank_reason(reason)

    try:
        await _insert_event(db_session, reason=reason)
        await db_session.flush()
        database_accepts = True
    except IntegrityError:
        database_accepts = False
    await db_session.rollback()

    assert database_accepts == domain_accepts


async def test_the_database_accepts_the_bounds(db_session):
    await _insert_risk(db_session)
    await _insert_event(db_session, reason="x" * 2000)
    await _insert_event(db_session, id="event-2", ordinal=2, kind="undismissed", reason=None)
    await db_session.commit()


async def test_a_second_event_at_one_ordinal_is_refused_by_the_constraint(db_session):
    """Kills `uq_risk_events_risk_id_ordinal` dropped from the migration, which is what makes two
    concurrent undos collide rather than both append."""
    await _insert_risk(db_session)
    await _insert_event(db_session)

    with pytest.raises(IntegrityError):
        await _insert_event(db_session, id="event-2", kind="undismissed", reason=None)
    await db_session.rollback()


async def test_a_snapshot_names_at_least_one_finding(db_session):
    with pytest.raises(IntegrityError):
        await db_session.execute(
            text(
                "INSERT INTO risks (id, project_id, finding_ids) VALUES ('r', 'p', ARRAY[]::text[])"
            )
        )
    await db_session.rollback()
