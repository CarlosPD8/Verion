"""The same-Risk rule and the dismissal record's invariants. ADR-0036 decisions 2, 7 and 11.

**The superset case is the one that matters.** A rule that treated a surface which GAINED a
member as still dismissed would hide a finding nobody dismissed, which is the failure the rule
exists to prevent. The mutation replacing `<=` with `>=` is killed by
`test_a_surface_that_gained_a_member_is_not_dismissed` (among others), and the "any overlap"
mutation by that test and `test_an_overlapping_surface_is_not_dismissed`.
"""

from datetime import UTC, datetime, timedelta

import pytest

from verion.modules.history.domain.risk import (
    MAX_REASON_CHARS,
    Risk,
    RiskDismissal,
    RiskEvent,
    RiskEventKind,
    Snapshot,
    covering_dismissal,
    is_dismissed,
)

_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _snapshot(
    risk_id: str,
    *finding_ids: str,
    state: RiskEventKind = RiskEventKind.DISMISSED,
    since: datetime = _AT,
) -> Snapshot:
    return Snapshot(risk_id=risk_id, finding_ids=finding_ids, state=state, state_since=since)


def _event(**overrides) -> RiskEvent:
    values = {
        "id": "event-1",
        "risk_id": "risk-1",
        "ordinal": 1,
        "kind": RiskEventKind.DISMISSED,
        "actor_user_id": "user-1",
        "reason": "accepted risk",
        "occurred_at": _AT,
    }
    values.update(overrides)
    return RiskEvent(**values)


# ---------------------------------------------------------------------------
# The subset rule
# ---------------------------------------------------------------------------


def test_the_exact_snapshot_is_dismissed():
    snapshots = [_snapshot("risk-1", "f-1", "f-2")]

    assert covering_dismissal(("f-1", "f-2"), snapshots) == "risk-1"
    assert is_dismissed(("f-2", "f-1"), snapshots)


def test_a_surface_that_lost_a_member_stays_dismissed():
    assert covering_dismissal(("f-1",), [_snapshot("risk-1", "f-1", "f-2")]) == "risk-1"


def test_a_surface_that_gained_a_member_is_not_dismissed():
    """The security-relevant case: `f-3` was never dismissed, so the Risk reopens."""
    assert covering_dismissal(("f-1", "f-2", "f-3"), [_snapshot("risk-1", "f-1", "f-2")]) is None


def test_an_overlapping_surface_is_not_dismissed():
    """Kills an any-overlap rule: `f-9` was never in the snapshot."""
    assert not is_dismissed(("f-2", "f-9"), [_snapshot("risk-1", "f-1", "f-2")])


def test_a_disjoint_surface_is_not_dismissed():
    assert not is_dismissed(("f-9",), [_snapshot("risk-1", "f-1", "f-2")])


def test_both_halves_of_a_split_stay_dismissed():
    """A derived surface split by a map change (G53): each half is a subset of the snapshot."""
    snapshots = [_snapshot("risk-1", "semgrep-1", "zap-1", "zap-2")]

    assert covering_dismissal(("semgrep-1",), snapshots) == "risk-1"
    assert covering_dismissal(("zap-1", "zap-2"), snapshots) == "risk-1"


def test_an_undone_snapshot_dismisses_nothing():
    """Kills a rule that ignores the record's latest kind."""
    snapshots = [_snapshot("risk-1", "f-1", state=RiskEventKind.UNDISMISSED)]

    assert covering_dismissal(("f-1",), snapshots) is None


def test_an_empty_surface_is_never_covered():
    assert covering_dismissal((), [_snapshot("risk-1", "f-1")]) is None


def test_the_most_recently_dismissed_covering_record_is_named():
    """Kills returning the first match or the oldest."""
    older = _snapshot("risk-a", "f-1", "f-2", since=_AT)
    newer = _snapshot("risk-b", "f-1", "f-3", since=_AT + timedelta(minutes=1))

    assert covering_dismissal(("f-1",), [older, newer]) == "risk-b"
    assert covering_dismissal(("f-1",), [newer, older]) == "risk-b"


def test_an_undone_record_is_skipped_even_when_it_is_the_newest():
    older = _snapshot("risk-a", "f-1", since=_AT)
    undone = _snapshot(
        "risk-b", "f-1", state=RiskEventKind.UNDISMISSED, since=_AT + timedelta(minutes=1)
    )

    assert covering_dismissal(("f-1",), [undone, older]) == "risk-a"


def test_equal_times_name_the_lowest_record_id_whatever_the_input_order():
    first = _snapshot("risk-a", "f-1")
    second = _snapshot("risk-b", "f-1")

    assert covering_dismissal(("f-1",), [second, first]) == "risk-a"
    assert covering_dismissal(("f-1",), [first, second]) == "risk-a"


# ---------------------------------------------------------------------------
# The record's invariants
# ---------------------------------------------------------------------------


def test_a_snapshot_names_at_least_one_finding_and_none_twice():
    with pytest.raises(ValueError):
        Risk(id="risk-1", project_id="p", finding_ids=())
    with pytest.raises(ValueError):
        Risk(id="risk-1", project_id="p", finding_ids=("f-1", "f-1"))


def test_a_dismissal_requires_a_reason():
    with pytest.raises(ValueError):
        _event(reason=None)


def test_an_undo_may_omit_its_reason():
    assert _event(kind=RiskEventKind.UNDISMISSED, ordinal=2, reason=None).reason is None


@pytest.mark.parametrize("kind", list(RiskEventKind))
@pytest.mark.parametrize("blank", ["  \t ", "\n", "\x0b\x0c\r"])
def test_a_reason_is_never_blank(kind, blank):
    with pytest.raises(ValueError):
        _event(kind=kind, reason=blank)


def test_a_reason_is_at_most_the_bound():
    assert len(_event(reason="x" * MAX_REASON_CHARS).reason or "") == MAX_REASON_CHARS
    with pytest.raises(ValueError):
        _event(reason="x" * (MAX_REASON_CHARS + 1))


def test_an_ordinal_starts_at_one():
    with pytest.raises(ValueError):
        _event(ordinal=0)


def test_occurred_at_must_be_timezone_aware():
    """Rule 14."""
    with pytest.raises(ValueError):
        _event(occurred_at=datetime(2026, 1, 1))


def test_a_dismissal_state_is_its_latest_events_kind():
    risk = Risk(id="risk-1", project_id="p", finding_ids=("f-1",))
    undo = _event(id="event-2", ordinal=2, kind=RiskEventKind.UNDISMISSED, reason=None)

    assert RiskDismissal(risk=risk, latest=undo).state is RiskEventKind.UNDISMISSED
    with pytest.raises(ValueError):
        RiskDismissal(risk=risk, latest=_event(risk_id="risk-other"))
