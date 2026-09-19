from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# ADR-0036 decision 7. The figure is borrowed from ADR-0034's M6 check, which bounds a narration
# every member reads. That check bounds model output; this is the first bound on member-supplied
# input, enforced again by `ck_risk_events_reason_length` (G91 records the rest).
MAX_REASON_CHARS = 2000

# What counts as blank, stated as one explicit set so that the domain, the request schemas and
# `ck_risk_events_reason_not_blank` agree: Postgres's `btrim` strips only what it is told to,
# while Python's bare `str.strip()` strips every Unicode whitespace character. ASCII whitespace
# only, in all three places. A reason of only U+00A0 is therefore not blank, and that is the
# same answer everywhere.
REASON_BLANK_CHARS = " \t\n\r\x0b\x0c"


def is_blank_reason(reason: str) -> bool:
    return not reason.strip(REASON_BLANK_CHARS)


class RiskEventKind(StrEnum):
    """What happened to a dismissal record. There is no `opened`: a projection has no moment
    of creation (ADR-0036 decision 7), and `resolved` is M9.1's."""

    DISMISSED = "dismissed"
    UNDISMISSED = "undismissed"


@dataclass(frozen=True, kw_only=True)
class Risk:
    """A dismissal record: the first stored Risk in the system (ADR-0036 decision 1).

    **Not the live Risk.** A candidate Risk is still a projection with no identifier (ADR-0025
    decision 1). This is a snapshot of one surface's members at the moment a user dismissed it,
    written once and never refreshed, so its `id` addresses the record and cannot repoint.

    **Identity columns only.** User-set state lives in `RiskEvent`, never here, which is what
    resolves **G37**: no statement that rewrites this row from the projection exists, and if one
    is ever written it finds no user state to clobber.
    """

    id: str
    project_id: str
    finding_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.finding_ids:
            raise ValueError("A dismissal snapshot must name at least one finding")
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("A dismissal snapshot must not repeat a finding id")


@dataclass(frozen=True, kw_only=True)
class RiskEvent:
    """One append-only entry in a dismissal record's log (ADR-0036 decision 7).

    **`ordinal` is the order**, never `occurred_at`, which ties under one clock tick. The first
    event is 1. A record is dismissed once and undone at most once, so it holds ordinals 1 and
    at most 2.

    The reason's invariants are enforced twice, here and by `risk_events`' CHECK constraints,
    ADR-0017 decision 1's idiom: required and non-blank for `dismissed`, non-blank whenever
    present, and at most `MAX_REASON_CHARS` characters.
    """

    id: str
    risk_id: str
    ordinal: int
    kind: RiskEventKind
    actor_user_id: str
    reason: str | None
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.ordinal < 1:
            raise ValueError("An event's ordinal starts at 1")
        if self.kind is RiskEventKind.DISMISSED and self.reason is None:
            raise ValueError("A dismissal requires a reason")
        if self.reason is not None:
            if is_blank_reason(self.reason):
                raise ValueError("A reason must not be blank")
            if len(self.reason) > MAX_REASON_CHARS:
                raise ValueError(f"A reason is at most {MAX_REASON_CHARS} characters")
        # Rule 14: every timestamp is UTC-aware, via ClockPort.
        if self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")


@dataclass(frozen=True, kw_only=True)
class RiskDismissal:
    """A dismissal record with its latest event: what one list item or write response shows."""

    risk: Risk
    latest: RiskEvent

    def __post_init__(self) -> None:
        if self.latest.risk_id != self.risk.id:
            raise ValueError("A dismissal's latest event must belong to it")

    @property
    def state(self) -> RiskEventKind:
        return self.latest.kind


@dataclass(frozen=True, kw_only=True)
class Snapshot:
    """What the same-Risk rule reads about one record: its members, and its current state."""

    risk_id: str
    finding_ids: tuple[str, ...]
    state: RiskEventKind
    state_since: datetime


def covering_dismissal(current_ids: Iterable[str], snapshots: Iterable[Snapshot]) -> str | None:
    """The record that dismisses this surface now, or `None`. ADR-0036 decision 2.

    **A current surface is dismissed iff its finding-id set is a SUBSET of some snapshot whose
    latest event is `dismissed`.** A dropped member or a split keeps the dismissal on every
    half; a new member reopens it. So the rule never hides a finding that was not in a snapshot.
    A superset or any-overlap rule would hide it, which is why neither is used.

    When several records cover the surface, the one named is the most recently dismissed, ties
    broken by the lowest record id. That picks one id deterministically for the 409 body
    (decision 11). It is not an event order, which is the ordinal's.
    """
    current = frozenset(current_ids)
    if not current:
        # An empty set is a subset of everything. No surface is empty, so nothing is covered.
        return None
    covering = sorted(
        (
            snapshot
            for snapshot in snapshots
            if snapshot.state is RiskEventKind.DISMISSED
            and current <= frozenset(snapshot.finding_ids)
        ),
        key=lambda snapshot: snapshot.risk_id,
    )
    if not covering:
        return None
    # `max` returns the first maximal element, so among equal times the lowest id wins.
    return max(covering, key=lambda snapshot: snapshot.state_since).risk_id


def is_dismissed(current_ids: Iterable[str], snapshots: Iterable[Snapshot]) -> bool:
    """Whether some active snapshot covers this surface. M8.2's overlay will read this."""
    return covering_dismissal(current_ids, snapshots) is not None
