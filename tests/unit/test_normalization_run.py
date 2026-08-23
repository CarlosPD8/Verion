from datetime import UTC, datetime

import pytest

from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)

_REQUESTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
_STARTED_AT = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
_FINISHED_AT = datetime(2026, 1, 1, 0, 2, tzinfo=UTC)


def test_requested_is_pending_with_no_timestamps_and_no_reason():
    run = NormalizationRun.requested(
        id="n1", scan_id="s1", project_id="p1", requested_at=_REQUESTED_AT
    )

    assert run.status is NormalizationRunStatus.PENDING
    assert run.project_id == "p1"
    assert run.requested_at == _REQUESTED_AT
    assert run.started_at is None
    assert run.finished_at is None
    assert run.failure_reason is None


# The invariant, from both directions. Enforced here and again by
# ck_normalization_runs_failure_reason_shape, the same two-place idiom ADR-016
# decision 2 established for ScanResult — a failure_reason must mean "this
# stage failed", and a failed row must say why, or the reader has to guess.


def test_failed_without_a_reason_is_rejected():
    with pytest.raises(ValueError, match="is FAILED but has no failure_reason"):
        NormalizationRun(
            id="n1",
            scan_id="s1",
            project_id="p1",
            status=NormalizationRunStatus.FAILED,
            requested_at=_REQUESTED_AT,
            started_at=None,
            finished_at=None,
            failure_reason=None,
        )


@pytest.mark.parametrize(
    "status",
    [
        NormalizationRunStatus.PENDING,
        NormalizationRunStatus.RUNNING,
        NormalizationRunStatus.COMPLETED,
    ],
)
def test_any_non_failed_status_carrying_a_reason_is_rejected(status):
    """Parametrized over all three rather than just one: the CHECK constraint
    is written as `status <> 'failed'`, so a domain guard that only covered
    COMPLETED would silently diverge from it."""
    with pytest.raises(ValueError, match="carries a failure_reason"):
        NormalizationRun(
            id="n1",
            scan_id="s1",
            project_id="p1",
            status=status,
            requested_at=_REQUESTED_AT,
            started_at=None,
            finished_at=None,
            failure_reason="boom",
        )


def test_failed_with_a_reason_is_accepted():
    run = NormalizationRun(
        id="n1",
        scan_id="s1",
        project_id="p1",
        status=NormalizationRunStatus.FAILED,
        requested_at=_REQUESTED_AT,
        started_at=_REQUESTED_AT,
        finished_at=_REQUESTED_AT,
        failure_reason="unparseable semgrep output",
    )

    assert run.failure_reason == "unparseable semgrep output"


def test_timestamps_are_constrained_per_status():
    """The inverse of M4.0's `test_timestamps_are_deliberately_unconstrained`,
    which this replaces rather than deletes.

    That test existed "so a future reader does not 'fix' it" — the timestamps
    were unconstrained because they belong to transitions M4.4 writes. M4.4 is
    that issue, the transitions exist below, and the exact object that test
    constructed and accepted (a PENDING run carrying both timestamps) is now
    rejected. Kept as a test rather than dropped so the reversal is visible in
    the file where the original claim lived, not only in a commit message.
    """
    with pytest.raises(ValueError, match="started_at is set"):
        NormalizationRun(
            id="n1",
            scan_id="s1",
            project_id="p1",
            status=NormalizationRunStatus.PENDING,
            requested_at=_REQUESTED_AT,
            started_at=_REQUESTED_AT,
            finished_at=_REQUESTED_AT,
            failure_reason=None,
        )


# The timestamp invariant, stated per status and asserted per status. The
# parametrisation is exhaustive over NormalizationRunStatus on purpose: the
# failure this guards is a status left unconstrained by omission, which is how
# RUNNING would otherwise have kept accepting a finished_at.
@pytest.mark.parametrize(
    ("status", "started_at", "finished_at", "failure_reason"),
    [
        (NormalizationRunStatus.PENDING, None, None, None),
        (NormalizationRunStatus.RUNNING, _REQUESTED_AT, None, None),
        (NormalizationRunStatus.COMPLETED, _REQUESTED_AT, _FINISHED_AT, None),
        (NormalizationRunStatus.FAILED, _REQUESTED_AT, _FINISHED_AT, "boom"),
    ],
)
def test_every_status_has_exactly_one_legal_timestamp_shape(
    status, started_at, finished_at, failure_reason
):
    run = NormalizationRun(
        id="n1",
        scan_id="s1",
        project_id="p1",
        status=status,
        requested_at=_REQUESTED_AT,
        started_at=started_at,
        finished_at=finished_at,
        failure_reason=failure_reason,
    )

    assert run.status is status


@pytest.mark.parametrize(
    ("status", "started_at", "finished_at", "failure_reason", "match"),
    [
        (NormalizationRunStatus.PENDING, _REQUESTED_AT, None, None, "started_at is set"),
        (NormalizationRunStatus.RUNNING, None, None, None, "started_at is None"),
        (
            NormalizationRunStatus.RUNNING,
            _REQUESTED_AT,
            _FINISHED_AT,
            None,
            "finished_at is set",
        ),
        (NormalizationRunStatus.COMPLETED, _REQUESTED_AT, None, None, "finished_at is None"),
        (NormalizationRunStatus.FAILED, _REQUESTED_AT, None, "boom", "finished_at is None"),
    ],
)
def test_a_timestamp_shape_no_status_allows_is_rejected(
    status, started_at, finished_at, failure_reason, match
):
    with pytest.raises(ValueError, match=match):
        NormalizationRun(
            id="n1",
            scan_id="s1",
            project_id="p1",
            status=status,
            requested_at=_REQUESTED_AT,
            started_at=started_at,
            finished_at=finished_at,
            failure_reason=failure_reason,
        )


def test_a_run_cannot_finish_before_it_started():
    with pytest.raises(ValueError, match="before it started"):
        NormalizationRun(
            id="n1",
            scan_id="s1",
            project_id="p1",
            status=NormalizationRunStatus.COMPLETED,
            requested_at=_REQUESTED_AT,
            started_at=_FINISHED_AT,
            finished_at=_REQUESTED_AT,
            failure_reason=None,
        )


# ---------------------------------------------------------------------------
# Transitions (M4.4). COMPLETED is the only terminal state; see the entity's
# docstring for why FAILED deliberately is not.
# ---------------------------------------------------------------------------


def _requested() -> NormalizationRun:
    return NormalizationRun.requested(
        id="n1", scan_id="s1", project_id="p1", requested_at=_REQUESTED_AT
    )


def test_start_claims_a_pending_run_and_records_when():
    run = _requested().start(_STARTED_AT)

    assert run.status is NormalizationRunStatus.RUNNING
    assert run.started_at == _STARTED_AT
    assert run.finished_at is None


def test_a_reclaim_preserves_the_original_start_time():
    """Mirrors RunScanUseCase's `scan.started_at or self._clock.now()`: a retry
    re-runs the work, it does not restart the clock."""
    first = _requested().start(_STARTED_AT)

    second = first.start(_FINISHED_AT)

    assert second.status is NormalizationRunStatus.RUNNING
    assert second.started_at == _STARTED_AT


def test_a_failed_run_can_be_reclaimed_and_its_reason_is_cleared():
    """The property that keeps arq's retry alive. The job writes FAILED and
    re-raises for a transient failure; if FAILED were terminal, the retry would
    find a row it could not claim and the retry would be decorative.

    The reason is cleared because a RUNNING row carrying one is rejected by both
    __post_init__ and ck_normalization_runs_failure_reason_shape.
    """
    failed = _requested().start(_STARTED_AT).fail(_FINISHED_AT, "transient DB error")

    reclaimed = failed.start(_FINISHED_AT)

    assert reclaimed.status is NormalizationRunStatus.RUNNING
    assert reclaimed.failure_reason is None
    assert reclaimed.finished_at is None
    assert reclaimed.started_at == _STARTED_AT


def test_a_completed_run_is_terminal():
    completed = _requested().start(_STARTED_AT).complete(_FINISHED_AT)

    with pytest.raises(ValueError, match="already COMPLETED"):
        completed.start(_FINISHED_AT)


@pytest.mark.parametrize(
    "transition",
    [
        lambda run: run.complete(_FINISHED_AT),
        lambda run: run.fail(_FINISHED_AT, "boom"),
    ],
    ids=["complete", "fail"],
)
def test_a_terminal_transition_requires_a_claim_first(transition):
    """No status skips RUNNING. A run that was never claimed cannot report an
    outcome, because nothing produced one.

    Parametrised over callables rather than a name plus a branch in the body:
    the branch would be an expression statement, which is both weaker to read and
    the kind of structural shape a lint autofix can rewrite (G8)."""
    run = _requested()

    with pytest.raises(ValueError, match="cannot go straight to"):
        transition(run)


def test_fail_refuses_an_empty_reason():
    """An empty string satisfies the IS NOT NULL CHECK while telling a reader
    nothing — the same reason native_severity records "(absent)" rather than ""."""
    running = _requested().start(_STARTED_AT)

    with pytest.raises(ValueError, match="empty reason"):
        running.fail(_FINISHED_AT, "")
