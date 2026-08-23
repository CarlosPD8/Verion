from datetime import UTC, datetime

import pytest

from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)

_REQUESTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_requested_is_pending_with_no_timestamps_and_no_reason():
    run = NormalizationRun.requested(id="n1", scan_id="s1", requested_at=_REQUESTED_AT)

    assert run.status is NormalizationRunStatus.PENDING
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
        status=NormalizationRunStatus.FAILED,
        requested_at=_REQUESTED_AT,
        started_at=_REQUESTED_AT,
        finished_at=_REQUESTED_AT,
        failure_reason="unparseable semgrep output",
    )

    assert run.failure_reason == "unparseable semgrep output"


def test_timestamps_are_deliberately_unconstrained():
    """Not an oversight — recorded as a test so a future reader does not "fix"
    it. started_at/finished_at belong to transitions M4.4 writes; constraining
    them here would pin a state machine M4.0 does not implement (ADR-0017
    decision 1).
    """
    run = NormalizationRun(
        id="n1",
        scan_id="s1",
        status=NormalizationRunStatus.PENDING,
        requested_at=_REQUESTED_AT,
        started_at=_REQUESTED_AT,
        finished_at=_REQUESTED_AT,
        failure_reason=None,
    )

    assert run.status is NormalizationRunStatus.PENDING
