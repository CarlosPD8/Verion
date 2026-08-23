"""The one relationship in the sweep's configuration that is a constraint rather
than a preference (ADR-0021).

`get_stale` selects `running` rows as well as `pending` ones, deliberately: a job
killed by `job_timeout`, or a worker killed after the claim commits, leaves a
`running` row that a pending-only sweep could never recover — permanent silent
loss of exactly the work the record exists to guarantee. The cost is the opposite
failure, re-enqueuing a job that is still alive, and that one is harmless: arq's
job-id dedup makes it a no-op and the work is idempotent by construction.

**What keeps that trade in the harmless direction is `job_timeout <
stale_after`,** and nothing else. arq kills a job at `job_timeout`, so a row that
is `running` past the threshold cannot still have a live job working it — it is
either genuinely stalled or was claimed late behind a queue, and the latter is
bounded by concurrent job count (arq's `max_jobs`, 10 by default) rather than by
backlog depth.

Invert the ordering and the sweep starts continuously re-enqueuing live work
instead, at which point "harmless no-op" stops being true. That is a one-line
change to `job_timeout` in a file that never mentions the sweep, which is the
whole reason this is a test and not a comment.
"""

from datetime import timedelta

from verion.platform.settings import Settings
from verion.platform.worker import WorkerSettings


def test_the_sweep_threshold_outlives_the_job_timeout_it_is_derived_from():
    settings = Settings()

    assert settings.normalization_sweep_stale_after_seconds > WorkerSettings.job_timeout


def test_the_threshold_clears_a_full_job_timeout_with_room_for_queueing():
    """Not just greater — greater by enough that a job which ran to the very edge
    of its timeout, plus the time its claim spent queued behind other work, is
    still not swept while alive. 50% headroom over the timeout."""
    settings = Settings()

    assert (
        timedelta(seconds=settings.normalization_sweep_stale_after_seconds)
        >= timedelta(seconds=WorkerSettings.job_timeout) * 1.5
    )


def test_the_batch_size_bounds_one_tick():
    """A cron tick must not be able to turn a pathological table into an unbounded
    burst of Redis writes."""
    settings = Settings()

    assert 0 < settings.normalization_sweep_batch_size <= 1000
