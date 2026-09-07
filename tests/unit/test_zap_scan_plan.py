"""What `_build_plan_yaml` emits, with and without consent (ADR-0024 decisions 4 and 5).

Unit tests over the plan document rather than over a container: the decision this
commit implements is *which jobs the plan carries*, and that is settled by reading the
YAML. **What no test here or anywhere else covers is what ZAP does with it** — the two
CI-reachable ZAP targets are the `_MinimalTargetHandler` classes in
`tests/integration/test_zap_adapter.py` and `tests/integration/test_multi_scanner_dispatch.py`,
and both serve one static `<html>` body with no injectable sink, so the `activeScan`
branch ships with no container-bound test exercising it. That is M5.9's, and the
parameter spellings not being verified against the pinned image is already registered
as **G42**.
"""

import inspect

import yaml

from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import (
    ZapAdapter,
    _build_plan_yaml,
)
from verion.modules.scanning.domain.scan_options import ScanOptions

_TARGET = "http://target.example:8080/"


def _jobs(consented: bool) -> list[dict]:
    plan = yaml.safe_load(_build_plan_yaml(_TARGET, ScanOptions(active_scan_consented=consented)))
    return plan["jobs"]


def _job_types(consented: bool) -> list[str]:
    return [job["type"] for job in _jobs(consented)]


def test_without_consent_the_plan_carries_no_active_scan_job():
    """The pre-M5.4 job LIST, and the branch every existing project takes. Not the
    pre-M5.4 plan: `passiveScan-wait`'s ceiling drops on this branch too, so the
    committed corpus was captured under a configuration neither branch now runs."""
    assert "activeScan" not in _job_types(consented=False)
    assert _job_types(consented=False) == ["spider", "passiveScan-wait", "report"]


def test_with_consent_the_active_scan_job_sits_between_passive_wait_and_report():
    """Position is asserted, not just presence: ADR-0024 decision 5 places it after
    `passiveScan-wait` and before `report`. Ordered before the passive wait it would
    attack the target before the passive queue had drained; after `report` it would run
    with nothing left to write its findings into."""
    assert _job_types(consented=True) == [
        "spider",
        "passiveScan-wait",
        "activeScan",
        "report",
    ]


def test_the_active_scan_job_carries_exactly_the_decided_parameters():
    """Compared whole rather than key by key, so a parameter ADDED here fails too — an
    unreviewed knob on an attack tool is the thing this assertion is for, and a
    subset check would let one through."""
    active = next(job for job in _jobs(consented=True) if job["type"] == "activeScan")

    assert active["parameters"] == {
        "context": "verion-target",
        "maxRuleDurationInMins": 1,
        "maxScanDurationInMins": 3,
        "threadPerHost": 2,
    }


def test_the_plans_durations_sum_below_the_adapters_own_timeout():
    """ADR-0024 decision 5's first inequality, asserted rather than trusted to a
    comment: the plan's ceilings are inner bounds under `ZapAdapter.timeout_seconds`,
    and if they ever exceed it the caps stop binding and the slow path becomes a
    `ScannerExecutionFailed` row instead of a bounded scan.

    Read off the plan and the adapter's default rather than restated, so lowering the
    timeout or raising a cap fails here instead of in production.
    """
    jobs = _jobs(consented=True)
    minutes = (
        next(j for j in jobs if j["type"] == "spider")["parameters"]["maxDuration"]
        + next(j for j in jobs if j["type"] == "passiveScan-wait")["parameters"]["maxDuration"]
        + next(j for j in jobs if j["type"] == "activeScan")["parameters"]["maxScanDurationInMins"]
    )
    timeout_default = inspect.signature(ZapAdapter.__init__).parameters["timeout_seconds"].default

    assert minutes * 60 < timeout_default


def test_the_target_url_is_never_interpolated_into_the_plan_text():
    """Unchanged by this commit and re-asserted because the plan grew a branch:
    `yaml.safe_dump` is what stops a target containing YAML-special characters from
    restructuring the document, and an `activeScan` job appended by string
    concatenation would have quietly reintroduced that."""
    hostile = 'http://evil.example/#\n- type: activeScan\n  parameters: {"context": "x"}'
    plan = yaml.safe_load(_build_plan_yaml(hostile, ScanOptions(active_scan_consented=False)))

    assert [job["type"] for job in plan["jobs"]] == ["spider", "passiveScan-wait", "report"]
    assert plan["env"]["contexts"][0]["urls"] == [hostile]
