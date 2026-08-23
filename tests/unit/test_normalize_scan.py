"""`NormalizeScanUseCase` against in-memory ports (M4.4).

The two contracts ADR-0020 decision 5 calls "compile-time invisible" are pinned
here and again in `tests/integration/test_normalize_scan_pipeline.py`. Both
layers are needed and neither is redundant: the count-and-shape assertions are
cheap and precise here, while the one that depends on the upsert RESOLVING an id
against a row written by an earlier scan is only non-vacuous against a real
`RETURNING` (see `InMemoryFindingRepository`'s docstring for how far the fake
goes).
"""

import json
from datetime import UTC, datetime

import pytest

from verion.modules.normalization.application.normalize_scan import NormalizeScanUseCase
from verion.modules.normalization.domain.exceptions import UnknownScannerOutput
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
from verion.modules.scanning.domain.scan_result import ScanResult

_SCAN = "scan-1"
_PROJECT = "project-1"
_REQUESTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
_NOW = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)


def _claimed_run() -> NormalizationRun:
    return NormalizationRun.requested(
        id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_REQUESTED_AT
    ).start(_REQUESTED_AT)


def _use_case(results, findings, runs, ids, clock):
    return NormalizeScanUseCase(
        scan_results=results,
        findings=findings,
        normalization_runs=runs,
        id_generator=ids,
        clock=clock,
    )


async def _seed_result(scan_results, tool: str, raw_output: str) -> None:
    await scan_results.upsert(
        ScanResult.succeeded(id=f"sr-{tool}", scan_id=_SCAN, tool=tool, raw_output=raw_output)
    )


# ---------------------------------------------------------------------------
# The happy path, and the two degenerate cases ADR-0017 decision 3 fixed
# ---------------------------------------------------------------------------


async def test_a_scan_s_succeeded_output_becomes_findings_and_sightings(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
    scanner_fixture,
):
    run = _claimed_run()
    normalization_run_repository.seed(run)
    await _seed_result(scan_result_repository, "semgrep", scanner_fixture("semgrep_scan.json"))

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    findings = await finding_repository.get_by_project_id(_PROJECT)
    assert findings
    assert all(finding.project_id == _PROJECT for finding in findings)
    # One sighting per finding, all against this scan.
    assert len(finding_repository.sighting_calls) == len(findings)
    assert {sighting.scan_id for sighting in finding_repository.sighting_calls} == {_SCAN}
    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.COMPLETED
    assert stored_run.finished_at == clock.now()


async def test_a_failed_tool_contributes_nothing_and_the_run_still_completes(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
    scanner_fixture,
):
    """The `PARTIAL` case, at the use-case layer.

    There is no branch for it: `get_succeeded_by_scan_id` simply does not return
    the failed tool's row, which is ADR-016 decision 2's whole point — the line
    between trustworthy and untrustworthy output is drawn by that query and not
    by anything reading a status.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    await _seed_result(scan_result_repository, "semgrep", scanner_fixture("semgrep_scan.json"))
    await scan_result_repository.upsert(
        ScanResult.failed(id="sr-trivy", scan_id=_SCAN, tool="trivy", failure_reason="boom")
    )

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    findings = await finding_repository.get_by_project_id(_PROJECT)
    assert {finding.source for finding in findings} == {"semgrep"}
    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.COMPLETED


async def test_a_scan_where_every_tool_failed_completes_with_zero_findings(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """ADR-0017 decision 3's uniformity, asserted rather than assumed.

    `NormalizationRunStatus.FAILED` means NORMALIZATION failed. Nothing failed
    here — there was simply nothing trustworthy to normalize — so the run is
    `completed`. Skipping this case would have created a second code path and a
    hole in the invariant the sweep is built on.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    await scan_result_repository.upsert(
        ScanResult.failed(id="sr-1", scan_id=_SCAN, tool="semgrep", failure_reason="boom")
    )

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    assert await finding_repository.get_by_project_id(_PROJECT) == []
    assert finding_repository.sighting_calls == []
    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.COMPLETED
    assert stored_run.failure_reason is None


# ---------------------------------------------------------------------------
# ADR-0020 decision 5's two invisible contracts
# ---------------------------------------------------------------------------


async def test_record_sighting_is_called_once_per_identity_with_the_complete_total(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The second contract: once per `(finding, scan)`, carrying the TOTAL.

    `match_count` is overwritten rather than summed, so a shape that called this
    twice for one identity would silently keep only the last partial count. Three
    Semgrep matches of one rule in one file collapse to one identity — line
    numbers are deliberately not hash inputs (ADR-0019 decision 3) — so this input
    produces exactly one call carrying 3.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    three_matches = {
        "results": [
            {
                "check_id": "dangerous-eval",
                "path": "app.py",
                "start": {"line": line},
                "end": {"line": line},
                "extra": {"severity": "ERROR", "metadata": {}},
            }
            for line in (10, 20, 30)
        ]
    }
    await _seed_result(scan_result_repository, "semgrep", json.dumps(three_matches))

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    assert len(finding_repository.sighting_calls) == 1
    assert finding_repository.sighting_calls[0].match_count == 3
    assert len(await finding_repository.get_by_project_id(_PROJECT)) == 1


async def test_the_sighting_uses_the_id_the_upsert_resolved_not_the_observation_s(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
    scanner_fixture,
):
    """The first contract: identity is the hash, `id` is a surrogate, and only
    the upsert settles which one wins (ADR-0019 decision 1).

    Normalizing the same output for a SECOND scan is what makes this observable:
    the mapper generates fresh ids, they lose to the stored ones, and a sighting
    written against `representative.id` would point at a finding that does not
    exist. Asserted here against the fake's merge, and again against a real
    `RETURNING` in the integration suite.
    """
    raw = scanner_fixture("semgrep_scan.json")
    first = _claimed_run()
    normalization_run_repository.seed(first)
    await _seed_result(scan_result_repository, "semgrep", raw)
    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(first)
    stored_ids = {finding.id for finding in await finding_repository.get_by_project_id(_PROJECT)}

    second = NormalizationRun.requested(
        id="run-2", scan_id="scan-2", project_id=_PROJECT, requested_at=_REQUESTED_AT
    ).start(_REQUESTED_AT)
    normalization_run_repository.seed(second)
    await scan_result_repository.upsert(
        ScanResult.succeeded(id="sr-2", scan_id="scan-2", tool="semgrep", raw_output=raw)
    )
    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(second)

    second_scan_sightings = [s for s in finding_repository.sighting_calls if s.scan_id == "scan-2"]
    assert second_scan_sightings
    assert {sighting.finding_id for sighting in second_scan_sightings} == stored_ids
    # And no second row was created: the identity resolved to the stored finding.
    assert len(await finding_repository.get_by_project_id(_PROJECT)) == len(stored_ids)


# ---------------------------------------------------------------------------
# ADR-0019 decision 2's open question, decided here (ADR-0021)
# ---------------------------------------------------------------------------


async def test_one_conflicting_group_is_skipped_and_every_other_finding_survives(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """M4.4's acceptance criteria, over a synthetic identifier-less element.

    Two Semgrep results with NO `check_id` at the same path share an identity —
    the `"(unidentified)"` fallback makes the absence visible without removing the
    collision — and they disagree on `severity`, which is rule-level, so
    `collapse_by_identity` raises.

    **The assertion that matters is the third one.** Letting that raise propagate
    would abort a whole scan's normalization over one malformed element: the
    `PRODUCT_SPEC.md` §12 corruption the `Location` guard was removed to avoid,
    arriving through a different validation rule. The good finding surviving is
    what fails if a future refactor moves the catch back out to the whole pass.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    conflicting = {
        "results": [
            {
                "check_id": "",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "ERROR", "metadata": {}},
            },
            {
                "check_id": "",
                "path": "app.py",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"severity": "WARNING", "metadata": {}},
            },
            {
                "check_id": "a-real-rule",
                "path": "other.py",
                "start": {"line": 9},
                "end": {"line": 9},
                "extra": {"severity": "ERROR", "metadata": {}},
            },
        ]
    }
    await _seed_result(scan_result_repository, "semgrep", json.dumps(conflicting))

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    findings = await finding_repository.get_by_project_id(_PROJECT)
    # The conflicting identity is absent — nothing was upserted for it, so no
    # sighting could reference it either.
    assert all(finding.rule_id != "(unidentified)" for finding in findings)
    assert {sighting.finding_id for sighting in finding_repository.sighting_calls} == {
        finding.id for finding in findings
    }
    # THE ASSERTION THAT MATTERS: every other finding in the same scan survived.
    assert [finding.rule_id for finding in findings] == ["a-real-rule"]
    assert len(finding_repository.sighting_calls) == 1


async def test_a_skipped_group_marks_the_run_failed_with_the_hash_and_no_values(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The skip is recorded, not silent — `src/` has no logging, so the run row is
    the only place it can be said (ADR-0017 decision 1 created `failure_reason`
    for exactly a failure that is neither a scanner outcome nor a pre-tool one).

    The reason names the count and the `dedup_hash` and NEVER the disagreeing
    values, which are `title`/`severity` and can carry scanned content (rule 12).
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    conflicting = {
        "results": [
            {
                "check_id": "",
                "path": "app.py",
                "start": {"line": n},
                "end": {"line": n},
                "extra": {"severity": severity, "metadata": {}},
            }
            for n, severity in ((1, "ERROR"), (2, "WARNING"))
        ]
    }
    await _seed_result(scan_result_repository, "semgrep", json.dumps(conflicting))

    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)

    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.FAILED
    assert "1 finding group(s) could not be collapsed" in stored_run.failure_reason
    assert "v1:" in stored_run.failure_reason
    # Rule 12: no attribute VALUES in the persisted reason.
    assert "ERROR" not in stored_run.failure_reason
    assert "WARNING" not in stored_run.failure_reason


async def test_a_skipped_group_does_not_re_raise_so_arq_does_not_retry(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """The deterministic half of the failure taxonomy (ADR-0021).

    This failure is a pure function of the persisted `ScanResult` rows, which do
    not change between attempts — so a retry fails identically and buys five
    wasted runs. Not raising is what keeps arq out of it.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    conflicting = {
        "results": [
            {
                "check_id": "",
                "path": "app.py",
                "start": {"line": n},
                "end": {"line": n},
                "extra": {"severity": severity, "metadata": {}},
            }
            for n, severity in ((1, "ERROR"), (2, "INFO"))
        ]
    }
    await _seed_result(scan_result_repository, "semgrep", json.dumps(conflicting))

    # No pytest.raises: returning normally IS the assertion.
    await _use_case(
        scan_result_repository,
        finding_repository,
        normalization_run_repository,
        id_generator,
        clock,
    ).execute(run)


# ---------------------------------------------------------------------------
# The transient half of the failure taxonomy
# ---------------------------------------------------------------------------


async def test_an_unexpected_failure_marks_the_run_failed_and_re_raises(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """Re-raising is what lets arq retry, and the run being `failed` rather than
    left `running` is what makes it visible in the meantime. Both halves matter:
    without the write there is no record, and without the raise there is no retry.
    """
    run = _claimed_run()
    normalization_run_repository.seed(run)
    await _seed_result(scan_result_repository, "semgrep", "this is not json")

    with pytest.raises(json.JSONDecodeError):
        await _use_case(
            scan_result_repository,
            finding_repository,
            normalization_run_repository,
            id_generator,
            clock,
        ).execute(run)

    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.FAILED
    assert stored_run.failure_reason


async def test_a_failed_run_is_still_claimable_so_the_retry_can_proceed(
    normalization_run_repository,
):
    """The property that makes re-raising useful rather than decorative. If
    `FAILED` were terminal, arq's retry would reach `claim`, get `None`, and
    return — a retry that silently does nothing."""
    run = _claimed_run()
    normalization_run_repository.seed(run.fail(_NOW, "transient"))

    reclaimed = await normalization_run_repository.claim(scan_id=_SCAN, now=_NOW)

    assert reclaimed is not None
    assert reclaimed.status is NormalizationRunStatus.RUNNING


async def test_a_result_for_an_unknown_tool_raises_rather_than_being_skipped(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """ADR-016 decision 2's raise-versus-degrade line, at the other end of the
    pipeline: an unrecognised *severity* degrades to UNKNOWN because it is
    upstream data a tool can change in any release, but an unrecognised *tool
    name* is deployment configuration this project controls."""
    run = _claimed_run()
    normalization_run_repository.seed(run)
    await _seed_result(scan_result_repository, "nessus", "{}")

    with pytest.raises(UnknownScannerOutput, match="nessus"):
        await _use_case(
            scan_result_repository,
            finding_repository,
            normalization_run_repository,
            id_generator,
            clock,
        ).execute(run)


async def test_no_scanned_content_reaches_the_persisted_failure_reason(
    scan_result_repository,
    finding_repository,
    normalization_run_repository,
    id_generator,
    clock,
):
    """Rule 12, on the sink this issue introduces.

    `failure_reason` is persisted and M4.5 returns it. The obvious way to write
    the transient branch — `f"{type(exc).__name__}: {exc}"` — leaks: the likeliest
    exception here is a SQLAlchemy `StatementError`, whose `__str__` renders
    `[SQL: …] [parameters: …]`, and the statement in question is the finding
    upsert, whose bound parameters include `title` and `Evidence.raw_payload`.
    That is scanned source code in an API response.

    Asserted with an exception whose message carries a marker, because asserting
    "the reason is short" or "the reason is truthy" would pass the leaking version
    too — which is what the first draft of this file did.
    """
    secret = "AKIAIOSFODNN7EXAMPLE-in-scanned-source"

    class _LeakyRepository:
        async def upsert(self, finding):
            raise RuntimeError(f"[SQL: INSERT INTO findings] [parameters: ('{secret}',)]")

        async def record_sighting(self, sighting) -> None: ...

    run = _claimed_run()
    normalization_run_repository.seed(run)
    await _seed_result(
        scan_result_repository,
        "semgrep",
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "r",
                        "path": "a.py",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {"severity": "ERROR", "metadata": {}},
                    }
                ]
            }
        ),
    )

    with pytest.raises(RuntimeError):
        await _use_case(
            scan_result_repository,
            _LeakyRepository(),
            normalization_run_repository,
            id_generator,
            clock,
        ).execute(run)

    stored_run = await normalization_run_repository.get_by_scan_id(_SCAN)
    assert stored_run.status is NormalizationRunStatus.FAILED
    assert secret not in stored_run.failure_reason
    assert "parameters" not in stored_run.failure_reason
    # The type still survives, which is the diagnostic that is safe to keep.
    assert "RuntimeError" in stored_run.failure_reason
