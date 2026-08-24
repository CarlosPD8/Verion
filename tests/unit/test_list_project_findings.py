"""`ListProjectFindingsUseCase` and `GetFindingEvidenceUseCase` against fakes (M4.5).

Three things here are not ordinary coverage and say so:

- the **gate-placement** tests, which prove authorization runs before any read
  rather than merely that a denial happens (ADR-0013's idiom);
- the **severity-ordering** test, whose expectation is DERIVED from `Severity.rank`
  rather than retyped, so a change to the scale fails it instead of being followed
  silently (ADR-0020 decision 4's layer 2);
- the **UNKNOWN-exclusion** test, which pins a consequence of honouring one total
  order that is surprising enough to be worth a failing test if anyone "fixes" it.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.normalization.application.get_finding_evidence import (
    GetFindingEvidenceUseCase,
    payload_is_truncated,
)
from verion.modules.normalization.application.list_project_findings import (
    ListProjectFindingsUseCase,
)
from verion.modules.normalization.domain.exceptions import FindingNotFound, ProjectAccessDenied
from verion.modules.normalization.domain.finding import (
    Evidence,
    Finding,
    FindingSighting,
    Location,
)
from verion.modules.normalization.domain.normalization_run import NormalizationRun
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_USER = "user-1"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(
    *,
    finding_id: str,
    severity: Severity,
    source: ScannerTool = ScannerTool.SEMGREP,
    rule_id: str | None = None,
    raw_payload: str = '{"ok": true}',
    project_id: str = _PROJECT,
) -> Finding:
    return Finding(
        id=finding_id,
        project_id=project_id,
        source=source,
        rule_id=rule_id or f"rule-{finding_id}",
        severity=severity,
        native_severity="ERROR",
        title=f"title {finding_id}",
        location=Location(file_path=f"{finding_id}.py", start_line=1),
        evidence=Evidence(
            id=f"ev-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload=raw_payload,
            source_tool=source,
            captured_at=_AT,
        ),
    )


async def _seed(repository, finding: Finding, *, scan_id: str = _SCAN, at: datetime = _AT) -> None:
    stored = await repository.upsert(finding)
    await repository.record_sighting(
        FindingSighting(finding_id=stored.id, scan_id=scan_id, observed_at=at, match_count=1)
    )


def _use_case(project_access, findings, runs) -> ListProjectFindingsUseCase:
    return ListProjectFindingsUseCase(
        project_access=project_access, findings=findings, normalization_runs=runs
    )


# ---------------------------------------------------------------------------
# Authorization — the first project-scoped read outside `projects`
# ---------------------------------------------------------------------------


async def test_a_caller_who_may_not_read_the_project_is_refused(
    project_access, finding_repository, normalization_run_repository
):
    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, finding_repository, normalization_run_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )


async def test_listing_authorizes_before_it_reads_anything(
    project_access, exploding_finding_repository, normalization_run_repository
):
    """The gate must run first, not merely run.

    `ExplodingFindingRepository` raises on every read, so this fails if the
    authorization check is ever moved below the query — a refactor that would
    leave the denial working and every other test green while sending an
    unauthorized caller's project id to the database.
    """
    with pytest.raises(ProjectAccessDenied):
        await _use_case(
            project_access, exploding_finding_repository, normalization_run_repository
        ).execute(project_id=_PROJECT, user_id=_USER)


async def test_evidence_authorizes_before_it_reads_anything(
    project_access, exploding_finding_repository
):
    with pytest.raises(ProjectAccessDenied):
        await GetFindingEvidenceUseCase(
            project_access=project_access, findings=exploding_finding_repository
        ).execute(project_id=_PROJECT, user_id=_USER, finding_id="finding-1")


async def test_a_member_sees_the_project_s_findings(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    await _seed(finding_repository, _finding(finding_id="f1", severity=Severity.HIGH))

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [item.finding.id for item in page.items] == ["f1"]
    assert page.total == 1


# ---------------------------------------------------------------------------
# Ordering — derived from Severity.rank, never retyped
# ---------------------------------------------------------------------------


async def test_findings_are_ordered_by_severity_rank_descending(
    project_access, finding_repository, normalization_run_repository
):
    """The expectation is COMPUTED from `Severity.rank`, not written out.

    Retyping `["critical", "high", …]` here would make this test agree with a
    second copy of the scale rather than with the scale. A change to `_RANK` would
    then be followed silently by the query and contradicted by nothing — the
    drift ADR-0020 decision 1 avoided for the upsert's SET clause, in a second
    place.
    """
    project_access.permit(_PROJECT, _USER)
    for member in Severity:
        await _seed(finding_repository, _finding(finding_id=str(member), severity=member))

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    expected = [str(m) for m in sorted(Severity, key=lambda m: m.rank, reverse=True)]
    assert [item.finding.severity for item in page.items] == expected


async def test_unknown_sorts_last_below_info(
    project_access, finding_repository, normalization_run_repository
):
    """A product decision made by a sort key, so it gets a test that states it.

    `Severity.UNKNOWN` means "the tool did not know", not "least dangerous". It
    sorts last because that is the display convention `Severity`'s own docstring
    declares, and promoting it would let a mapper's silence decide priority.
    """
    project_access.permit(_PROJECT, _USER)
    await _seed(finding_repository, _finding(finding_id="u", severity=Severity.UNKNOWN))
    await _seed(finding_repository, _finding(finding_id="i", severity=Severity.INFO))

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [item.finding.id for item in page.items] == ["i", "u"]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


async def test_min_severity_keeps_that_rank_and_above(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    for member in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        await _seed(finding_repository, _finding(finding_id=str(member), severity=member))

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER, min_severity=Severity.HIGH)

    assert [item.finding.severity for item in page.items] == ["critical", "high"]
    assert page.total == 2


async def test_min_severity_excludes_unknown_because_unknown_ranks_lowest(
    project_access, finding_repository, normalization_run_repository
):
    """Surprising, deliberate, and therefore pinned rather than left to be found.

    `UNKNOWN` ranks BELOW `INFO`, so filtering by rank drops findings whose
    severity no tool could determine — including under `min_severity=info`, the
    weakest filter anyone would think to apply. The escape hatch is
    `min_severity=unknown`, which is rank 0 and therefore a no-op.

    The alternative — always including `UNKNOWN` regardless of the filter — was
    rejected because it makes the parameter's name a lie. Honouring one total
    order and documenting the edge beats two orders that disagree.
    """
    project_access.permit(_PROJECT, _USER)
    await _seed(finding_repository, _finding(finding_id="u", severity=Severity.UNKNOWN))
    await _seed(finding_repository, _finding(finding_id="i", severity=Severity.INFO))

    use_case = _use_case(project_access, finding_repository, normalization_run_repository)

    filtered = await use_case.execute(
        project_id=_PROJECT, user_id=_USER, min_severity=Severity.INFO
    )
    assert [item.finding.id for item in filtered.items] == ["i"]

    unfiltered = await use_case.execute(
        project_id=_PROJECT, user_id=_USER, min_severity=Severity.UNKNOWN
    )
    assert {item.finding.id for item in unfiltered.items} == {"i", "u"}


async def test_source_filters_by_tool(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    await _seed(
        finding_repository,
        _finding(finding_id="s", severity=Severity.HIGH, source=ScannerTool.SEMGREP),
    )
    await _seed(
        finding_repository,
        _finding(finding_id="t", severity=Severity.HIGH, source=ScannerTool.TRIVY),
    )

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER, source=ScannerTool.TRIVY)

    assert [item.finding.id for item in page.items] == ["t"]
    assert page.total == 1


async def test_another_project_s_findings_are_never_returned(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    await _seed(finding_repository, _finding(finding_id="ours", severity=Severity.HIGH))
    await _seed(
        finding_repository,
        _finding(finding_id="theirs", severity=Severity.HIGH, project_id="project-2"),
    )

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [item.finding.id for item in page.items] == ["ours"]


# ---------------------------------------------------------------------------
# Paging
# ---------------------------------------------------------------------------


async def test_a_page_is_bounded_while_total_counts_the_whole_filtered_set(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    for index in range(5):
        await _seed(finding_repository, _finding(finding_id=f"f{index}", severity=Severity.HIGH))

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER, limit=2, offset=2)

    assert len(page.items) == 2
    assert page.total == 5
    assert (page.limit, page.offset) == (2, 2)


# ---------------------------------------------------------------------------
# Sighting aggregate — derived per request, never stored (ADR-0019 decision 1)
# ---------------------------------------------------------------------------


async def test_sighting_summary_aggregates_every_scan_that_observed_the_finding(
    project_access, finding_repository, normalization_run_repository
):
    project_access.permit(_PROJECT, _USER)
    finding = _finding(finding_id="f1", severity=Severity.HIGH)
    await _seed(finding_repository, finding, scan_id="scan-1", at=_AT)
    await _seed(finding_repository, finding, scan_id="scan-2", at=datetime(2026, 3, 1, tzinfo=UTC))

    [item] = (
        await _use_case(project_access, finding_repository, normalization_run_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )
    ).items

    assert item.sighting_count == 2
    assert item.first_seen_at == _AT
    assert item.last_seen_at == datetime(2026, 3, 1, tzinfo=UTC)
    assert item.last_seen_scan_id == "scan-2"


# ---------------------------------------------------------------------------
# What the response says about its own completeness (G15)
# ---------------------------------------------------------------------------


async def test_a_clean_project_and_a_project_with_failed_runs_are_distinguishable(
    project_access, finding_repository, normalization_run_repository
):
    """The whole reason the envelope carries normalization state.

    Both projects below return zero findings. Without `unfinished_runs` the two
    responses would be byte-identical, and a project whose scans never normalized
    would read as a project with nothing wrong with it — G15's own description of
    the gap this narrows.
    """
    project_access.permit(_PROJECT, _USER)
    use_case = _use_case(project_access, finding_repository, normalization_run_repository)

    clean = await use_case.execute(project_id=_PROJECT, user_id=_USER)
    assert (clean.total, clean.unfinished_runs, clean.latest_run) == (0, 0, None)

    normalization_run_repository.seed(
        NormalizationRun.requested(id="run-1", scan_id=_SCAN, project_id=_PROJECT, requested_at=_AT)
        .start(_AT)
        .fail(_AT, "Normalization failed with OSError.")
    )

    broken = await use_case.execute(project_id=_PROJECT, user_id=_USER)
    assert broken.total == 0
    assert broken.unfinished_runs == 1
    assert broken.latest_run is not None
    assert broken.latest_run.failure_reason == "Normalization failed with OSError."


async def test_a_completed_latest_run_does_not_hide_earlier_failures(
    project_access, finding_repository, normalization_run_repository
):
    """Why `unfinished_runs` exists and `latest_run` alone would not do.

    The most recent scan normalized cleanly, so `latest_run.status` is
    `completed` and the project looks healthy — while an earlier scan's findings
    were never produced. A single latest-run field would report that as fine.
    """
    project_access.permit(_PROJECT, _USER)
    normalization_run_repository.seed(
        NormalizationRun.requested(
            id="run-old", scan_id="scan-old", project_id=_PROJECT, requested_at=_AT
        )
        .start(_AT)
        .fail(_AT, "Normalization failed with OSError.")
    )
    later = datetime(2026, 6, 1, tzinfo=UTC)
    normalization_run_repository.seed(
        NormalizationRun.requested(
            id="run-new", scan_id="scan-new", project_id=_PROJECT, requested_at=later
        )
        .start(later)
        .complete(later)
    )

    page = await _use_case(
        project_access, finding_repository, normalization_run_repository
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert page.latest_run is not None
    assert page.latest_run.status == "completed"
    assert page.unfinished_runs == 1


# ---------------------------------------------------------------------------
# Evidence — the rule-12 surface
# ---------------------------------------------------------------------------


async def test_evidence_is_returned_for_a_finding_in_the_project(
    project_access, finding_repository
):
    project_access.permit(_PROJECT, _USER)
    await _seed(
        finding_repository,
        _finding(finding_id="f1", severity=Severity.HIGH, raw_payload='{"lines": "x = 1"}'),
    )

    evidence = await GetFindingEvidenceUseCase(
        project_access=project_access, findings=finding_repository
    ).execute(project_id=_PROJECT, user_id=_USER, finding_id="f1")

    assert evidence.raw_payload == '{"lines": "x = 1"}'
    assert evidence.scan_id == _SCAN


async def test_a_finding_id_from_another_project_is_not_found(project_access, finding_repository):
    """Cross-tenant read of scanned source, refused — and refused indistinguishably.

    The caller is a legitimate member of `_PROJECT`. Passing a finding id that
    exists in another project must produce the same answer as passing one that
    exists nowhere, or the endpoint becomes an oracle for which ids exist in
    projects the caller cannot see.
    """
    project_access.permit(_PROJECT, _USER)
    await _seed(
        finding_repository,
        _finding(finding_id="theirs", severity=Severity.HIGH, project_id="project-2"),
    )
    use_case = GetFindingEvidenceUseCase(project_access=project_access, findings=finding_repository)

    with pytest.raises(FindingNotFound):
        await use_case.execute(project_id=_PROJECT, user_id=_USER, finding_id="theirs")
    with pytest.raises(FindingNotFound):
        await use_case.execute(project_id=_PROJECT, user_id=_USER, finding_id="never-existed")


# ---------------------------------------------------------------------------
# payload_is_truncated — obligation 2
# ---------------------------------------------------------------------------


def test_a_whole_payload_is_not_reported_as_truncated():
    assert payload_is_truncated('{"a": 1, "b": [2, 3]}') is False


def test_a_payload_cut_by_the_character_cap_is_reported_as_truncated():
    """The defect this flag exists for: `[:MAX_RAW_PAYLOAD_CHARS]` mid-structure.

    Note what is NOT asserted: that the payload "is not valid JSON". The flag
    claims the payload is an incomplete PREFIX of its source element, and the
    parse attempt is how that is currently detected — exactly while a character
    slice is the only lossy step. G16 carries the trigger for when it stops being.
    """
    whole = '{"extra": {"lines": "requires login"}, "check_id": "dangerous-eval"}'
    assert payload_is_truncated(whole[:30]) is True
