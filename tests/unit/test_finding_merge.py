from datetime import UTC, datetime

import pytest

from verion.modules.normalization.domain.finding import (
    Evidence,
    Finding,
    Location,
    collapse_by_identity,
    merge_observation,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(
    finding_id="f-1",
    *,
    evidence_id="ev-1",
    scan_id="scan-1",
    payload="{}",
    source=ScannerTool.SEMGREP,
    **overrides,
):
    return Finding(
        **{
            "id": finding_id,
            "project_id": "proj-1",
            "source": source,
            "rule_id": "rules.dangerous-eval",
            "severity": Severity.HIGH,
            "native_severity": "ERROR",
            "title": "rules.dangerous-eval",
            "location": Location(file_path="app.py", start_line=2, end_line=2),
            "evidence": Evidence(
                id=evidence_id,
                finding_id=finding_id,
                scan_id=scan_id,
                raw_payload=payload,
                source_tool=source,
                captured_at=_NOW,
            ),
            **overrides,
        }
    )


def test_a_merge_keeps_identity_and_takes_the_new_attributes():
    """What a second scan observing the same finding does: the stored row keeps
    its `id` and its project, and everything the tool can revise is refreshed —
    including the evidence, which becomes the latest scan's payload."""
    stored = _finding("f-stored", evidence_id="ev-stored", scan_id="scan-1")
    observed = _finding(
        "f-candidate",
        evidence_id="ev-candidate",
        scan_id="scan-2",
        payload='{"observed": "again"}',
        severity=Severity.CRITICAL,
        native_severity="CRITICAL",
        title="a rescored advisory",
        cvss=9.8,
        location=Location(file_path="app.py", start_line=47, end_line=47),
    )

    merged = merge_observation(stored, observed)

    assert merged.id == "f-stored"
    assert merged.project_id == "proj-1"
    assert merged.dedup_hash == stored.dedup_hash
    assert merged.severity is Severity.CRITICAL
    assert merged.title == "a rescored advisory"
    assert merged.cvss == 9.8
    assert merged.location.start_line == 47
    # The evidence row is updated in place, not replaced by a second one.
    assert merged.evidence.id == "ev-stored"
    assert merged.evidence.finding_id == "f-stored"
    assert merged.evidence.raw_payload == '{"observed": "again"}'
    assert merged.evidence.scan_id == "scan-2"


def test_merging_two_different_findings_raises():
    """A mismatched hash can only mean a caller merged two different findings —
    a programming error, not upstream data, so it fails where it happens rather
    than degrading (ADR-0018 decision 1's raise-versus-degrade line)."""
    with pytest.raises(ValueError, match="dedup_hash"):
        merge_observation(_finding(), _finding("f-2", rule_id="rules.something-else"))


def test_merging_across_projects_raises():
    """Findings dedup within a project and never across one. A shared row would
    make one tenant's dismissal apply to another's project."""
    with pytest.raises(ValueError, match="findings dedup within a project"):
        merge_observation(_finding(), _finding("f-2", project_id="proj-2"))


def test_two_matches_of_one_rule_in_one_file_collapse_with_a_count():
    """The receipt for the under-count `dedup_hash` accepts by excluding line
    numbers: the two matches become one finding, and `match_count` records that
    it was two."""
    first = _finding(
        "f-1", payload='{"line": 2}', location=Location(file_path="app.py", start_line=2)
    )
    second = _finding(
        "f-2", payload='{"line": 90}', location=Location(file_path="app.py", start_line=90)
    )

    collapsed = collapse_by_identity([first, second])

    assert len(collapsed) == 1
    representative, match_count = collapsed[0]
    assert match_count == 2
    assert representative.location.start_line == 2


def test_distinct_identities_are_not_collapsed():
    findings = [
        _finding("f-1"),
        _finding("f-2", rule_id="rules.other"),
        _finding("f-3", location=Location(file_path="other.py")),
    ]

    collapsed = collapse_by_identity(findings)

    assert len(collapsed) == 3
    assert {count for _, count in collapsed} == {1}


def test_the_representative_does_not_depend_on_input_order():
    """The whole point of a total sort key. Input order is the tool's, and ZAP's
    own instance ordering is measurably not stable, so anything decided by "first
    in the list" is decided by the crawl."""
    first = _finding(
        "f-1", payload='{"line": 2}', location=Location(file_path="app.py", start_line=2)
    )
    second = _finding(
        "f-2", payload='{"line": 90}', location=Location(file_path="app.py", start_line=90)
    )

    forwards = collapse_by_identity([first, second])
    backwards = collapse_by_identity([second, first])

    assert forwards[0][0].location.start_line == backwards[0][0].location.start_line == 2


def test_the_representative_is_total_when_no_finding_has_a_line():
    """Trivy and ZAP populate no line fields at all, so a `start_line`-only key
    would have left every one of their groups falling back to list order. The
    payload tiebreak is what makes the choice total."""
    trivy_location = Location(file_path="requirements.txt", package="urllib3")
    first = _finding(
        "f-1",
        payload='{"a": 1}',
        source=ScannerTool.TRIVY,
        rule_id="CVE-2019-11324",
        location=trivy_location,
    )
    second = _finding(
        "f-2",
        payload='{"b": 2}',
        source=ScannerTool.TRIVY,
        rule_id="CVE-2019-11324",
        location=trivy_location,
    )

    forwards = collapse_by_identity([first, second])
    backwards = collapse_by_identity([second, first])

    assert forwards[0][1] == backwards[0][1] == 2
    assert forwards[0][0].evidence.raw_payload == backwards[0][0].evidence.raw_payload


def test_collapsing_across_projects_raises():
    """`dedup_hash` excludes the project deliberately — scope is the `UNIQUE`
    constraint, not a hash input — so grouping by it alone would merge across
    projects if a caller ever mixed them. Inert today, since one scan is one
    project, and guarded anyway: `merge_observation` enforces the same boundary,
    and a matched pair where only one half checks the scope is a pair that will
    be relied on for both."""
    with pytest.raises(ValueError, match="findings dedup within a project"):
        collapse_by_identity([_finding("f-1"), _finding("f-2", project_id="proj-2")])


def test_a_group_disagreeing_on_a_rule_level_attribute_raises():
    """Severity is per-rule for Semgrep, per-advisory for Trivy and per-alert for
    ZAP, so two findings sharing an identity inside one scan cannot legitimately
    disagree on it. Asserted rather than assumed, because that "cannot" is the
    kind that stops being true without anything noticing — and a disagreement
    would mean a mapper derived a rule-level attribute from a match-level field.
    """
    first = _finding("f-1", payload='{"a": 1}')
    second = _finding("f-2", payload='{"b": 2}', severity=Severity.LOW)

    with pytest.raises(ValueError, match="'severity'"):
        collapse_by_identity([first, second])
