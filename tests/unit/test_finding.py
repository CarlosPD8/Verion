from datetime import UTC, datetime

import pytest

from verion.modules.normalization.domain.cwe import canonical_cwe
from verion.modules.normalization.domain.finding import (
    MAX_RAW_PAYLOAD_CHARS,
    Evidence,
    Finding,
    Location,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _evidence(**overrides) -> Evidence:
    return Evidence(
        **{
            "id": "ev-1",
            "finding_id": "f-1",
            "scan_id": "scan-1",
            "raw_payload": "{}",
            "source_tool": ScannerTool.SEMGREP,
            "captured_at": _NOW,
            **overrides,
        }
    )


def _finding(**overrides) -> Finding:
    return Finding(
        **{
            "id": "f-1",
            "project_id": "proj-1",
            "source": ScannerTool.SEMGREP,
            "rule_id": "rules.example",
            "severity": Severity.HIGH,
            "native_severity": "ERROR",
            "title": "rules.example",
            "location": Location(file_path="app.py", start_line=1),
            "evidence": _evidence(),
            **overrides,
        }
    )


def test_a_finding_carries_no_confidence():
    """Absent on purpose, so re-adding it is a deliberate act rather than a
    drive-by.

    `confidence` waits for M6.1: only ZAP supplies it, as an opaque numeric code
    whose vocabulary mixes degrees (High/Medium/Low) with states (Confirmed,
    False Positive), and nothing compares it today — `RiskReasoning`'s five
    signals do not include it. `dedup_hash` was the other half of this pin until
    M4.2 resolved G5; it is now a derived property, covered below and in
    `test_dedup_hash.py`.
    """
    assert not hasattr(_finding(), "confidence")


def test_a_finding_is_no_longer_scan_scoped():
    """The G5 resolution, pinned at the entity.

    A `Finding` outlives the scan that first produced it: it is identified by
    `dedup_hash` and scoped to a project, with per-scan observations recorded as
    `FindingSighting` rows. A `scan_id` back on the entity would mean either
    "first scan" or "latest scan" depending on the writer, and neither answers
    M9.1's question — which is exactly the ambiguity G5 recorded. The scan
    survives on the evidence, as the provenance of the retained payload.
    """
    finding = _finding()

    assert not hasattr(finding, "scan_id")
    assert finding.project_id == "proj-1"
    assert finding.evidence.scan_id == "scan-1"


def test_dedup_hash_is_derived_and_cannot_be_assigned():
    """A property, not a constructor field — so it cannot drift from the fields
    it is over and cannot be forged by a caller."""
    finding = _finding()

    assert finding.dedup_hash.startswith("v1:")
    # A property with no setter on a frozen dataclass: FrozenInstanceError is an
    # AttributeError subclass, so one expectation covers both mechanisms.
    with pytest.raises(AttributeError):
        finding.dedup_hash = "v1:forged"


def test_two_findings_differing_only_in_mutable_attributes_share_an_identity():
    """The exclusions from `dedup_hash`, asserted over entities rather than over
    the hash function's signature.

    Every field varied here changes without the underlying finding changing: an
    edit above shifts the lines, a bump that fixes nothing changes the version,
    and an NVD rescore changes severity, CVSS and the advisory title. Re-keying
    on any of them would report a resolution that never happened.
    """
    original = _finding()
    rescored = _finding(
        severity=Severity.CRITICAL,
        native_severity="CRITICAL",
        title="a completely rewritten advisory title",
        cwe="CWE-79",
        cvss=9.8,
        location=Location(
            file_path="app.py", start_line=42, end_line=47, installed_version="1.25.0"
        ),
    )

    assert rescored.dedup_hash == original.dedup_hash


def test_a_different_file_is_a_different_finding():
    """The other half: the same rule firing in two files is two findings, not one
    over-merged one."""
    assert _finding().dedup_hash != _finding(location=Location(file_path="other.py")).dedup_hash


def test_rule_id_may_not_be_empty():
    """It is a dedup_hash input, and an empty one would silently merge unrelated
    findings of different rules into a single identity."""
    with pytest.raises(ValueError, match="empty rule_id"):
        _finding(rule_id="")


def test_evidence_must_belong_to_its_finding():
    with pytest.raises(ValueError, match="carries finding_id"):
        _finding(evidence=_evidence(finding_id="someone-else"))


def test_evidence_must_agree_with_the_finding_on_which_tool_produced_it():
    """A mismatch here would misattribute evidence to the wrong scanner, which
    M5 would then correlate as a cross-tool agreement that never happened."""
    with pytest.raises(ValueError, match="records"):
        _finding(source=ScannerTool.TRIVY, evidence=_evidence(source_tool=ScannerTool.ZAP))


def test_native_severity_may_not_be_empty():
    """Even an unrecognised level has to be recorded verbatim — that string is
    the only remaining trace of what the tool actually said once `severity` has
    degraded to UNKNOWN."""
    with pytest.raises(ValueError, match="empty native_severity"):
        _finding(severity=Severity.UNKNOWN, native_severity="")


def test_an_oversized_payload_is_rejected_so_mappers_must_truncate():
    with pytest.raises(ValueError, match="over the"):
        _evidence(raw_payload="x" * (MAX_RAW_PAYLOAD_CHARS + 1))

    # The boundary itself is allowed.
    assert _evidence(raw_payload="x" * MAX_RAW_PAYLOAD_CHARS)


def test_a_location_may_be_entirely_empty():
    """No guard, deliberately: a ZAP site-level alert can carry no instances, and
    raising mid-map would discard every other finding in the same scan."""
    assert Location() == Location()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CWE-20", "CWE-20"),
        ("693", "CWE-693"),
        (693, "CWE-693"),
        ("CWE-95: Improper Neutralization of Directives", "CWE-95"),
        ("  CWE-79  ", "CWE-79"),
        # ZAP's "none known" sentinels, which must not become CWE--1 / CWE-0.
        ("-1", None),
        ("0", None),
        (None, None),
        ("", None),
        ("not a cwe at all", None),
    ],
)
def test_cwe_canonicalisation(raw, expected):
    """The three tools spell CWEs three ways. M5 compares them across tools, so a
    mismatch here is a silent false negative that looks exactly like "these
    findings are unrelated"."""
    assert canonical_cwe(raw) == expected
