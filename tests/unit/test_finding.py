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
            "scan_id": "scan-1",
            "source": ScannerTool.SEMGREP,
            "severity": Severity.HIGH,
            "native_severity": "ERROR",
            "title": "rules.example",
            "location": Location(file_path="app.py", start_line=1),
            "evidence": _evidence(),
            **overrides,
        }
    )


def test_a_finding_carries_neither_confidence_nor_dedup_hash():
    """Both are absent on purpose, and this pins that so re-adding either is a
    deliberate act rather than a drive-by.

    `confidence` waits for M6.1: only ZAP supplies it, as an opaque numeric code
    whose vocabulary mixes degrees (High/Medium/Low) with states (Confirmed,
    False Positive), and nothing compares it today — `RiskReasoning`'s five
    signals do not include it. `dedup_hash` waits for M4.2: computing one here
    would mean inventing the identity rule that issue exists to decide (G5).
    """
    finding = _finding()

    assert not hasattr(finding, "confidence")
    assert not hasattr(finding, "dedup_hash")


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
