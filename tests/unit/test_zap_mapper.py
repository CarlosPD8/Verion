import json

from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "zap_scan.json"
_EDGES = "zap_synthetic_edges.json"


def _map(raw, id_generator, clock):
    return map_zap_output(scan_id="scan-1", raw_output=raw, id_generator=id_generator, clock=clock)


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against a genuine ZAP 2.17.0 traditional-json report."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 4
    assert {f.source for f in findings} == {ScannerTool.ZAP}

    xcto = next(f for f in findings if f.title == "X-Content-Type-Options Header Missing")
    assert xcto.severity is Severity.LOW
    assert xcto.native_severity == "Low"
    assert xcto.cwe == "CWE-693"
    assert xcto.location.url == "http://target.example:8080/"
    assert xcto.location.http_method == "GET"
    assert xcto.location.parameter == "x-content-type-options"


def test_severity_comes_from_riskcode_not_from_a_severity_field(
    scanner_fixture, id_generator, clock
):
    """ZAP's report has no `severity` key at all. The word form exists only inside
    `riskdesc` as "Risk (Confidence)"; `riskcode` is the enumerated value, so it
    is the source. Getting this wrong would make every ZAP finding UNKNOWN."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)
    by_severity = sorted(f.severity for f in findings)

    assert by_severity == [Severity.LOW, Severity.LOW, Severity.MEDIUM, Severity.MEDIUM]
    assert {f.native_severity for f in findings} == {"Low", "Medium"}


def test_cvss_and_owasp_are_none_because_the_report_carries_neither(
    scanner_fixture, id_generator, clock
):
    """`wascid` is a different taxonomy and must not be mistaken for an OWASP
    category — mapping it across would be inventing a value."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert all(f.cvss is None for f in findings)
    assert all(f.owasp_category is None for f in findings)


def test_one_finding_per_alert_not_per_instance(scanner_fixture, id_generator, clock):
    """Deliberate, and recorded because M4.2 may revisit it: an alert is what ZAP
    considers a finding (one riskcode, one cweid, one solution), while instances
    are *occurrences* — the sighting concept G5 says the model is missing.
    Splitting per instance here would pre-empt that decision. Nothing is lost:
    every instance stays verbatim in the evidence.
    """
    raw = scanner_fixture(_REAL)
    findings = _map(raw, id_generator, clock)
    alerts = [a for s in json.loads(raw)["site"] for a in s["alerts"]]
    total_instances = sum(len(a.get("instances") or []) for a in alerts)

    assert len(findings) == len(alerts) == 4
    assert total_instances == 11
    recovered = sum(len(json.loads(f.evidence.raw_payload)["instances"]) for f in findings)
    assert recovered == total_instances


def test_evidence_round_trips_to_the_exact_source_alert(scanner_fixture, id_generator, clock):
    raw = scanner_fixture(_REAL)
    finding = next(
        f for f in _map(raw, id_generator, clock) if f.title == "Missing Anti-clickjacking Header"
    )
    source = next(
        a
        for s in json.loads(raw)["site"]
        for a in s["alerts"]
        if a["name"] == "Missing Anti-clickjacking Header"
    )

    assert json.loads(finding.evidence.raw_payload) == source
    assert finding.evidence.source_tool is ScannerTool.ZAP


def test_the_riskcodes_absent_from_the_real_capture(scanner_fixture, id_generator, clock):
    """The real fixture has only riskcode 1 and 2, so High and Informational are
    covered here."""
    by_title = {f.title: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    high = by_title["Cross Site Scripting (Reflected)"]
    assert high.severity is Severity.HIGH
    assert high.native_severity == "High"

    info = by_title["Re-examine Cache-control Directives"]
    assert info.severity is Severity.INFO
    assert info.native_severity == "Informational"


def test_zaps_no_cwe_sentinels_become_none(scanner_fixture, id_generator, clock):
    """ZAP writes `-1` or `0` rather than omitting `cweid`. Passing either through
    would fabricate "CWE--1"/"CWE-0" and give M5 a key that correlates findings
    which have nothing in common."""
    by_title = {f.title: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    assert by_title["Re-examine Cache-control Directives"].cwe is None
    assert by_title["An alert with no instances at all"].cwe is None


def test_an_alert_with_no_instances_still_produces_a_finding(scanner_fixture, id_generator, clock):
    """It is still a real alert, and dropping it would discard scanner output —
    the corruption PRODUCT_SPEC.md §12 forbids. The location falls back to the
    site the alert is nested under, which is less precise than a per-instance URL
    but is not a guess: that nesting is ZAP's own statement of where it applies.
    """
    by_title = {f.title: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}
    orphan = by_title["An alert with no instances at all"]

    assert orphan.severity is Severity.LOW
    assert orphan.location.url == "http://target.example:8080"
    assert orphan.location.http_method is None
    assert orphan.location.parameter is None


def test_an_unrecognised_riskcode_degrades_instead_of_raising(scanner_fixture, id_generator, clock):
    by_title = {f.title: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}
    degraded = by_title["A riskcode ZAP does not define today"]

    assert degraded.severity is Severity.UNKNOWN
    assert "7" in degraded.native_severity


def test_an_empty_report_produces_no_findings(id_generator, clock):
    assert _map('{"@version": "2.17.0", "site": []}', id_generator, clock) == []
    assert _map('{"@version": "2.17.0"}', id_generator, clock) == []
