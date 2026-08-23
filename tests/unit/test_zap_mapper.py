import json
from collections import Counter

from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "zap_scan.json"
_EDGES = "zap_synthetic_edges.json"


def _map(raw, id_generator, clock, scan_id="scan-1"):
    return map_zap_output(
        project_id="proj-1",
        scan_id=scan_id,
        raw_output=raw,
        id_generator=id_generator,
        clock=clock,
    )


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against a genuine ZAP 2.17.0 traditional-json report."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 11
    assert {f.source for f in findings} == {ScannerTool.ZAP}

    xcto = next(
        f
        for f in findings
        if f.title == "X-Content-Type-Options Header Missing"
        and f.location.url == "http://target.example:8080/robots.txt"
    )
    assert xcto.severity is Severity.LOW
    assert xcto.native_severity == "Low"
    assert xcto.cwe == "CWE-693"
    assert xcto.rule_id == "10021"
    assert xcto.location.http_method == "GET"
    assert xcto.location.parameter == "x-content-type-options"


def test_severity_comes_from_riskcode_not_from_a_severity_field(
    scanner_fixture, id_generator, clock
):
    """ZAP's report has no `severity` key at all. The word form exists only inside
    `riskdesc` as "Risk (Confidence)"; `riskcode` is the enumerated value, so it
    is the source. Getting this wrong would make every ZAP finding UNKNOWN."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)
    counted = Counter(f.severity for f in findings)

    # riskcode 2 on two alerts covering 3 and 2 instances; riskcode 1 on two
    # alerts covering 3 each.
    assert counted == Counter({Severity.LOW: 6, Severity.MEDIUM: 5})
    assert {f.native_severity for f in findings} == {"Low", "Medium"}


def test_cvss_and_owasp_are_none_because_the_report_carries_neither(
    scanner_fixture, id_generator, clock
):
    """`wascid` is a different taxonomy and must not be mistaken for an OWASP
    category — mapping it across would be inventing a value."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert all(f.cvss is None for f in findings)
    assert all(f.owasp_category is None for f in findings)


def test_one_finding_per_alert_instance(scanner_fixture, id_generator, clock):
    """M4.1 mapped one Finding per *alert* and deferred the choice; ADR-0019
    decides per *instance*.

    An alert-level finding would have to take its location from `instances[0]`,
    and that is not deterministic — the three instances of the alert below carry
    ids 6, 7 and 5, so they arrive in crawl order rather than sorted. Identity
    would have had to fall back to the site while `Location` displayed a URI that
    was not part of it. Per-instance also makes resolution granular: fixing the
    header on one URL and not another becomes one resolved and one still present.

    Every instance is accounted for exactly once — they are partitioned across
    the findings rather than duplicated or dropped.
    """
    raw = scanner_fixture(_REAL)
    findings = _map(raw, id_generator, clock)
    alerts = [a for s in json.loads(raw)["site"] for a in s["alerts"]]
    instances = [i for a in alerts for i in (a.get("instances") or [])]

    assert len(alerts) == 4
    assert len(findings) == len(instances) == 11
    assert len({f.dedup_hash for f in findings}) == 11
    recovered = [i for f in findings for i in json.loads(f.evidence.raw_payload)["instances"]]
    assert sorted(json.dumps(i, sort_keys=True) for i in recovered) == sorted(
        json.dumps(i, sort_keys=True) for i in instances
    )


def test_instance_ordering_does_not_affect_identity(scanner_fixture, id_generator, clock):
    """The measured hazard, pinned: ZAP returns an alert's instances in crawl
    order, so a re-scan can reorder them. Under per-instance findings that must
    change nothing about identity — only which finding is emitted first."""
    document = json.loads(scanner_fixture(_REAL))
    reordered = json.loads(scanner_fixture(_REAL))
    for site in reordered["site"]:
        for alert in site["alerts"]:
            alert["instances"] = list(reversed(alert.get("instances") or []))

    before = _map(json.dumps(document), id_generator, clock)
    after = _map(json.dumps(reordered), id_generator, clock)

    assert {f.dedup_hash for f in after} == {f.dedup_hash for f in before}


def test_evidence_is_the_alert_narrowed_to_this_finding_s_instance(
    scanner_fixture, id_generator, clock
):
    """ADR-0018 decision 6 clarified, not amended: still a verbatim copy of the
    source element, where the source element for a per-instance finding is the
    alert-plus-instance pair. Every alert-level field survives untouched; only
    the sibling instances are absent, and they are in the sibling findings."""
    raw = scanner_fixture(_REAL)
    finding = next(
        f
        for f in _map(raw, id_generator, clock)
        if f.title == "Missing Anti-clickjacking Header"
        and f.location.url == "http://target.example:8080/robots.txt"
    )
    source = next(
        a
        for s in json.loads(raw)["site"]
        for a in s["alerts"]
        if a["name"] == "Missing Anti-clickjacking Header"
    )
    payload = json.loads(finding.evidence.raw_payload)

    assert payload["instances"] == [
        i for i in source["instances"] if i["uri"] == "http://target.example:8080/robots.txt"
    ]
    assert {k: v for k, v in payload.items() if k != "instances"} == {
        k: v for k, v in source.items() if k != "instances"
    }
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
