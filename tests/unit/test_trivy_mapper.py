import json

from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "trivy_scan.json"
_EDGES = "trivy_synthetic_edges.json"


def _map(raw, id_generator, clock):
    return map_trivy_output(
        scan_id="scan-1", raw_output=raw, id_generator=id_generator, clock=clock
    )


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against genuine Trivy 0.74.0 output for `urllib3==1.24.1`."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 12
    assert {f.source for f in findings} == {ScannerTool.TRIVY}
    assert {f.severity for f in findings} == {Severity.HIGH, Severity.MEDIUM}
    assert sorted(f.native_severity for f in findings) == ["HIGH"] * 6 + ["MEDIUM"] * 6

    known = next(f for f in findings if f.title.startswith("CVE-2019-11324"))
    assert known.severity is Severity.HIGH
    assert known.cwe == "CWE-295"
    assert known.cvss == 7.5
    assert known.location.file_path == "requirements.txt"
    assert known.location.package == "urllib3"
    assert known.location.installed_version == "1.24.1"


def test_every_real_vulnerability_carries_exactly_one_cwe(scanner_fixture, id_generator, clock):
    """The measurement that settled `Finding.cwe` as a single value rather than a
    tuple (ADR-0018).

    **What this does and does not guard.** It guards the *fixture*: `{1}` is a
    literal and the fixture is data read at run time, so a re-capture that brought
    a two-CWE vulnerability fails here rather than silently widening the evidence
    the ADR rests on. Verified by mutation — injecting a second CweID into the
    fixture fails this assertion at the line below.

    It does **not** guard production. This target is one `requirements.txt`; other
    ecosystems do emit multiple CweIDs, and no fixture can prove otherwise. That
    case is covered by `test_multiple_cwes_keep_the_first_and_lose_none` below,
    which pins the mapper's *behaviour* rather than the data's shape — the two
    tests answer different questions and both are needed.
    """
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert all(f.cwe is not None for f in findings)
    source = json.loads(scanner_fixture(_REAL))
    counts = {
        len(v.get("CweIDs") or [])
        for r in source["Results"]
        for v in (r.get("Vulnerabilities") or [])
    }
    assert counts == {1}


def test_multiple_cwes_keep_the_first_and_lose_none(scanner_fixture, id_generator, clock):
    """What happens when a tool emits two CWEs — specified, not incidental.

    `Finding.cwe` is a single value because the measured maximum across all three
    real fixtures is 1, but that is a fact about *these targets*, not about Trivy.
    Other ecosystems emit several. Without this test the mapper's `next(iter(...))`
    would be an unexamined silent truncation, and the first production npm scan
    would be where anyone found out.

    The contract asserted here is the one ADR-0018 claims: the first CWE as the
    tool ordered it becomes the correlation key, and **nothing is discarded** —
    the full list survives in `raw_payload`, so M4.2 or M5 can widen to set
    intersection later without a re-scan.
    """
    by_id = {f.title.split(":")[0]: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}
    multi = by_id["CVE-9000-0006"]

    assert multi.cwe == "CWE-287"
    assert json.loads(multi.evidence.raw_payload)["CweIDs"] == ["CWE-287", "CWE-863"]


def test_owasp_is_always_none_because_trivy_has_no_such_concept(
    scanner_fixture, id_generator, clock
):
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert all(f.owasp_category is None for f in findings)


def test_evidence_round_trips_to_the_exact_source_element(scanner_fixture, id_generator, clock):
    raw = scanner_fixture(_REAL)
    finding = next(
        f for f in _map(raw, id_generator, clock) if f.title.startswith("CVE-2019-11324")
    )
    source = next(
        v
        for r in json.loads(raw)["Results"]
        for v in (r.get("Vulnerabilities") or [])
        if v["VulnerabilityID"] == "CVE-2019-11324"
    )

    assert json.loads(finding.evidence.raw_payload) == source
    assert finding.evidence.source_tool is ScannerTool.TRIVY


def test_the_full_severity_scale_including_unknown(scanner_fixture, id_generator, clock):
    """The real fixture contains only HIGH and MEDIUM, so CRITICAL, LOW and the
    literal UNKNOWN are covered here. UNKNOWN is carried through rather than
    folded into LOW — collapsing it would invent a Risk Engine input."""
    by_id = {f.title.split(":")[0]: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    assert by_id["CVE-9000-0001"].severity is Severity.CRITICAL
    assert by_id["CVE-9000-0002"].severity is Severity.LOW
    assert by_id["CVE-9000-0003"].severity is Severity.UNKNOWN
    assert by_id["CVE-9000-0003"].native_severity == "UNKNOWN"


def test_a_v2_only_score_yields_none_rather_than_a_v2_number(scanner_fixture, id_generator, clock):
    """v2 and v3 are different scales. Putting a v2 6.8 in the same field M6 will
    compare against v3 scores is a rule-5 violation dressed up as arithmetic."""
    by_id = {f.title.split(":")[0]: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    assert by_id["CVE-9000-0004"].cvss is None
    # Severity is mapped independently, so it survives the missing score.
    assert by_id["CVE-9000-0004"].severity is Severity.MEDIUM


def test_cvss_vendor_selection_is_deterministic(scanner_fixture, id_generator, clock):
    by_id = {f.title.split(":")[0]: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    # Preferred vendor present.
    assert by_id["CVE-9000-0001"].cvss == 9.8
    # No preferred vendor: falls back rather than returning None.
    assert by_id["CVE-9000-0005"].cvss == 7.1
    # Preference order applies when nvd is absent but redhat is present.
    assert by_id["CVE-9000-0003"].cvss == 5.5


def test_a_missing_cwe_list_is_none_not_a_guess(scanner_fixture, id_generator, clock):
    by_id = {f.title.split(":")[0]: f for f in _map(scanner_fixture(_EDGES), id_generator, clock)}

    assert by_id["CVE-9000-0002"].cwe is None
    assert by_id["CVE-9000-0003"].cwe is None


def test_a_null_vulnerabilities_list_is_handled(scanner_fixture, id_generator, clock):
    """Trivy emits `"Vulnerabilities": null` for a clean target, and omits the key
    entirely for a config result — `test_trivy_adapter.py` works around the same
    thing. Neither may crash the mapper or produce a phantom finding."""
    findings = _map(scanner_fixture(_EDGES), id_generator, clock)

    assert len(findings) == 6
    assert all(f.location.file_path == "poetry.lock" for f in findings)


def test_an_empty_document_produces_no_findings(id_generator, clock):
    assert _map('{"SchemaVersion": 2, "Results": []}', id_generator, clock) == []
    assert _map('{"SchemaVersion": 2}', id_generator, clock) == []
