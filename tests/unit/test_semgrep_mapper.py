import json

from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "semgrep_scan.json"
_EDGES = "semgrep_synthetic_edges.json"


def _map(raw, id_generator, clock):
    return map_semgrep_output(
        scan_id="scan-1", raw_output=raw, id_generator=id_generator, clock=clock
    )


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against genuine Semgrep 1.173.0 output, not a hand-written approximation."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scan_id == "scan-1"
    assert finding.source is ScannerTool.SEMGREP
    assert finding.severity is Severity.HIGH
    assert finding.native_severity == "ERROR"
    assert finding.title.endswith("dangerous-eval")
    assert finding.location.file_path == "vulnerable.py"
    assert finding.location.start_line == 2
    assert finding.location.end_line == 2


def test_absent_fields_are_none_and_are_never_invented(scanner_fixture, id_generator, clock):
    """The assertion that catches a mapper filling in a value the tool never gave.

    This project's pinned ruleset declares no `metadata`, so a real Semgrep
    finding here carries no CWE and no OWASP category — tracked as G6. Semgrep
    emits no CVSS at all. If any of these three ever becomes non-None from this
    fixture, something is manufacturing Risk Engine inputs (rule 5).
    """
    finding = _map(scanner_fixture(_REAL), id_generator, clock)[0]

    assert finding.cwe is None
    assert finding.owasp_category is None
    assert finding.cvss is None


def test_evidence_round_trips_to_the_exact_source_element(scanner_fixture, id_generator, clock):
    raw = scanner_fixture(_REAL)
    finding = _map(raw, id_generator, clock)[0]

    assert json.loads(finding.evidence.raw_payload) == json.loads(raw)["results"][0]
    assert finding.evidence.source_tool is ScannerTool.SEMGREP
    assert finding.evidence.finding_id == finding.id
    assert finding.evidence.captured_at == clock.now()


def test_metadata_is_read_when_a_rule_declares_it(scanner_fixture, id_generator, clock):
    """G6 is a property of this project's ruleset, not of the mapper — so the
    mapper must still populate both fields when a rule does declare them, whether
    as a list or as a bare string."""
    findings = _map(scanner_fixture(_EDGES), id_generator, clock)
    by_title = {f.title: f for f in findings}

    from_list = by_title["rules.with-metadata"]
    assert from_list.severity is Severity.MEDIUM
    assert from_list.native_severity == "WARNING"
    assert from_list.cwe == "CWE-95"
    assert from_list.owasp_category == "A03:2021 - Injection"

    from_scalar = by_title["rules.informational"]
    assert from_scalar.severity is Severity.INFO
    assert from_scalar.cwe == "CWE-16"
    assert from_scalar.owasp_category == "A05:2021 - Security Misconfiguration"


def test_an_unrecognised_severity_degrades_instead_of_raising(scanner_fixture, id_generator, clock):
    """A future Semgrep release can add a level. That must not take down a worker
    — but the tool's own word is still recorded, so nothing is silently lost."""
    findings = _map(scanner_fixture(_EDGES), id_generator, clock)
    degraded = next(f for f in findings if f.title.endswith("does-not-have-today"))

    assert degraded.severity is Severity.UNKNOWN
    assert degraded.native_severity == "CATASTROPHIC"


def test_an_empty_result_set_produces_no_findings(id_generator, clock):
    """What `octocat/Hello-World` actually returns, and why the fixtures are
    captured from the per-adapter targets instead."""
    empty = '{"version": "1.173.0", "results": [], "errors": [], "paths": {"scanned": []}}'

    assert _map(empty, id_generator, clock) == []
