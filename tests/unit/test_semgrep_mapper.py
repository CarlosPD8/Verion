import json

from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "semgrep_scan.json"
_EDGES = "semgrep_synthetic_edges.json"


def _map(raw, id_generator, clock, scan_id="scan-1"):
    return map_semgrep_output(
        project_id="proj-1",
        scan_id=scan_id,
        raw_output=raw,
        id_generator=id_generator,
        clock=clock,
    )


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against genuine Semgrep 1.173.0 output, not a hand-written approximation."""
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.project_id == "proj-1"
    assert finding.evidence.scan_id == "scan-1"
    assert finding.source is ScannerTool.SEMGREP
    assert finding.severity is Severity.HIGH
    assert finding.native_severity == "ERROR"
    assert finding.title == "dangerous-eval"
    # The G23 target's own source file, not M4.1's two-line `vulnerable.py`.
    assert finding.location.file_path == "app.py"
    assert finding.location.start_line == 28
    assert finding.location.end_line == 28


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


def test_rule_id_is_the_check_id_and_not_the_title(scanner_fixture, id_generator, clock):
    """`rule_id` exists because the common schema had nowhere to put "what
    fired". For Semgrep the two happen to coincide, which is why this asserts the
    field rather than the string — Trivy's title is `"<CVE>: <prose>"`, and it is
    the prose half that makes hashing `title` unsafe.

    Equality, not `endswith` (M4.4). `rule_id` is a `dedup_hash` input, and the
    suffix form passed for all three of the CWD-dependent dotted `check_id` values
    G10 measured — so it could not distinguish the value production writes from two
    it never will. The fixture now carries the post-fix `dangerous-eval`; what pins
    the *adapter* producing it is `test_semgrep_adapter.py`, since no committed
    capture can observe a CWD-dependent value."""
    finding = _map(scanner_fixture(_REAL), id_generator, clock)[0]

    assert finding.rule_id == "dangerous-eval"


def test_the_same_output_dedups_to_the_same_hash_across_scans(scanner_fixture, id_generator, clock):
    """M4.2's acceptance criterion, asserted at the domain layer because that is
    the only one M4.2 shipped — persistence is M4.3's: re-running a scan must not
    duplicate an identical finding.

    The two mappings get **different** surrogate ids and the **same**
    `dedup_hash`, which is what proves identity comes from the content rather
    than from the id — the property M4.3's upsert on `(project_id, dedup_hash)`
    is built on.
    """
    raw = scanner_fixture(_REAL)

    first = _map(raw, id_generator, clock, scan_id="scan-1")[0]
    second = _map(raw, id_generator, clock, scan_id="scan-2")[0]

    assert first.id != second.id
    assert first.evidence.scan_id != second.evidence.scan_id
    assert first.dedup_hash == second.dedup_hash


def test_a_line_shift_does_not_change_identity(scanner_fixture, id_generator, clock):
    """An edit *above* a finding moves its line range without changing the
    finding, so `start_line`/`end_line` are excluded from `dedup_hash`.

    The captured fixture cannot show this — that would need two scans of a
    mutated target — so the shift is applied to a copy of the real document here,
    and the docstring says so rather than implying the capture proved it.
    """
    document = json.loads(scanner_fixture(_REAL))
    shifted = json.loads(scanner_fixture(_REAL))
    shifted["results"][0]["start"]["line"] += 40
    shifted["results"][0]["end"]["line"] += 40

    original = _map(json.dumps(document), id_generator, clock)[0]
    moved = _map(json.dumps(shifted), id_generator, clock)[0]

    assert moved.location.start_line == original.location.start_line + 40
    assert moved.dedup_hash == original.dedup_hash


def test_an_empty_result_set_produces_no_findings(id_generator, clock):
    """An empty `results` array is a real Semgrep response, not a malformed one.

    `octocat/Hello-World` produces exactly this against the pinned Python-only
    ruleset, which is why it was never a viable capture target. (This docstring
    read "…and why the fixtures are captured from the per-adapter targets instead"
    until M5.1: since G23 they are captured from one common target, so that clause
    described an arrangement that no longer exists.)
    """
    empty = '{"version": "1.173.0", "results": [], "errors": [], "paths": {"scanned": []}}'

    assert _map(empty, id_generator, clock) == []
