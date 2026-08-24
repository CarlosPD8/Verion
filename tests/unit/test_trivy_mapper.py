import json
from collections import Counter

from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_REAL = "trivy_scan.json"
_EDGES = "trivy_synthetic_edges.json"


def _map(raw, id_generator, clock, scan_id="scan-1"):
    return map_trivy_output(
        project_id="proj-1",
        scan_id=scan_id,
        raw_output=raw,
        id_generator=id_generator,
        clock=clock,
    )


def test_maps_the_real_captured_output(scanner_fixture, id_generator, clock):
    """Against genuine Trivy 0.74.0 output for the G23 target's pinned closure.

    Re-derived at M5.1 against the common-target corpus. The old capture was one
    `requirements.txt` holding `urllib3==1.24.1` alone; this one is that target's
    whole closure, so the counts below cover three packages (Flask 2, Werkzeug 6,
    urllib3 12) rather than one.
    """
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert len(findings) == 20
    assert {f.source for f in findings} == {ScannerTool.TRIVY}
    # LOW is new in this corpus — the previous capture had no LOW at all.
    assert {f.severity for f in findings} == {Severity.HIGH, Severity.MEDIUM, Severity.LOW}
    assert sorted(f.native_severity for f in findings) == (
        ["HIGH"] * 8 + ["LOW"] * 1 + ["MEDIUM"] * 11
    )

    known = next(f for f in findings if f.title.startswith("CVE-2019-11324"))
    assert known.severity is Severity.HIGH
    assert known.cwe == "CWE-295"
    assert known.cvss == 7.5
    assert known.location.file_path == "requirements.txt"
    assert known.location.package == "urllib3"
    assert known.location.installed_version == "1.24.1"


def test_each_vulnerability_gets_its_own_identity(scanner_fixture, id_generator, clock):
    """Identity is `VulnerabilityID` + `Target` + `PkgName`. Twenty CVEs across
    three packages in one manifest must be twenty findings, not three.

    **The expected set is now derived from the whole document rather than from
    `range(12)`.** The literal index range was a G20 hazard in its own right: it
    covered the first twelve elements by position, so a re-capture that grew the
    fixture left the extra elements unasserted while the test still looked like a
    completeness check. Deriving it from every `Vulnerabilities` entry makes the
    assertion track the fixture instead of a number somebody has to remember.
    """
    findings = _map(scanner_fixture(_REAL), id_generator, clock)
    document = json.loads(scanner_fixture(_REAL))

    assert len({f.dedup_hash for f in findings}) == 20
    assert {f.rule_id for f in findings} == {
        vulnerability["VulnerabilityID"]
        for result in document["Results"]
        for vulnerability in (result.get("Vulnerabilities") or [])
    }


def test_a_version_bump_is_not_a_new_finding(scanner_fixture, id_generator, clock):
    """`InstalledVersion` is excluded from `dedup_hash` deliberately.

    Bumping a package from one vulnerable version to another vulnerable version
    does not fix anything, so re-keying the finding would report a resolution
    that never happened. When a bump *does* remediate, Trivy stops reporting the
    CVE and the finding stops being sighted — which is the correct signal, and
    needs no help from the hash.
    """
    document = json.loads(scanner_fixture(_REAL))
    bumped = json.loads(scanner_fixture(_REAL))
    for vulnerability in bumped["Results"][0]["Vulnerabilities"]:
        vulnerability["InstalledVersion"] = "1.25.0"

    before = _map(json.dumps(document), id_generator, clock)[0]
    after = _map(json.dumps(bumped), id_generator, clock)[0]

    assert after.location.installed_version == "1.25.0"
    assert after.dedup_hash == before.dedup_hash


def test_the_real_cwe_cardinality_is_one_apart_from_a_single_two(
    scanner_fixture, id_generator, clock
):
    """The measurement ADR-0018 decision 4 cites — **and this test is why the
    falsification was loud rather than silent.**

    Renamed at M5.1, because the old name asserted the falsified fact. It read
    `test_every_real_vulnerability_carries_exactly_one_cwe`, and the G23 capture
    made that false: `CVE-2024-49767` (Werkzeug 2.3.8) carries
    `["CWE-400", "CWE-770"]`. A test whose *name* states a claim the data refutes
    is worse than a stale docstring, since the name is what a reader trusts
    without opening the body.

    **What this does and does not guard, unchanged in kind.** It guards the
    *fixture*: the literals below are read against data loaded at run time, so any
    re-capture that changes the cardinality — or moves the two-CWE case to a
    different vulnerability — fails here rather than silently widening the
    evidence an accepted ADR rests on. That is exactly what happened at M5.1, in
    commit `00708b9`, where this test is red on purpose.

    It does **not** guard production, and the corpus does not settle *which*
    selection rule is in force: the mapper keeps the first entry in document
    order, but `CWE-400` is also the numerically lower one, so the data cannot
    distinguish "first" from "lowest" — only `mappers/trivy.py` does. Whether that
    ordering is even stable across vulnerability-DB updates is unmeasured (G26).
    The mapper's *behaviour* on multi-CWE input is pinned by
    `test_multiple_cwes_keep_the_first_and_lose_none` below; the two tests answer
    different questions and both are needed.
    """
    findings = _map(scanner_fixture(_REAL), id_generator, clock)

    assert all(f.cwe is not None for f in findings)
    source = json.loads(scanner_fixture(_REAL))
    by_cardinality = Counter(
        len(v.get("CweIDs") or [])
        for r in source["Results"]
        for v in (r.get("Vulnerabilities") or [])
    )
    assert by_cardinality == Counter({1: 19, 2: 1})

    # Named, not just counted: a re-capture that keeps one two-CWE vulnerability
    # but makes it a different one is a change to the evidence too.
    multi = [
        v["VulnerabilityID"]
        for r in source["Results"]
        for v in (r.get("Vulnerabilities") or [])
        if len(v.get("CweIDs") or []) > 1
    ]
    assert multi == ["CVE-2024-49767"]
    assert next(f for f in findings if f.rule_id == "CVE-2024-49767").cwe == "CWE-400"


def test_multiple_cwes_keep_the_first_and_lose_none(scanner_fixture, id_generator, clock):
    """What happens when a tool emits two CWEs — specified, not incidental.

    `Finding.cwe` is a single value, and until M5.1 the stated basis was that the
    measured maximum across the real fixtures was 1 — a fact about *those targets*,
    not about Trivy. **That basis is now falsified**: the G23 corpus contains one
    two-CWE vulnerability (ADR-0018's Amendments, 2026-08-24). The decision stands,
    for the reason this test exists: without it the mapper's `next(iter(...))` would
    have been an unexamined silent truncation, and a real two-CWE element arriving
    would have been the first anyone knew of it.

    **This test needed no change when that happened, which is the point of writing
    it against synthetic input.** It specifies the mapper's behaviour rather than
    the corpus's shape, so it was already correct for data that did not yet exist.
    Its sibling `test_the_real_cwe_cardinality_is_one_apart_from_a_single_two` is
    the one that guards the corpus, and that one did have to change.

    The contract asserted here is the one ADR-0018 claims: the first CWE as the
    tool ordered it becomes the correlation key, and **nothing is discarded** —
    the full list survives in `raw_payload`, so M5 can widen to set intersection
    later without a re-scan. (M4.2 has since been decided and did not widen it:
    `cwe` is advisory-mutable, so ADR-0019 keeps it out of `dedup_hash` entirely.)
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
    """The real fixture contains HIGH, MEDIUM and one LOW, so CRITICAL and the
    literal UNKNOWN are what still need covering here. UNKNOWN is carried through
    rather than folded into LOW — collapsing it would invent a Risk Engine input.

    (Read "only HIGH and MEDIUM" until M5.1; the G23 corpus brought a LOW. The
    synthetic set still covers it, so this test never went red — a docstring going
    stale silently, which is the G20 shape.)
    """
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
