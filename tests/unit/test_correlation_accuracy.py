"""M5.3's curated correlation fixtures, their expected groupings, and the shape check over them.

Two artifacts in one module, because `tests/` is not a package — see `tests/conftest.py`'s
`scanner_fixture` docstring, which states that constraint and why a shared path constant has
to arrive as a fixture. Nothing in `tests/` imports across test modules today either.

- The **curated fixture set**: hand-written `Finding`s with the group each must land in,
  run through the shipped path (`build_match_key`, then `group_by_match_key`) as a
  regression suite. M5.3's roadmap entry defines the deliverable and bounds what it may
  demonstrate; **G19** is acceptance criteria there.
- The **shape conformance check**: each fixture's field-presence profile against a profile
  derived at run time from the three committed real fixtures.
  `docs/adr/0026-fixture-shape-conformance-check.md` carries the whole decision, including
  what this may and may not be said to establish; the bounds that a reader of this file most
  needs are restated on `test_a_curated_finding_has_the_shape_the_corpus_has`.

**Not the shape of ADR-0020 decision 4, and deliberately not named as it.** That ADR's
first two layers compare declaration to declaration and are total by construction. Here the
corpus *is* the expected answer, so the check is sample-based. ADR-0026 decision 1 argues
why borrowing the name would import a guarantee this does not have.

What is **not** covered here, and where it is: the authorization gate and the project-scoped
read (`test_correlate_findings.py`), the key's annotation conformance, order-independence of
grouping and the pairwise relation (`test_match_key.py`), and ADR-0023 amendment section 8's
prediction over the committed corpus (`test_correlate_findings.py`).
"""

import dataclasses
import json
import uuid
from datetime import UTC, datetime

import pytest

from verion.modules.correlation.application.match_key_builder import build_match_key
from verion.modules.correlation.domain.matching import group_by_match_key
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# A fixed namespace, so every id below is UUID-formatted and stable across runs without
# twenty-six hex literals in the file. **Rule 9 is the only source for this property** —
# ADR-0026 section 3 records that id shape is exactly what no corpus can supply and no
# assertion here can check, which is why it is made true by construction rather than by
# care. uuid5 hashes its name, so these do not cluster the way the sequential ids in
# G19's originating defect did.
_NAMESPACE = uuid.UUID("6f2a1e5c-0b73-4d18-9c4a-2e8f7b1d5a30")


def _id(label: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, label))


_PROJECT = _id("project:demo-target")
_OTHER_PROJECT = _id("project:someone-elses")
_SCAN = _id("scan:1")
_AT = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CuratedFinding:
    """One hand-written finding and the group it is expected to land in.

    The expected group is declared **beside** the finding rather than in a separate
    expectations table, so a fixture cannot be added without somebody deciding what it
    should correlate with. Findings expected to be singletons carry a group label of their
    own; two singletons sharing one label would wrongly expect one group.
    """

    label: str
    expected_group: str
    finding: Finding


def _curated(
    *,
    label: str,
    expected_group: str,
    source: ScannerTool,
    rule_id: str,
    severity: Severity,
    native_severity: str,
    title: str,
    location: Location,
    raw_payload: str,
    project_id: str = _PROJECT,
    cwe: str | None = None,
    owasp_category: str | None = None,
    cvss: float | None = None,
) -> CuratedFinding:
    finding_id = _id(f"finding:{label}")
    return CuratedFinding(
        label=label,
        expected_group=expected_group,
        finding=Finding(
            id=finding_id,
            project_id=project_id,
            source=source,
            rule_id=rule_id,
            severity=severity,
            native_severity=native_severity,
            title=title,
            location=location,
            evidence=Evidence(
                id=_id(f"evidence:{label}"),
                finding_id=finding_id,
                scan_id=_SCAN,
                raw_payload=raw_payload,
                source_tool=source,
                captured_at=_AT,
            ),
            cwe=cwe,
            owasp_category=owasp_category,
            cvss=cvss,
        ),
    )


def _trivy(
    label: str,
    expected_group: str,
    *,
    rule_id: str,
    package: str,
    installed_version: str,
    cwe: str,
    cvss: float,
    severity: Severity,
    native_severity: str,
    title: str,
    project_id: str = _PROJECT,
) -> CuratedFinding:
    """A Trivy-shaped finding: manifest path, package, version, CWE and CVSS, nothing else.

    The five populated fields are the ones the committed capture populates on all twenty of
    its findings; the conformance check derives that rather than trusting this comment.
    """
    return _curated(
        label=label,
        expected_group=expected_group,
        source=ScannerTool.TRIVY,
        rule_id=rule_id,
        severity=severity,
        native_severity=native_severity,
        title=title,
        location=Location(
            file_path="requirements.txt",
            package=package,
            installed_version=installed_version,
        ),
        raw_payload=json.dumps(
            {
                "VulnerabilityID": rule_id,
                "PkgName": package,
                "InstalledVersion": installed_version,
                "Severity": native_severity,
                "CweIDs": [cwe],
            },
            separators=(",", ":"),
        ),
        project_id=project_id,
        cwe=cwe,
        cvss=cvss,
    )


def _zap(
    label: str,
    expected_group: str,
    *,
    rule_id: str,
    url: str,
    cwe: str,
    severity: Severity,
    native_severity: str,
    title: str,
    http_method: str = "GET",
    parameter: str | None = None,
) -> CuratedFinding:
    """A ZAP-shaped finding: one `(alert, instance)` pair, so url and method are per-instance.

    `parameter` is free to be present or absent: it is partial in the committed capture, and
    ADR-0026 section 3 excludes partial rows from the check by the rule rather than by an
    exception. Both are exercised below so the fixture set does not accidentally imply one.
    """
    return _curated(
        label=label,
        expected_group=expected_group,
        source=ScannerTool.ZAP,
        rule_id=rule_id,
        severity=severity,
        native_severity=native_severity,
        title=title,
        location=Location(url=url, http_method=http_method, parameter=parameter),
        raw_payload=json.dumps(
            {
                "alertRef": rule_id,
                "cweid": cwe.removeprefix("CWE-"),
                "riskdesc": f"{native_severity} (Medium)",
                "instance": {"uri": url, "method": http_method, "param": parameter or ""},
            },
            separators=(",", ":"),
        ),
        cwe=cwe,
    )


def _semgrep(
    label: str,
    expected_group: str,
    *,
    file_path: str,
    start_line: int,
    end_line: int,
) -> CuratedFinding:
    """A Semgrep-shaped finding: a file and line span, and no vulnerability scalars at all.

    `rule_id`, `native_severity` and `title` are fixed rather than parameters because
    `rulesets/default.yml` declares exactly one rule, at `severity: ERROR` — so every Semgrep
    finding this deployment can produce today carries these three values, and a second fixture
    is that rule firing at a second location rather than a second invented rule id. `title` is
    the rule id rather than the rule's `message`, because that is what `mappers/semgrep.py`
    constructs it from. M5.3's roadmap entry is where the instruction about `rule_id` lives.

    `cwe`, `owasp_category` and `cvss` are all absent, and the two grounds for that are
    different ones — separated in ADR-0026 decision 1's `#### The measured ground, which is
    two different claims and not one`, which is where they are argued.
    """
    return _curated(
        label=label,
        expected_group=expected_group,
        source=ScannerTool.SEMGREP,
        rule_id="dangerous-eval",
        severity=Severity.HIGH,
        native_severity="ERROR",
        title="dangerous-eval",
        location=Location(file_path=file_path, start_line=start_line, end_line=end_line),
        raw_payload=json.dumps(
            {
                "check_id": "dangerous-eval",
                "path": file_path,
                "start": {"line": start_line},
                "end": {"line": end_line},
                "extra": {"severity": "ERROR", "metadata": {}},
            },
            separators=(",", ":"),
        ),
    )


# The fixture set. **Enumerable and iterated, never named one by one** — a check that
# listed these individually would be the third free-to-drift copy ADR-0026 decision 5
# rejects, and would silently stop covering whatever somebody adds here. Same construction
# as `SIGNAL_FIELDS` in `correlation/domain/match_key.py`, which `test_match_key.py`
# parametrizes over for the same reason.
#
# Three things this set may not contain, each with its own ground:
#   - a group spanning two tools, and no derived-location group at all: M5.5 and M5.6 do
#     not exist, and M5.3's entry forbids showing what the system does not do;
#   - the CWE the register records as the one measured cross-tool pair and a FALSE match:
#     no CWE value appears on both a Trivy and a ZAP fixture here;
#   - a CWE, OWASP category or CVSS on a Semgrep finding — see `_semgrep`.
# The check below mechanises the third. The first two are held by review.
_CURATED: tuple[CuratedFinding, ...] = (
    _trivy(
        "trivy-urllib3-cve-2019-11324",
        "urllib3",
        rule_id="CVE-2019-11324",
        package="urllib3",
        installed_version="1.24.1",
        cwe="CWE-295",
        cvss=7.5,
        severity=Severity.HIGH,
        native_severity="HIGH",
        title="urllib3 before 1.24.2 does not remove the Authorization HTTP header",
    ),
    _trivy(
        "trivy-urllib3-cve-2019-11236",
        "urllib3",
        rule_id="CVE-2019-11236",
        package="urllib3",
        installed_version="1.24.1",
        cwe="CWE-93",
        cvss=6.1,
        severity=Severity.MEDIUM,
        native_severity="MEDIUM",
        title="urllib3: CRLF injection via the request method",
    ),
    # Same package, a DIFFERENT installed version: this must still group. `installed_version`
    # is one of the three fields `dedup_hash` excludes because they refresh per sighting, and
    # ADR-0023 amendment section 3 keeps it out of the key on that ground.
    _trivy(
        "trivy-urllib3-cve-2020-26137",
        "urllib3",
        rule_id="CVE-2020-26137",
        package="urllib3",
        installed_version="1.25.9",
        cwe="CWE-93",
        cvss=6.5,
        severity=Severity.MEDIUM,
        native_severity="MEDIUM",
        title="urllib3: CRLF injection via HTTP request headers",
    ),
    _trivy(
        "trivy-flask-cve-2023-30861",
        "Flask",
        rule_id="CVE-2023-30861",
        package="Flask",
        installed_version="2.3.1",
        cwe="CWE-539",
        cvss=7.5,
        severity=Severity.HIGH,
        native_severity="HIGH",
        title="flask: Possible disclosure of permanent session cookie",
    ),
    # An equal signal in another project. `project_id` is scope rather than signal, so this
    # must not join the three above however identical the package looks.
    _trivy(
        "trivy-urllib3-other-project",
        "other-project-urllib3",
        rule_id="CVE-2019-11324",
        package="urllib3",
        installed_version="1.24.1",
        cwe="CWE-295",
        cvss=7.5,
        severity=Severity.HIGH,
        native_severity="HIGH",
        title="urllib3 before 1.24.2 does not remove the Authorization HTTP header",
        project_id=_OTHER_PROJECT,
    ),
    _zap(
        "zap-root-csp",
        "zap-root",
        rule_id="10038-1",
        url="http://target.example:8080/",
        cwe="CWE-693",
        severity=Severity.MEDIUM,
        native_severity="Medium",
        title="Content Security Policy (CSP) Header Not Set",
    ),
    # Same url, a populated `parameter`: must still group. A ZAP-only refinement OF `url`,
    # whose only effect on a key would be to split the groups `url` exists to produce.
    _zap(
        "zap-root-clickjacking",
        "zap-root",
        rule_id="10020-1",
        url="http://target.example:8080/",
        cwe="CWE-1021",
        severity=Severity.MEDIUM,
        native_severity="Medium",
        title="Missing Anti-clickjacking Header",
        parameter="x-frame-options",
    ),
    # Same url, a different method: must still group, for the same reason.
    _zap(
        "zap-root-server-banner",
        "zap-root",
        rule_id="10036-2",
        url="http://target.example:8080/",
        cwe="CWE-497",
        severity=Severity.LOW,
        native_severity="Low",
        title="Server Leaks Version Information via Server HTTP Response Header Field",
        http_method="HEAD",
    ),
    _zap(
        "zap-calculate-expr-2x3",
        "zap-calculate-expr-2x3",
        rule_id="10038-1",
        url="http://target.example:8080/calculate?expr=2*3",
        cwe="CWE-693",
        severity=Severity.MEDIUM,
        native_severity="Medium",
        title="Content Security Policy (CSP) Header Not Set",
    ),
    # Same PATH as the one above, a different query string. Two groups, because the key is
    # the full `Location.url`. ADR-0023 amendment section 6 argues that choice and names
    # **G31** as the trigger to revisit it at M5.4; ADR-0026's Consequences records that
    # fixtures written now bake the pre-M5.4 grouping in. This is that, written down.
    _zap(
        "zap-calculate-expr-calculate",
        "zap-calculate-expr-calculate",
        rule_id="10038-1",
        url="http://target.example:8080/calculate?expr=calculate",
        cwe="CWE-693",
        severity=Severity.MEDIUM,
        native_severity="Medium",
        title="Content Security Policy (CSP) Header Not Set",
    ),
    # Two no-signal findings, each its own singleton. The committed corpus cannot exercise
    # this: it holds exactly one Semgrep finding, so one group of one either way.
    _semgrep(
        "semgrep-eval-app",
        "semgrep-eval-app",
        file_path="app.py",
        start_line=12,
        end_line=12,
    ),
    _semgrep(
        "semgrep-eval-helpers",
        "semgrep-eval-helpers",
        file_path="helpers.py",
        start_line=31,
        end_line=33,
    ),
)


def _by_label(*labels: str) -> list[CuratedFinding]:
    registry = {curated.label: curated for curated in _CURATED}
    return [registry[label] for label in labels]


# ---------------------------------------------------------------------------
# The corpus profile: populated-or-not per field, per tool, derived at run time
# ---------------------------------------------------------------------------

ALWAYS = "ALWAYS"
SOMETIMES = "SOMETIMES"
NEVER = "NEVER"

# The three `Finding` scalars the profile covers, beside `Location`'s eight fields.
_SHAPE_SCALARS = ("cwe", "owasp_category", "cvss")

# Every other `Finding` field, declared so that the partition below can be checked against
# the entity's own declaration. Surrogate, scope, provenance and rule-level attributes —
# none of them a location or vulnerability shape the fixtures could get wrong in the way
# this check is about.
_NOT_SHAPE_FIELDS = (
    "id",
    "project_id",
    "source",
    "rule_id",
    "severity",
    "native_severity",
    "title",
    "evidence",
)


def _shape_of(finding: Finding) -> dict[str, bool]:
    """Populated-or-not for each of the eleven profile fields. Values are never read."""
    location = {
        field.name: getattr(finding.location, field.name) is not None
        for field in dataclasses.fields(Location)
    }
    scalars = {name: getattr(finding, name) is not None for name in _SHAPE_SCALARS}
    return {**location, **scalars}


@pytest.fixture
def corpus_profile(
    scanner_fixture, id_generator, clock
) -> dict[tuple[str, str], tuple[str, int, int]]:
    """`(tool, field) -> (row, populated, n)`, from the three committed captures.

    Derived from the **committed** fixtures only. Feeding M5.3's own fixtures in would raise
    Semgrep's denominator using the very data whose shape is in question — ADR-0026
    alternative 3 rejects it as G19 in one move.

    **Two things are deliberately not asserted anywhere, and both are decisions rather than
    omissions.** Disjointness of the three rows: the classification below is an
    `if`/`elif`/`else`, so no field can land in two buckets, and asserting it would test the
    language — ADR-0026 decision 2 says so and this is that. And the profile's field set
    against `dataclasses.fields(Location)` plus `_SHAPE_SCALARS`: the profile is *built* from
    exactly those two sources, so the comparison is `A == A` and cannot fail. A field added
    to `Location` is caught by the pinned-membership test instead, where it arrives as a new
    `0/n` NEVER row the pinned literals do not contain. Verified by mutation: adding a
    `fragment` field to `Location` left the union test green and turned the membership test
    red on `semgrep NEVER rows are (…'fragment'…) over n=1`.
    """
    corpus = {
        "semgrep": map_semgrep_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("semgrep_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        "trivy": map_trivy_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("trivy_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        "zap": map_zap_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("zap_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
    }

    profile: dict[tuple[str, str], tuple[str, int, int]] = {}
    for tool, findings in corpus.items():
        n = len(findings)
        shapes = [_shape_of(finding) for finding in findings]
        for field in shapes[0]:
            populated = sum(1 for shape in shapes if shape[field])
            if populated == n:
                row = ALWAYS
            elif populated == 0:
                row = NEVER
            else:
                row = SOMETIMES
            profile[(tool, field)] = (row, populated, n)
    return profile


# What the profile is expected to be, written as pinned literals against data read at run
# time — the `test_the_real_cwe_cardinality_is_one_apart_from_a_single_two` construction,
# not a free-to-drift list. A re-capture that moves any row turns this red, which is the
# guard working: ADR-0026's Consequences and **G39** carry why, and G39 is the entry that
# fires when a pinned ruleset or scan plan changes without a re-capture.
_EXPECTED_DENOMINATORS = {"semgrep": 1, "trivy": 20, "zap": 13}

_EXPECTED_PROFILE: dict[str, dict[str, tuple[str, ...]]] = {
    "semgrep": {
        ALWAYS: ("end_line", "file_path", "start_line"),
        SOMETIMES: (),
        NEVER: (
            "cvss",
            "cwe",
            "http_method",
            "installed_version",
            "owasp_category",
            "package",
            "parameter",
            "url",
        ),
    },
    "trivy": {
        ALWAYS: ("cvss", "cwe", "file_path", "installed_version", "package"),
        SOMETIMES: (),
        NEVER: ("end_line", "http_method", "owasp_category", "parameter", "start_line", "url"),
    },
    "zap": {
        ALWAYS: ("cwe", "http_method", "url"),
        SOMETIMES: ("parameter",),
        NEVER: (
            "cvss",
            "end_line",
            "file_path",
            "installed_version",
            "owasp_category",
            "package",
            "start_line",
        ),
    },
}

# How many of the eleven rows a fixture of each tool is actually checked against. ZAP is 10
# rather than 11 because a partial row constrains nothing and is skipped by the rule.
_EXAMINED_ROWS = {"semgrep": 11, "trivy": 11, "zap": 10}


# ---------------------------------------------------------------------------
# The partition, against `Finding`'s own declaration
# ---------------------------------------------------------------------------


def test_every_finding_field_is_a_shape_scalar_the_location_or_neither():
    """A field cannot join `Finding` without somebody deciding whether it has a shape.

    A new scalar that no bucket accounts for fails here rather than arriving silently and
    being invisible to every fixture ever written. `dataclasses.fields(Finding)` is the
    declaration; the two tuples are the claim under test.

    This is the whole of the live union assertion. The other half decision 2 describes — the
    profile's field set against `Location`'s declaration — is not asserted, because both
    sides of it derive from `dataclasses.fields(Location)`; see `corpus_profile`'s docstring
    for that and for where a new `Location` field is caught instead. **That departure from an
    accepted ADR is registered as G41**, so it is findable from the register rather than only
    from here.

    Verified by mutation: adding an `epss` scalar to `Finding` turned this red alone, on
    `Extra items in the right set: 'epss'`, with every other test in this module green.
    """
    assert {"location", *_SHAPE_SCALARS, *_NOT_SHAPE_FIELDS} == {
        field.name for field in dataclasses.fields(Finding)
    }


def test_the_pinned_profile_holds_and_zap_parameter_is_the_only_row_no_fixture_is_checked_against(
    corpus_profile,
):
    """The corpus's shape, pinned. A re-capture that moves a row fails here.

    Both directions matter and the ADR names both: a re-capture that made ZAP's `parameter`
    populated on every instance, or one that made a currently-ALWAYS field partial, changes
    what the fixtures are checked against and must not do so quietly.

    The denominators are pinned beside the rows because they are what a row *means*:
    Semgrep's eight NEVER rows rest on a single finding, and a reader of a failure here
    should not have to go and count.

    Verified by mutation on the DERIVED side, since a re-capture is what this layer guards:
    stripping every `param` value from `tests/fixtures/scanners/zap_scan.json` moved
    `parameter` from SOMETIMES to NEVER, and this failed on that reclassification —
    `zap SOMETIMES rows are () over n=13, pinned as ('parameter',)` — not on a read error.
    """
    denominators = {tool: n for (tool, _field), (_row, _populated, n) in corpus_profile.items()}
    assert denominators == _EXPECTED_DENOMINATORS

    derived: dict[str, dict[str, list[str]]] = {}
    for (tool, field), (row, _populated, _n) in corpus_profile.items():
        derived.setdefault(tool, {}).setdefault(row, []).append(field)

    for tool, buckets in _EXPECTED_PROFILE.items():
        for row in (ALWAYS, SOMETIMES, NEVER):
            actual = tuple(sorted(derived[tool].get(row, [])))
            assert actual == buckets[row], (
                f"{tool} {row} rows are {actual} over n={denominators[tool]}, "
                f"pinned as {buckets[row]}"
            )


# ---------------------------------------------------------------------------
# Conformance — every curated fixture against the profile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("curated", _CURATED, ids=[c.label for c in _CURATED])
def test_a_curated_finding_has_the_shape_the_corpus_has(curated, corpus_profile):
    """Populated where the corpus is always populated, absent where it never is.

    **Sample-based, and bounded.** This says nothing about the VALUE of any field, nothing
    about id shape, and nothing about cardinality, ordering, distribution or width — the four
    properties **G19** names as the ones a planner reads. ADR-0026 section 3 states the bounds
    in full, and states that shipping this does not discharge G19.

    A partial row is skipped **by the rule** — a row that is neither always nor never
    populated constrains nothing — and never by a hand-written exception. `parameter` is the
    only such row today; the test above is where that is pinned and named.

    Verified by mutation: giving `_semgrep` a `cwe` turned this red on the row ADR-0026 calls
    the profile's load-bearing one — `semgrep cwe is NEVER in the corpus at 0/1, but this
    fixture has it populated`.
    """
    tool = str(curated.finding.source)
    examined = 0

    for field, populated in _shape_of(curated.finding).items():
        row, count, n = corpus_profile[(tool, field)]
        if row == SOMETIMES:
            continue
        examined += 1
        assert populated is (row == ALWAYS), (
            f"{curated.label}: {tool} {field} is {row} in the corpus at {count}/{n}, "
            f"but this fixture has it {'populated' if populated else 'absent'}"
        )

    assert examined == _EXAMINED_ROWS[tool], (
        f"{curated.label}: examined {examined} rows, expected {_EXAMINED_ROWS[tool]}"
    )


def test_the_conformance_check_runs_over_every_fixture_and_all_three_tools():
    """The precondition the conformance test rests on, asserted rather than assumed.

    The check above iterates the registry, so it covers whatever `_CURATED` holds and no more.

    Verified by mutation: `_CURATED = ()` turned this red on `assert 0 == 12`. Six grouping
    tests went red too, on `KeyError` out of `_by_label`.
    """
    assert len(_CURATED) == 12
    assert {str(curated.finding.source) for curated in _CURATED} == {"semgrep", "trivy", "zap"}
    assert len({curated.label for curated in _CURATED}) == len(_CURATED)

    pairs = sum(_EXAMINED_ROWS[str(curated.finding.source)] for curated in _CURATED)
    assert pairs == 127


# ---------------------------------------------------------------------------
# Grouping — the registry's declared groups against the shipped matcher
# ---------------------------------------------------------------------------


def _grouped(curated: list[CuratedFinding] | tuple[CuratedFinding, ...]) -> list[tuple[str, ...]]:
    """Group by label, through the shipped path: `build_match_key` then `group_by_match_key`.

    Labels rather than ids, so a failure reads as names. Both are pure functions, so this
    exercises the matcher without the repository read and authorization gate
    `test_correlate_findings.py` covers.
    """
    label_of = {item.finding.id: item.label for item in curated}
    groups = group_by_match_key(
        [
            (
                item.finding.id,
                build_match_key(
                    project_id=item.finding.project_id,
                    package=item.finding.location.package,
                    url=item.finding.location.url,
                ),
            )
            for item in curated
        ]
    )
    return sorted(tuple(sorted(label_of[i] for i in group.finding_ids)) for group in groups)


def test_the_matcher_produces_exactly_the_groups_the_registry_declares():
    """Positive and negative in one shape: the whole partition, not a sample of it.

    Every fixture's declared group is checked at once, so a fixture that joined a group it
    should not is as loud as one that failed to join the group it should. The named cases
    below single out the ones worth being able to point at.
    """
    declared: dict[str, list[str]] = {}
    for curated in _CURATED:
        declared.setdefault(curated.expected_group, []).append(curated.label)

    assert _grouped(_CURATED) == sorted(tuple(sorted(labels)) for labels in declared.values())


def test_every_curated_finding_lands_in_exactly_one_group():
    """Nothing dropped, nothing duplicated — the invariant a Risk count is reconciled against."""
    grouped = [label for group in _grouped(_CURATED) for label in group]

    assert len(grouped) == len(_CURATED)
    assert set(grouped) == {curated.label for curated in _CURATED}


# --- should correlate ------------------------------------------------------


def test_findings_on_one_package_group_across_two_installed_versions():
    """`installed_version` refreshes on every sighting, so a key carrying it would be unstable
    across scans. ADR-0023's 2026-08-26 amendment section 3 excludes it on that ground."""
    assert _grouped(
        _by_label(
            "trivy-urllib3-cve-2019-11324",
            "trivy-urllib3-cve-2019-11236",
            "trivy-urllib3-cve-2020-26137",
        )
    ) == [
        (
            "trivy-urllib3-cve-2019-11236",
            "trivy-urllib3-cve-2019-11324",
            "trivy-urllib3-cve-2020-26137",
        )
    ]


def test_findings_at_one_url_group_across_method_and_parameter():
    """`http_method` and `parameter` are ZAP-only refinements OF `url`, and the only effect of
    keying on them would be to split the groups `url` exists to produce, finer, inside one
    tool. Same amendment section."""
    assert _grouped(
        _by_label("zap-root-csp", "zap-root-clickjacking", "zap-root-server-banner")
    ) == [("zap-root-clickjacking", "zap-root-csp", "zap-root-server-banner")]


# --- should NOT correlate --------------------------------------------------


def test_two_different_packages_do_not_correlate():
    assert _grouped(_by_label("trivy-urllib3-cve-2019-11324", "trivy-flask-cve-2023-30861")) == [
        ("trivy-flask-cve-2023-30861",),
        ("trivy-urllib3-cve-2019-11324",),
    ]


def test_two_urls_that_differ_only_in_their_query_string_do_not_correlate():
    """The key is the FULL url, so one path with two query strings is two groups.

    This is the pre-M5.4 grouping, and the fixture set bakes it in deliberately rather than
    by accident: ADR-0023's amendment section 6 records the choice and **G31** is the trigger
    to revisit it when M5.4's active plan makes `url` split `/calculate` in production.
    """
    assert _grouped(_by_label("zap-calculate-expr-2x3", "zap-calculate-expr-calculate")) == [
        ("zap-calculate-expr-2x3",),
        ("zap-calculate-expr-calculate",),
    ]


def test_the_same_package_in_two_projects_does_not_correlate():
    """The tenant boundary. `project_id` is scope, never on its own a reason to correlate."""
    assert _grouped(_by_label("trivy-urllib3-cve-2019-11324", "trivy-urllib3-other-project")) == [
        ("trivy-urllib3-cve-2019-11324",),
        ("trivy-urllib3-other-project",),
    ]


def test_two_no_signal_findings_become_two_singletons_rather_than_one_group():
    """Two absences are not a match, and neither is a drop.

    Both halves pull opposite ways and both are decided elsewhere: bucketing them together
    would fabricate an event no tool reported, and dropping them would make a Risk count that
    cannot be reconciled against `count_for_project`. **G36** carries what a `matches` written
    to the ADR's letter would do here instead — every no-signal finding in a project fused
    into one Risk — and records that the committed corpus cannot detect it, because it holds
    exactly one such finding.
    """
    assert _grouped(_by_label("semgrep-eval-app", "semgrep-eval-helpers")) == [
        ("semgrep-eval-app",),
        ("semgrep-eval-helpers",),
    ]


def test_no_group_spans_two_tools():
    """Asserted from the fixtures' own `source` values, never read off the key.

    Reading tool-disjointness off the key would be circular — the key cannot carry a
    `source`, so it would restate the field list. What actually prevents a cross-tool match
    is the mappers, and M5.3 may not exhibit a cross-tool group in any case: M5.5 and M5.6 do
    not exist, so a group spanning two tools here would be showing something the system does
    not do.
    """
    source_of = {curated.label: str(curated.finding.source) for curated in _CURATED}

    assert [group for group in _grouped(_CURATED) if len({source_of[i] for i in group}) > 1] == []
