"""`CorrelateFindingsUseCase` against fakes, and the ADR-0023 prediction against the corpus.

Four things here are not ordinary coverage:

- the **authorization gate-placement** test, which proves authorization runs before any read
  rather than merely that a denial happens (ADR-0013's idiom, as `test_list_project_findings.py`
  uses it);
- the **derivation gate** tests (M5.6 commit 3) — M5.6's acceptance criterion, *a derived
  SAST↔DAST group is not produced when the serving declaration is absent or out of force*,
  including an ordering test whose subject is that the route map is not even READ without a
  declaration in force;
- the **corpus measurement**, which runs the three committed fixtures through the real
  mappers and this module's own key, matcher and use case, twice — once with no declaration
  and once with one — against ADR-0023's amendment section 8, whose prediction the M5.6 re-key
  changed and whose divergence that ADR's 2026-09-15 amendment records clause by clause;
- the **ADR-0023 Decision A guard**, which lives here and not in `test_correlation_accuracy.py`
  because this is the file that runs the real ZAP mapper.

**What none of this proves about production**, stated because the derivation tests are green:
these tests exercise the gate and the derivation against a populated fake, and are not
evidence of a product capability. *(Until M5.6 commit 4 production's `RouteMapPort` returned
an empty map and produced no cross-tool group at all. Since commit 4 it reads a map stored at
Security Context build, and the evidence that production produces the group is
`tests/integration/test_derived_group_end_to_end.py`, not this file.)*
"""

from collections import Counter
from datetime import UTC, datetime

import pytest

from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.domain.exceptions import ProjectAccessDenied
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.modules.projects.domain.route_extraction import RouteMap, RouteSpan
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"
_USER = "user-1"
_SCAN = "scan-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(
    *,
    finding_id: str,
    location: Location,
    project_id: str = _PROJECT,
    source: ScannerTool = ScannerTool.TRIVY,
) -> Finding:
    return Finding(
        id=finding_id,
        project_id=project_id,
        source=source,
        rule_id=f"rule-{finding_id}",
        severity=Severity.HIGH,
        native_severity="HIGH",
        title=f"title {finding_id}",
        location=location,
        evidence=Evidence(
            id=f"ev-{finding_id}",
            finding_id=finding_id,
            scan_id=_SCAN,
            raw_payload='{"ok": true}',
            source_tool=source,
            captured_at=_AT,
        ),
    )


def _semgrep(finding_id: str, *, file_path: str, line: int) -> Finding:
    """The shape `mappers/semgrep.py` constructs: file and line fields, nothing else."""
    return _finding(
        finding_id=finding_id,
        location=Location(file_path=file_path, start_line=line, end_line=line),
        source=ScannerTool.SEMGREP,
    )


def _zap(finding_id: str, *, url: str) -> Finding:
    """The shape `mappers/zap.py` constructs: url and method, no file or package."""
    return _finding(
        finding_id=finding_id,
        location=Location(url=url, http_method="GET"),
        source=ScannerTool.ZAP,
    )


def _route_map(*spans: tuple[str, str, int, int]) -> RouteMap:
    """`(path, file_path, start_line, end_line)` tuples, as `extract_routes` would emit them."""
    return RouteMap(
        routes=tuple(
            RouteSpan(path=path, file_path=file_path, start_line=start, end_line=end)
            for path, file_path, start, end in spans
        ),
        unparsed_files=(),
        unresolved_routes=(),
        unread_tree=None,
    )


def _use_case(project_access, findings, serving, route_maps) -> CorrelateFindingsUseCase:
    return CorrelateFindingsUseCase(
        project_access=project_access, findings=findings, serving=serving, route_maps=route_maps
    )


def _source_sets(groups, source_of: dict[str, str]) -> list[set[str]]:
    return [{source_of[i] for i in group.finding_ids} for group in groups]


# ---------------------------------------------------------------------------
# Authorization — the same gate ListProjectFindingsUseCase sets, same port
# ---------------------------------------------------------------------------


async def test_a_caller_who_may_not_read_the_project_is_refused(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    with pytest.raises(ProjectAccessDenied):
        await _use_case(
            project_access, finding_repository, serving_declaration_port, route_map_port
        ).execute(project_id=_PROJECT, user_id=_USER)


async def test_correlation_authorizes_before_it_reads_anything(
    project_access, exploding_finding_repository, serving_declaration_port, route_map_port
):
    """The gate must run first, not merely run.

    `ExplodingFindingRepository` raises on every read, so this fails if the authorization
    check is ever moved below the query — a refactor that would leave the denial working
    and every other test green while sending an unauthorized caller's project id to the
    database.
    """
    with pytest.raises(ProjectAccessDenied):
        await _use_case(
            project_access, exploding_finding_repository, serving_declaration_port, route_map_port
        ).execute(project_id=_PROJECT, user_id=_USER)


async def test_a_refused_caller_never_reaches_the_declaration_or_the_route_map(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """Authorization precedes the derivation gate as well as the findings read.

    Asserted on the fakes' call logs rather than with exploding fakes, because the use case
    must also not raise anything OTHER than `ProjectAccessDenied` here.
    """
    serving_declaration_port.declare(_PROJECT)

    with pytest.raises(ProjectAccessDenied):
        await _use_case(
            project_access, finding_repository, serving_declaration_port, route_map_port
        ).execute(project_id=_PROJECT, user_id=_USER)

    assert serving_declaration_port.calls == []
    assert route_map_port.calls == []


async def test_another_project_s_findings_are_never_grouped_in(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The tenant boundary, checked at the use case as well as at the key.

    `test_match_key.py` pins that two equal packages in different projects do not match.
    This pins the other half: the read is scoped, so the other project's finding never
    reaches the matcher at all. Both are needed — a scoped read with an unscoped key would
    pass this, and an unscoped read with a scoped key would still hand another tenant's
    finding to correlation and return it as a singleton.
    """
    project_access.permit(_PROJECT, _USER)
    await finding_repository.upsert(
        _finding(finding_id="ours", location=Location(package="urllib3"))
    )
    await finding_repository.upsert(
        _finding(
            finding_id="theirs", location=Location(package="urllib3"), project_id=_OTHER_PROJECT
        )
    )

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [group.finding_ids for group in groups] == [("ours",)]


# ---------------------------------------------------------------------------
# Grouping over constructed fixtures — criterion (d), positive and negative
# ---------------------------------------------------------------------------


async def test_a_project_s_findings_group_by_shared_signal_and_only_by_it(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """Positive and negative in one shape, because the negative is the harder half.

    `f1`/`f2` share a package and must correlate. `f3` is a different package and must not
    join them, even though every other field it carries is as similar as the fixtures allow.
    `f4` carries file and line fields only — the Semgrep shape — and with no declaration in
    force it carries no signal and must come back as a singleton rather than being dropped
    or folded in with the other unlocatable findings.
    """
    project_access.permit(_PROJECT, _USER)
    for finding in (
        _finding(finding_id="f1", location=Location(package="urllib3", file_path="req.txt")),
        _finding(finding_id="f2", location=Location(package="urllib3", file_path="req.txt")),
        _finding(finding_id="f3", location=Location(package="Flask", file_path="req.txt")),
        _semgrep("f4", file_path="app.py", line=1),
    ):
        await finding_repository.upsert(finding)

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.package, group.finding_ids) for group in groups] == [
        (None, ("f4",)),
        ("Flask", ("f3",)),
        ("urllib3", ("f1", "f2")),
    ]


async def test_a_project_with_no_findings_correlates_to_no_groups(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    project_access.permit(_PROJECT, _USER)

    assert (
        await _use_case(
            project_access, finding_repository, serving_declaration_port, route_map_port
        ).execute(project_id=_PROJECT, user_id=_USER)
        == []
    )


# ---------------------------------------------------------------------------
# The derivation gate — M5.6's acceptance criterion (ADR-0028 decision 0)
# ---------------------------------------------------------------------------


async def test_the_route_map_is_not_read_while_no_declaration_is_in_force(
    project_access, finding_repository, serving_declaration_port, exploding_route_map_port
):
    """**The subject is the ORDER**: the derivation is not attempted, not attempted-and-dropped.

    `ExplodingRouteMapPort` raises on any read, so this fails if the gate is removed, if its
    verdict is ignored, or if the map is read before the verdict and its answer thrown away —
    three refactors under which every grouping assertion below could stay green. The
    declaration was checked exactly once, for this project.
    """
    project_access.permit(_PROJECT, _USER)
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=28))
    await finding_repository.upsert(_zap("dast", url="http://target.example:8080/calculate?x=1"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, exploding_route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert serving_declaration_port.calls == [_PROJECT]
    assert [(group.key.url, group.finding_ids) for group in groups] == [
        (None, ("sast",)),
        ("/calculate", ("dast",)),
    ]


async def test_a_derived_group_is_withheld_when_no_declaration_is_in_force(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The criterion itself: a route map that WOULD produce the pair, and no declaration.

    "Absent" and "out of force" are one answer at this port by design — the voiding rule is
    `declaration_in_force`'s, tested in `test_serving_declaration.py`, and the adapter that
    applies it to real rows is tested against Postgres. This is the consumer's half: whatever
    made the verdict `False`, the group is not produced and the map is not consulted.
    """
    project_access.permit(_PROJECT, _USER)
    route_map_port.set_map(_PROJECT, _route_map(("/calculate", "app.py", 14, 31)))
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=28))
    await finding_repository.upsert(_zap("dast", url="http://target.example:8080/calculate?x=1"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert sorted(group.finding_ids for group in groups) == [("dast",), ("sast",)]
    assert route_map_port.calls == []


async def test_a_derived_group_is_produced_when_the_declaration_is_in_force(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The positive half, so the withheld case above cannot pass by the derivation never working.

    A green group here means what `CorrelateFindingsUseCase.execute`'s docstring says and no
    more: the coupling was declared and not reconfigured since (G47), and the route exists in
    the map's tree with line 28 inside its span there (G52) — never that the two findings are
    about one system.
    """
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(
        _PROJECT, _route_map(("/", "app.py", 9, 11), ("/calculate", "app.py", 14, 31))
    )
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=28))
    await finding_repository.upsert(_zap("dast", url="http://target.example:8080/calculate?x=1"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.package, group.key.url, group.finding_ids) for group in groups] == [
        (None, "/calculate", ("dast", "sast")),
    ]
    assert route_map_port.calls == [_PROJECT]


async def test_a_line_served_by_two_stacked_routes_derives_nothing(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """Exactly one route, or no derived path — never a tie-break. G54's third member.

    Line 3 is in the shared body of a view carrying `@app.route("/a")` and `@app.route("/b")`,
    so it genuinely serves both. A key carries one `url`, and choosing either would assert a
    relation for one route and hide it for the other; so the finding stays a singleton, and a
    ZAP alert at either path stays out of its group. That the view's findings are therefore
    excluded from correlation is the cost G54 records.
    """
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(_PROJECT, _route_map(("/a", "app.py", 1, 4), ("/b", "app.py", 2, 4)))
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=3))
    await finding_repository.upsert(_zap("dast-a", url="http://t/a"))
    await finding_repository.upsert(_zap("dast-b", url="http://t/b"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.url, group.finding_ids) for group in groups] == [
        (None, ("sast",)),
        ("/a", ("dast-a",)),
        ("/b", ("dast-b",)),
    ]


async def test_a_line_outside_every_route_span_derives_nothing(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The miss case: a declaration in force and a map, but no route serves the line."""
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(_PROJECT, _route_map(("/calculate", "app.py", 14, 31)))
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=40))
    await finding_repository.upsert(_zap("dast", url="http://t/calculate"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.url, group.finding_ids) for group in groups] == [
        (None, ("sast",)),
        ("/calculate", ("dast",)),
    ]


async def test_a_converter_route_never_matches_a_concrete_crawled_path(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """**G54 must stay true**, and this is the correlation-level pin that it does.

    `test_route_extraction.py::test_a_converter_path_is_emitted_verbatim` pins the premise —
    the map says `/user/<int:id>`. This pins the consequence: under plain equality that key
    never meets a crawled `/user/123`, so the two stay apart. A pattern matcher slipped into
    the key, or a derivation that stripped converters, would fabricate this pair and fail
    here — the in-key fix G54's `Deferral rationale:` refuses. The derivation-side fix that
    entry leaves open would change this test deliberately, not silently.
    """
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(_PROJECT, _route_map(("/user/<int:id>", "app.py", 1, 3)))
    await finding_repository.upsert(_semgrep("sast", file_path="app.py", line=2))
    await finding_repository.upsert(_zap("dast", url="http://t/user/123"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.url, group.finding_ids) for group in groups] == [
        ("/user/123", ("dast",)),
        ("/user/<int:id>", ("sast",)),
    ]


async def test_a_finding_carrying_a_package_is_never_given_a_derived_path(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The derivation reaches only findings with no signal of their own.

    A finding with `package`, a `file_path` and a `start_line` inside a route span keeps its
    package key and gains no `url` — otherwise a Trivy-shaped finding could be pulled into a
    DAST group through a manifest path that happened to share a name with a source file.
    """
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(_PROJECT, _route_map(("/calculate", "app.py", 14, 31)))
    await finding_repository.upsert(
        _finding(
            finding_id="dep", location=Location(package="Flask", file_path="app.py", start_line=20)
        )
    )
    await finding_repository.upsert(_zap("dast", url="http://t/calculate"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.package, group.key.url, group.finding_ids) for group in groups] == [
        (None, "/calculate", ("dast",)),
        ("Flask", None, ("dep",)),
    ]


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
async def test_zap_is_keyed_on_path_whether_or_not_a_declaration_is_in_force(
    declared, project_access, finding_repository, serving_declaration_port, route_map_port
):
    """G31's first out, and it is NOT behind the gate — both parametrizations must agree.

    Two alerts at one endpoint with two query strings are one Risk: that is a property of the
    key, not of whether a SAST↔DAST comparison is founded, so it would be surprising for a
    serving declaration to change it. A re-key that only happened with a declaration in force
    fails the `undeclared` case.
    """
    project_access.permit(_PROJECT, _USER)
    if declared:
        serving_declaration_port.declare(_PROJECT)
    await finding_repository.upsert(_zap("expr-2x3", url="http://t:8080/calculate?expr=2*3"))
    await finding_repository.upsert(_zap("expr-calc", url="http://t:8080/calculate?expr=calculate"))
    await finding_repository.upsert(_zap("root", url="http://t:8080"))

    groups = await _use_case(
        project_access, finding_repository, serving_declaration_port, route_map_port
    ).execute(project_id=_PROJECT, user_id=_USER)

    assert [(group.key.url, group.finding_ids) for group in groups] == [
        ("/", ("root",)),
        ("/calculate", ("expr-2x3", "expr-calc")),
    ]


# ---------------------------------------------------------------------------
# The corpus measurement — ADR-0023's amendment section 8, and its 2026-09-15 divergence
# ---------------------------------------------------------------------------


class _FixtureFindingRepository:
    """Returns exactly the findings it was handed, filtered by project. Nothing else.

    **Deliberately not `InMemoryFindingRepository`, and the ground is stated precisely
    because the obvious version of it is not what was measured.** That fake's `upsert`
    resolves on `(project_id, dedup_hash)`, so seeding through it would make this test's
    corpus a function of the dedup rule as well as of the mappers. Measured: all 34
    findings carry distinct `dedup_hash` values today, so it would NOT in fact collapse
    any of them — this fake removes a dependency rather than fixing an observed defect.
    That is worth keeping anyway: `dedup_hash`'s inputs are not this test's subject, and a
    future change to them must not be able to alter a number this test reports as a
    property of the match key.
    """

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    async def get_by_project_id(self, project_id: str) -> list[Finding]:
        return [finding for finding in self._findings if finding.project_id == project_id]


# The demo target's routes as `extract_routes` emits them for `app.py` at `c68caa7`,
# decorator-inclusive — ADR-0029's 2026-09-10 amendment records these spans. Hand-written
# because no Flask tree is committed (ADR-0029 decision 5); the frozen-SHA exemption of
# ADR-0027 decision 5 is what lets line numbers into that repository appear here at all.
_DEMO_TARGET_ROUTES = (("/", "app.py", 9, 11), ("/calculate", "app.py", 14, 31))


def _committed_corpus(scanner_fixture, clock, id_generator) -> list[Finding]:
    findings = [
        *map_semgrep_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("semgrep_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        *map_trivy_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("trivy_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
        *map_zap_output(
            project_id=_PROJECT,
            scan_id=_SCAN,
            raw_output=scanner_fixture("zap_scan.json"),
            id_generator=id_generator,
            clock=clock,
        ),
    ]
    # Asserted BEFORE anything groups. The corpus size is a premise of every number
    # below, so a harness that quietly returned fewer findings would otherwise present
    # itself as a divergence in the key or the matcher — the one reading section 8 exists
    # to prevent.
    assert len(findings) == 34
    assert Counter(str(finding.source) for finding in findings) == {
        "trivy": 20,
        "zap": 13,
        "semgrep": 1,
    }
    # ADR-0023 Decision A's live guard: no ZAP finding carries a `package`. The `Server`
    # banner stays out of `Location`. This is the REAL mapper, which is why the guard lives
    # here — `test_correlation_accuracy.py` builds its ZAP locations by hand and cannot see it.
    assert [f.id for f in findings if f.source is ScannerTool.ZAP and f.location.package] == []
    return findings


def _assert_every_finding_in_exactly_one_group(groups, findings: list[Finding]) -> None:
    grouped_ids = [i for group in groups for i in group.finding_ids]
    assert len(grouped_ids) == len(findings)
    assert set(grouped_ids) == {finding.id for finding in findings}


async def test_the_committed_fixtures_with_no_declaration_in_force(
    scanner_fixture, project_access, serving_declaration_port, route_map_port, clock, id_generator
):
    """Section 8's prediction, re-checked under the path key and a closed gate.

    ADR-0023's 2026-08-26 amendment section 8 predicted, before any matching code existed:
    7 groups — Trivy 3 (`urllib3` 12, `Werkzeug` 6, `Flask` 2) and ZAP 4 keyed on the FULL
    URLs — with 33 of 34 findings in them, one no-signal singleton from Semgrep, and no group
    spanning two tools. **With no declaration in force, four of those five clauses still
    hold and one is falsified by decision**: the ZAP key values are now paths (G31's first
    out, ADR-0029 decision 4). The count stays 7 because the passive plan yields one query
    string per route, so path-keying merges nothing. ADR-0023's 2026-09-15 amendment records
    this as a dated record rather than striking a measurement that was right when taken.

    **This is also production's state between M5.6 commits 3 and 4**, whatever a project has
    declared, because the production route map is empty.

    Tool-disjointness is asserted from the findings' own `source` values, never inferred from
    the key shape — reading it off the key would restate the field list.
    """
    project_access.permit(_PROJECT, _USER)
    findings = _committed_corpus(scanner_fixture, clock, id_generator)

    groups = await CorrelateFindingsUseCase(
        project_access=project_access,
        findings=_FixtureFindingRepository(findings),
        serving=serving_declaration_port,
        route_maps=route_map_port,
    ).execute(project_id=_PROJECT, user_id=_USER)

    source_of = {finding.id: str(finding.source) for finding in findings}
    signal_groups = [group for group in groups if group.key.has_signal]
    no_signal_groups = [group for group in groups if not group.key.has_signal]

    assert len(signal_groups) == 7
    assert sum(len(group.finding_ids) for group in signal_groups) == 33
    assert [
        (group.key.package, group.key.url, len(group.finding_ids)) for group in signal_groups
    ] == [
        (None, "/", 5),
        (None, "/calculate", 4),
        (None, "/robots.txt", 2),
        (None, "/sitemap.xml", 2),
        ("Flask", None, 2),
        ("Werkzeug", None, 6),
        ("urllib3", None, 12),
    ]

    # One singleton, and it is Semgrep's: with the gate closed, nothing gives it a signal.
    assert [len(group.finding_ids) for group in no_signal_groups] == [1]
    assert {source_of[i] for group in no_signal_groups for i in group.finding_ids} == {"semgrep"}

    _assert_every_finding_in_exactly_one_group(groups, findings)
    assert [sources for sources in _source_sets(groups, source_of) if len(sources) > 1] == []
    assert route_map_port.calls == []


async def test_the_committed_fixtures_with_the_declaration_in_force(
    scanner_fixture, project_access, serving_declaration_port, route_map_port, clock, id_generator
):
    """The first cross-tool group this project has produced, and exactly one.

    **Replaces the assertion this file carried until M5.6 commit 3 — "no group spans two
    tools" — and says precisely what may now span two:** only `{semgrep, zap}`, only by a
    derived route path, only with a declaration in force, and only the one group the demo
    target's routes admit. Trivy still co-groups with nothing, since a finding carrying a
    `package` is never given a derived path.

    Against section 8: **7 groups still, by a different route** — the Semgrep singleton
    joins `/calculate` while nothing merges, which is not the reason section 8 gave for 7;
    **34 of 34** in groups rather than 33; **zero** no-signal singletons rather than one; and
    **one** group spanning two tools rather than none.
    """
    project_access.permit(_PROJECT, _USER)
    serving_declaration_port.declare(_PROJECT)
    route_map_port.set_map(_PROJECT, _route_map(*_DEMO_TARGET_ROUTES))
    findings = _committed_corpus(scanner_fixture, clock, id_generator)

    groups = await CorrelateFindingsUseCase(
        project_access=project_access,
        findings=_FixtureFindingRepository(findings),
        serving=serving_declaration_port,
        route_maps=route_map_port,
    ).execute(project_id=_PROJECT, user_id=_USER)

    source_of = {finding.id: str(finding.source) for finding in findings}
    signal_groups = [group for group in groups if group.key.has_signal]

    assert len(signal_groups) == 7
    assert sum(len(group.finding_ids) for group in signal_groups) == 34
    assert [
        (group.key.package, group.key.url, len(group.finding_ids)) for group in signal_groups
    ] == [
        (None, "/", 5),
        (None, "/calculate", 5),
        (None, "/robots.txt", 2),
        (None, "/sitemap.xml", 2),
        ("Flask", None, 2),
        ("Werkzeug", None, 6),
        ("urllib3", None, 12),
    ]
    assert [group for group in groups if not group.key.has_signal] == []
    _assert_every_finding_in_exactly_one_group(groups, findings)

    cross_tool = [
        (group.key.project_id, group.key.package, group.key.url, sources, len(group.finding_ids))
        for group, sources in zip(groups, _source_sets(groups, source_of), strict=True)
        if len(sources) > 1
    ]
    assert cross_tool == [(_PROJECT, None, "/calculate", {"semgrep", "zap"}, 5)]
    assert [sources for sources in _source_sets(groups, source_of) if "trivy" in sources] == [
        {"trivy"},
        {"trivy"},
        {"trivy"},
    ]
