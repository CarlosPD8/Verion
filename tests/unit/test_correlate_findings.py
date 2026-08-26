"""`CorrelateFindingsUseCase` against fakes, and the ADR-0023 prediction against the corpus.

Two things here are not ordinary coverage:

- the **gate-placement** test, which proves authorization runs before any read rather than
  merely that a denial happens (ADR-0013's idiom, as `test_list_project_findings.py` uses it);
- the **corpus measurement**, which runs the three committed fixtures through the real
  mappers and this module's own key, matcher and use case, and checks the falsifiable
  prediction ADR-0023's 2026-08-26 amendment section 8 wrote down before any matcher
  existed.
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


def _use_case(project_access, findings) -> CorrelateFindingsUseCase:
    return CorrelateFindingsUseCase(project_access=project_access, findings=findings)


# ---------------------------------------------------------------------------
# Authorization — the same gate ListProjectFindingsUseCase sets, same port
# ---------------------------------------------------------------------------


async def test_a_caller_who_may_not_read_the_project_is_refused(project_access, finding_repository):
    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, finding_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )


async def test_correlation_authorizes_before_it_reads_anything(
    project_access, exploding_finding_repository
):
    """The gate must run first, not merely run.

    `ExplodingFindingRepository` raises on every read, so this fails if the authorization
    check is ever moved below the query — a refactor that would leave the denial working
    and every other test green while sending an unauthorized caller's project id to the
    database.
    """
    with pytest.raises(ProjectAccessDenied):
        await _use_case(project_access, exploding_finding_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )


async def test_another_project_s_findings_are_never_grouped_in(project_access, finding_repository):
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

    groups = await _use_case(project_access, finding_repository).execute(
        project_id=_PROJECT, user_id=_USER
    )

    assert [group.finding_ids for group in groups] == [("ours",)]


# ---------------------------------------------------------------------------
# Grouping over constructed fixtures — criterion (d), positive and negative
# ---------------------------------------------------------------------------


async def test_a_project_s_findings_group_by_shared_signal_and_only_by_it(
    project_access, finding_repository
):
    """Positive and negative in one shape, because the negative is the harder half.

    `f1`/`f2` share a package and must correlate. `f3` is a different package and must not
    join them, even though every other field it carries is as similar as the fixtures allow.
    `f4` carries file and line fields only — the Semgrep shape, and none of them is in the
    key — so it carries no signal and must come back as a singleton rather than being
    dropped or folded in with the other unlocatable findings.
    """
    project_access.permit(_PROJECT, _USER)
    for finding in (
        _finding(finding_id="f1", location=Location(package="urllib3", file_path="req.txt")),
        _finding(finding_id="f2", location=Location(package="urllib3", file_path="req.txt")),
        _finding(finding_id="f3", location=Location(package="Flask", file_path="req.txt")),
        _finding(
            finding_id="f4",
            location=Location(file_path="app.py", start_line=1),
            source=ScannerTool.SEMGREP,
        ),
    ):
        await finding_repository.upsert(finding)

    groups = await _use_case(project_access, finding_repository).execute(
        project_id=_PROJECT, user_id=_USER
    )

    assert [(group.key.package, group.finding_ids) for group in groups] == [
        (None, ("f4",)),
        ("Flask", ("f3",)),
        ("urllib3", ("f1", "f2")),
    ]


async def test_a_project_with_no_findings_correlates_to_no_groups(
    project_access, finding_repository
):
    project_access.permit(_PROJECT, _USER)

    assert (
        await _use_case(project_access, finding_repository).execute(
            project_id=_PROJECT, user_id=_USER
        )
        == []
    )


# ---------------------------------------------------------------------------
# The corpus measurement — ADR-0023's amendment, section 8
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


async def test_the_committed_fixtures_group_as_adr_0023_predicted(
    scanner_fixture, project_access, clock, id_generator
):
    """The falsifiable prediction, checked rather than confirmed.

    ADR-0023's 2026-08-26 amendment section 8 predicted, before any matching code existed,
    that this key yields 7 groups over the committed fixtures — Trivy 3 (`urllib3` 12,
    `Werkzeug` 6, `Flask` 2) and ZAP 4 keyed on the full URLs — with 33 of 34 findings in
    those groups, one no-signal singleton from Semgrep, and no group spanning two tools.

    Run through the REAL mappers and this module's own key, matcher and use case, so what
    is measured is the whole path rather than a restatement of the prediction. Every number
    below reproduced on the first run.

    **`no group spanning two tools` is asserted from the findings' own `source` values**,
    not inferred from the key shape. Inferring it would make the assertion circular: the
    key cannot carry a `source`, so reading tool-disjointness off the key would be
    restating the field list rather than measuring the corpus. What actually prevents a
    cross-tool match is the MAPPERS — `mappers/trivy.py` constructs `package` and never
    `url`, `mappers/zap.py` the reverse — and this is the check that they still do.

    Not container-bound: three JSON files, three pure mapper functions and an in-process
    fake, so it costs no measurable time against the CI budget CLAUDE.md tracks.
    """
    project_access.permit(_PROJECT, _USER)
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

    groups = await CorrelateFindingsUseCase(
        project_access=project_access, findings=_FixtureFindingRepository(findings)
    ).execute(project_id=_PROJECT, user_id=_USER)

    source_of = {finding.id: str(finding.source) for finding in findings}
    signal_groups = [group for group in groups if group.key.has_signal]
    no_signal_groups = [group for group in groups if not group.key.has_signal]

    assert len(signal_groups) == 7
    assert sum(len(group.finding_ids) for group in signal_groups) == 33

    assert [
        (group.key.package, group.key.url, len(group.finding_ids)) for group in signal_groups
    ] == [
        (None, "http://target.example:8080/", 5),
        (None, "http://target.example:8080/calculate?expr=2*3", 4),
        (None, "http://target.example:8080/robots.txt", 2),
        (None, "http://target.example:8080/sitemap.xml", 2),
        ("Flask", None, 2),
        ("Werkzeug", None, 6),
        ("urllib3", None, 12),
    ]

    # One singleton, and it is Semgrep's — the cost of the key carrying no file or line
    # field. `mappers/semgrep.py` populates `file_path`, `start_line` and `end_line`, and
    # the key carries none of the three. M5.6 is the named exit.
    assert [len(group.finding_ids) for group in no_signal_groups] == [1]
    assert {source_of[i] for group in no_signal_groups for i in group.finding_ids} == {"semgrep"}

    # Every finding is in exactly one group: nothing dropped, nothing duplicated.
    grouped_ids = [i for group in groups for i in group.finding_ids]
    assert len(grouped_ids) == 34
    assert set(grouped_ids) == {finding.id for finding in findings}

    assert [group for group in groups if len({source_of[i] for i in group.finding_ids}) > 1] == []
