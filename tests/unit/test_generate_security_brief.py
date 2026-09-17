"""`GenerateSecurityBriefUseCase`: port, member reads, describe, explain, write. ADR-0033, ADR-0034.

**The order and the atomicity are pinned HERE, not in the route tests.** The request's session
rolls back on any exception, so a route test cannot see an `add` that happened before a
provider failure and was then undone. A recording repository can.

**Two kinds of provider are used, and they prove different things.** The contract-tested fake
from `tests/conftest.py` (G65) stands in where the question is plumbing. `_ScriptedProvider`
returns chosen output, so M6's validation is tested against adversarial TEXT. **Neither proves a
prompt is safe**: a provider that obeys no instructions cannot show an injection failing. Those
tests read the rendered prompt (`test_describe_prompt.py`), and so does this file's M7 test.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (
    DESCRIBE_PROMPT_VERSION,
    build_describe_messages,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import PROMPT_VERSION
from verion.modules.brief.application.generate_security_brief import (
    MAX_WHAT_HAPPENED_CHARS,
    GenerateSecurityBriefUseCase,
)
from verion.modules.brief.domain.brief_member import MAX_MEMBERS, MAX_TITLE_CHARS, BriefMember
from verion.modules.brief.domain.exceptions import (
    BriefMemberMissing,
    ExplanationUnavailable,
    WhatHappenedRejected,
)
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.normalization.domain.finding import Evidence, Finding, Location
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output
from verion.modules.normalization.domain.mappers.zap import map_zap_output
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRisk,
    ExplainableRiskAccessDenied,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

PROJECT = "proj-1"
USER = "user-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)
_ACTIVE_ZAP = Path(__file__).parents[1] / "integration/fixtures/active_scan/zap_active_scan.json"


def _finding(finding_id: str, source: ScannerTool, title: str, location: Location) -> Finding:
    return Finding(
        id=finding_id,
        project_id=PROJECT,
        source=source,
        rule_id=f"rule-{finding_id}",
        severity=Severity.HIGH,
        native_severity="HIGH",
        title=title,
        location=location,
        evidence=Evidence(
            id=f"ev-{finding_id}",
            finding_id=finding_id,
            scan_id="scan-1",
            raw_payload='{"payload": "PAYLOAD-SENTINEL"}',
            source_tool=source,
            captured_at=_AT,
        ),
    )


_SEMGREP = _finding(
    "f-3", ScannerTool.SEMGREP, "dangerous-eval", Location(file_path="app.py", start_line=28)
)
_ZAP = _finding(
    "f-5",
    ScannerTool.ZAP,
    "Server Side Template Injection (Blind)",
    Location(url="http://target.example:8080/calculate?expr=2*3", parameter="expr"),
)


def _risk(*finding_ids: str) -> ExplainableRisk:
    surface = score_surface(
        project_id=PROJECT,
        package=None,
        url="/calculate",
        members=[
            SurfaceMember(finding_id="f-3", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
            SurfaceMember(finding_id="f-5", source=ScannerTool.ZAP, severity=Severity.LOW),
        ],
    )
    ids = finding_ids or surface.finding_ids
    return ExplainableRisk(finding_ids=tuple(ids), decision=explainable_decision(surface))


class _FakeExplainableRisks:
    def __init__(self, risk, events=None):
        self._risk = risk
        self._events = events
        self.calls = []

    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        self.calls.append((project_id, user_id, finding_ids))
        if self._events is not None:
            self._events.append("port")
        return self._risk


class _DenyingExplainableRisks:
    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        raise ExplainableRiskAccessDenied(f"No readable project with id '{project_id}'")


class _ExplodingFindings:
    async def get_by_id(self, *, project_id, finding_id):
        raise AssertionError("a finding was read before the port's verdict")


class _CountingFindings:
    """Wraps the in-memory repository and records every `get_by_id`, and when it happened."""

    def __init__(self, inner, events=None):
        self._inner = inner
        self._events = events
        self.reads = []

    async def get_by_id(self, *, project_id, finding_id):
        self.reads.append((project_id, finding_id))
        if self._events is not None:
            self._events.append("read")
        return await self._inner.get_by_id(project_id=project_id, finding_id=finding_id)


class _ScriptedProvider:
    """Returns chosen text. Records calls, and the order they happened in when given `events`."""

    def __init__(self, *, describe_text="Two findings.", fail=None, events=None):
        self._describe_text = describe_text
        self._fail = fail
        self._events = events if events is not None else []
        self.describe_calls = []
        self.explain_calls = []

    async def describe(self, *, members, member_count):
        self._events.append("describe")
        self.describe_calls.append((members, member_count))
        if self._fail == "describe":
            raise ExplanationUnavailable("scripted describe failure")
        return Explanation(
            text=self._describe_text, model="m", prompt_version=DESCRIBE_PROMPT_VERSION
        )

    async def explain(self, *, decision):
        self._events.append("explain")
        self.explain_calls.append(decision)
        if self._fail == "explain":
            raise ExplanationUnavailable("scripted explain failure")
        return Explanation(text="Why.", model="m", prompt_version=PROMPT_VERSION)


class _RecordingBriefs:
    def __init__(self, events=None):
        self._events = events
        self.added = []

    async def add(self, brief):
        if self._events is not None:
            self._events.append("add")
        self.added.append(brief)


async def _seeded(finding_repository, *findings):
    for finding in findings:
        await finding_repository.upsert(finding)
    return finding_repository


def _use_case(explainable_risks, findings, provider, briefs, clock, id_generator):
    return GenerateSecurityBriefUseCase(
        explainable_risks=explainable_risks,
        findings=findings,
        explanations=provider,
        briefs=briefs,
        clock=clock,
        ids=id_generator,
    )


# --- what is stored ------------------------------------------------------------------------


async def test_the_brief_holds_the_decision_both_narrations_and_the_engines_members(
    explanation_provider_factory, finding_repository, clock, id_generator
):
    risk = _risk()
    port = _FakeExplainableRisks(risk)
    provider = explanation_provider_factory()
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    brief = await _use_case(port, findings, provider, briefs, clock, id_generator).execute(
        project_id=PROJECT, user_id=USER, finding_ids=("f-5", "f-3")
    )

    assert brief == SecurityBrief(
        id="fake-id-1",
        project_id=PROJECT,
        finding_ids=("f-3", "f-5"),
        decision=risk.decision,
        explanation=Explanation(
            text="fix_now at 6: severity 4 + exposure 1 + corroboration 1.",
            model="fake",
            prompt_version=PROMPT_VERSION,
        ),
        what_happened=Explanation(
            text="2 findings: semgrep dangerous-eval; zap Server Side Template Injection (Blind)",
            model="fake",
            prompt_version=DESCRIBE_PROMPT_VERSION,
        ),
        generated_at=clock.now(),
    )
    # Generation never writes a Brief without its second narration.
    assert brief.what_happened is not None
    assert briefs.added == [brief]
    assert port.calls == [(PROJECT, USER, ("f-5", "f-3"))]


async def test_each_call_is_given_only_its_own_input(
    explanation_provider_factory, finding_repository, clock, id_generator
):
    """`explain` gets the port's decision, and `describe` the members read from the ENGINE's ids."""
    risk = _risk()
    provider = explanation_provider_factory()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    await _use_case(
        _FakeExplainableRisks(risk), findings, provider, _RecordingBriefs(), clock, id_generator
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=risk.finding_ids)

    assert provider.calls == [risk.decision]
    assert provider.calls[0] is risk.decision
    [(members, member_count)] = provider.describe_calls
    assert member_count == 2
    assert members == (
        BriefMember.from_scalars(
            finding_id="f-3",
            source=ScannerTool.SEMGREP,
            title="dangerous-eval",
            file_path="app.py",
            start_line=28,
            end_line=None,
            package=None,
            installed_version=None,
            url=None,
            http_method=None,
            parameter=None,
        ),
        BriefMember.from_scalars(
            finding_id="f-5",
            source=ScannerTool.ZAP,
            title="Server Side Template Injection (Blind)",
            file_path=None,
            start_line=None,
            end_line=None,
            package=None,
            installed_version=None,
            url="http://target.example:8080/calculate?expr=2*3",
            http_method=None,
            parameter="expr",
        ),
    )


# --- order and atomicity -------------------------------------------------------------------


async def test_the_order_is_port_reads_describe_explain_then_the_write(
    finding_repository, clock, id_generator
):
    events = []
    findings = _CountingFindings(await _seeded(finding_repository, _SEMGREP, _ZAP), events)

    await _use_case(
        _FakeExplainableRisks(_risk(), events),
        findings,
        _ScriptedProvider(events=events),
        _RecordingBriefs(events),
        clock,
        id_generator,
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert events == ["port", "read", "read", "describe", "explain", "add"]


async def test_a_describe_failure_never_calls_explain_and_writes_nothing(
    finding_repository, clock, id_generator
):
    provider = _ScriptedProvider(fail="describe")
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    with pytest.raises(ExplanationUnavailable):
        await _use_case(
            _FakeExplainableRisks(_risk()), findings, provider, briefs, clock, id_generator
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert provider.explain_calls == []
    assert briefs.added == []


async def test_an_explain_failure_after_describe_writes_nothing(
    finding_repository, clock, id_generator
):
    """Mutation: `add` before the second call. One call was billed; no row may exist."""
    provider = _ScriptedProvider(fail="explain")
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    with pytest.raises(ExplanationUnavailable):
        await _use_case(
            _FakeExplainableRisks(_risk()), findings, provider, briefs, clock, id_generator
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert len(provider.describe_calls) == 1
    assert briefs.added == []


async def test_a_denial_reads_no_finding_calls_no_provider_and_writes_nothing(clock, id_generator):
    """Mutation: member reads before the port. The exploding repository then raises first."""
    provider = _ScriptedProvider()
    briefs = _RecordingBriefs()

    with pytest.raises(ExplainableRiskAccessDenied):
        await _use_case(
            _DenyingExplainableRisks(), _ExplodingFindings(), provider, briefs, clock, id_generator
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert provider.describe_calls == provider.explain_calls == []
    assert briefs.added == []


async def test_a_member_that_cannot_be_read_back_raises_before_any_provider_call(
    finding_repository, clock, id_generator
):
    provider = _ScriptedProvider()
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP)  # f-5 is never stored

    with pytest.raises(BriefMemberMissing):
        await _use_case(
            _FakeExplainableRisks(_risk()), findings, provider, briefs, clock, id_generator
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert provider.describe_calls == provider.explain_calls == []
    assert briefs.added == []


# --- M3: the member cap is applied where members are read ----------------------------------


async def test_a_surface_over_the_cap_reads_and_describes_twenty_of_its_full_size(
    finding_repository, clock, id_generator
):
    """A bound on READS, so the repository fake's recorded calls are the evidence (ADR-0034
    decision 5's one exception to reading the rendered prompt)."""
    ids = tuple(f"f-{n:02d}" for n in range(MAX_MEMBERS + 1))
    await _seeded(
        finding_repository,
        *(_finding(i, ScannerTool.TRIVY, f"CVE-{i}", Location(package=f"pkg-{i}")) for i in ids),
    )
    findings = _CountingFindings(finding_repository)
    provider = _ScriptedProvider()

    await _use_case(
        _FakeExplainableRisks(_risk(*ids)),
        findings,
        provider,
        _RecordingBriefs(),
        clock,
        id_generator,
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=ids)

    assert findings.reads == [(PROJECT, i) for i in ids[:MAX_MEMBERS]]
    [(members, member_count)] = provider.describe_calls
    assert [m.finding_id for m in members] == list(ids[:MAX_MEMBERS])
    assert member_count == MAX_MEMBERS + 1


# --- M6: output validation, against scripted adversarial output ----------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"Two findings.{chr(0x202E)}",
        f"Two findings.{chr(0x200B)}",
        "x" * (MAX_WHAT_HAPPENED_CHARS + 1),
        "This surface is fix_now.",
        "You should Fix Now.",
    ],
    ids=["bidi", "zero-width", "over-length", "fix_now-added", "fix-now-added-any-case"],
)
async def test_describe_output_failing_validation_is_rejected_and_nothing_follows(
    finding_repository, clock, id_generator, text
):
    provider = _ScriptedProvider(describe_text=text)
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    with pytest.raises(WhatHappenedRejected) as rejected:
        await _use_case(
            _FakeExplainableRisks(_risk()), findings, provider, briefs, clock, id_generator
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert isinstance(rejected.value, ExplanationUnavailable)
    assert text not in str(rejected.value)
    assert provider.explain_calls == []
    assert briefs.added == []


async def test_a_member_supplied_fix_now_echoed_by_the_model_still_generates(
    finding_repository, clock, id_generator
):
    """**The denial-of-service guard.** A scanned repository naming a package or a file
    `fix_now` must not make its surface's Brief ungeneratable (ADR-0034 decision 5, M6)."""
    semgrep = map_semgrep_output(
        project_id=PROJECT,
        scan_id="scan-1",
        raw_output=json.dumps(
            {
                "results": [
                    {
                        "check_id": "rules.eval",
                        "path": "src/fix_now.py",
                        "start": {"line": 3},
                        "end": {"line": 3},
                        "extra": {"severity": "WARNING", "message": "m", "metadata": {}},
                    }
                ]
            }
        ),
        id_generator=id_generator,
        clock=clock,
    )[0]
    trivy = _finding("f-t", ScannerTool.TRIVY, "CVE-2024-0001", Location(package="fix_now"))
    await _seeded(finding_repository, semgrep, trivy)
    ids = tuple(sorted((semgrep.id, trivy.id)))
    provider = _ScriptedProvider(
        describe_text="Semgrep flagged src/fix_now.py at line 3; Trivy flagged fix_now."
    )
    briefs = _RecordingBriefs()

    brief = await _use_case(
        _FakeExplainableRisks(_risk(*ids)),
        finding_repository,
        provider,
        briefs,
        clock,
        id_generator,
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=ids)

    assert briefs.added == [brief]
    assert brief.what_happened is not None


@pytest.mark.parametrize("word", ["priority", "plan", "monitor"])
async def test_ordinary_english_bucket_words_are_not_rejected(
    finding_repository, clock, id_generator, word
):
    """The known gap, pinned so it is a choice: the model's own phrasing is not a rejection."""
    provider = _ScriptedProvider(describe_text=f"A high-{word} dependency was reported.")
    briefs = _RecordingBriefs()
    findings = await _seeded(finding_repository, _SEMGREP, _ZAP)

    await _use_case(
        _FakeExplainableRisks(_risk()), findings, provider, briefs, clock, id_generator
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert len(briefs.added) == 1


async def test_a_token_cut_by_truncation_is_not_member_supplied(
    finding_repository, clock, id_generator
):
    """The model saw the TRUNCATED title, so a `fix_now` past the cap is one it cannot echo."""
    title = "t" * (MAX_TITLE_CHARS - 5) + "fix_now"
    await _seeded(
        finding_repository, _finding("f-c", ScannerTool.TRIVY, title, Location(package="pkg"))
    )
    provider = _ScriptedProvider(describe_text="It says fix_now.")

    with pytest.raises(WhatHappenedRejected):
        await _use_case(
            _FakeExplainableRisks(_risk("f-c")),
            finding_repository,
            provider,
            _RecordingBriefs(),
            clock,
            id_generator,
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-c",))


# --- M7: the payload never reaches the prompt, over a real fixture -------------------------


async def test_no_raw_payload_byte_reaches_the_describe_prompt(
    finding_repository, clock, id_generator
):
    """The committed active ZAP capture, through the real mapper and the real fill site.

    Alert `6-5`'s payload carries HTML `<p>` markup and a 3,791-character `solution`. The
    prompt is rendered from the members the use case actually handed the provider.
    """
    finding = next(
        f
        for f in map_zap_output(
            project_id=PROJECT,
            scan_id="scan-1",
            raw_output=_ACTIVE_ZAP.read_text(encoding="utf-8"),
            id_generator=id_generator,
            clock=clock,
        )
        if f.rule_id == "6-5"
    )
    solution = json.loads(finding.evidence.raw_payload)["solution"]
    assert "<p>" in finding.evidence.raw_payload and len(solution) > 3_000
    await _seeded(finding_repository, finding)
    provider = _ScriptedProvider()

    await _use_case(
        _FakeExplainableRisks(_risk(finding.id)),
        finding_repository,
        provider,
        _RecordingBriefs(),
        clock,
        id_generator,
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=(finding.id,))

    [(members, member_count)] = provider.describe_calls
    rendered = "".join(
        m["content"] for m in build_describe_messages(members, member_count=member_count)
    )
    assert "<p>" not in rendered
    # Every consecutive 40-character slice, at every offset, the last one included.
    for start in range(len(solution) - 39):
        assert solution[start : start + 40] not in rendered
    assert "PAYLOAD-SENTINEL" not in rendered
