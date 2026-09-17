"""`GenerateSecurityBriefUseCase`: port, then narration, then write. ADR-0033.

**The write order is pinned HERE, not in the route tests.** The request's session rolls back
on any exception, so a route test cannot see an `add` that happened before a provider failure
and was then undone. A recording repository can.

The provider is the contract-tested fake from `tests/conftest.py` (G65).
"""

import pytest

from verion.modules.brief.adapters.outbound.explanation.prompt import PROMPT_VERSION
from verion.modules.brief.application.generate_security_brief import (
    GenerateSecurityBriefUseCase,
)
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
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


def _risk() -> ExplainableRisk:
    surface = score_surface(
        project_id=PROJECT,
        package=None,
        url="/calculate",
        members=[
            SurfaceMember(finding_id="f-3", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
            SurfaceMember(finding_id="f-5", source=ScannerTool.ZAP, severity=Severity.LOW),
        ],
    )
    return ExplainableRisk(finding_ids=surface.finding_ids, decision=explainable_decision(surface))


class _FakeExplainableRisks:
    def __init__(self, risk):
        self._risk = risk
        self.calls = []

    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        self.calls.append((project_id, user_id, finding_ids))
        return self._risk


class _DenyingExplainableRisks:
    async def explainable_risk(self, *, project_id, user_id, finding_ids):
        raise ExplainableRiskAccessDenied(f"No readable project with id '{project_id}'")


class _RecordingBriefs:
    def __init__(self):
        self.added = []

    async def add(self, brief):
        self.added.append(brief)


def _use_case(explainable_risks, provider, briefs, clock, id_generator):
    return GenerateSecurityBriefUseCase(
        explainable_risks=explainable_risks,
        explanations=provider,
        briefs=briefs,
        clock=clock,
        ids=id_generator,
    )


async def test_the_brief_holds_the_decision_its_narration_and_the_engines_members(
    explanation_provider_factory, clock, id_generator
):
    risk = _risk()
    port = _FakeExplainableRisks(risk)
    provider = explanation_provider_factory()
    briefs = _RecordingBriefs()

    brief = await _use_case(port, provider, briefs, clock, id_generator).execute(
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
        generated_at=clock.now(),
    )
    assert briefs.added == [brief]
    # The request's set reaches the port as sent; what is STORED is the engine's.
    assert port.calls == [(PROJECT, USER, ("f-5", "f-3"))]


async def test_the_provider_is_given_exactly_the_ports_decision(
    explanation_provider_factory, clock, id_generator
):
    risk = _risk()
    provider = explanation_provider_factory()

    await _use_case(
        _FakeExplainableRisks(risk), provider, _RecordingBriefs(), clock, id_generator
    ).execute(project_id=PROJECT, user_id=USER, finding_ids=risk.finding_ids)

    assert provider.calls == [risk.decision]
    assert provider.calls[0] is risk.decision


async def test_a_provider_failure_writes_nothing(explanation_provider_factory, clock, id_generator):
    """Mutation: `add` before `explain`. Only this test sees it (see the module docstring)."""
    briefs = _RecordingBriefs()

    with pytest.raises(ExplanationUnavailable):
        await _use_case(
            _FakeExplainableRisks(_risk()),
            explanation_provider_factory(fail=True),
            briefs,
            clock,
            id_generator,
        ).execute(project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5"))

    assert briefs.added == []


async def test_a_denial_calls_no_provider_and_writes_nothing(
    explanation_provider_factory, clock, id_generator
):
    provider = explanation_provider_factory()
    briefs = _RecordingBriefs()

    with pytest.raises(ExplainableRiskAccessDenied):
        await _use_case(_DenyingExplainableRisks(), provider, briefs, clock, id_generator).execute(
            project_id=PROJECT, user_id=USER, finding_ids=("f-3", "f-5")
        )

    assert provider.calls == []
    assert briefs.added == []
