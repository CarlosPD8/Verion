"""`ScoredExplainableRisks`: selecting one current Risk by its exact member set. ADR-0033.

The real `ComputeRiskUseCase` runs over two per-file fakes. Groups are built by correlation's
real `group_by_match_key` over hand-written `MatchKey`s, and a finding is a scalar stand-in
carrying only the three attributes scoring reads (`id`, `source`, `severity`). **No `Finding`
is hand-written**, so G40's count is unchanged.

Two surfaces with no key signal are built here on purpose. The committed corpus holds exactly
one such finding (G36), so the collision that rules out keying a Brief on the match key
(ADR-0033 decision 1) cannot be shown from captures.

Helpers are module-local; `tests/` is not a package.
"""

import dataclasses
from types import SimpleNamespace

import pytest

from verion.modules.correlation.domain.match_key import MatchKey, MatchKeyResult
from verion.modules.correlation.domain.matching import group_by_match_key
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.application.explainable_risk_provider import (
    ScoredExplainableRisks,
)
from verion.modules.risk_engine.domain.scoring import ScoredSurface
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRisk,
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

PROJECT = "proj-1"
USER = "user-1"

_FINDINGS = {
    "f-2": (ScannerTool.SEMGREP, Severity.HIGH),
    "f-7": (ScannerTool.SEMGREP, Severity.HIGH),
    "f-3": (ScannerTool.SEMGREP, Severity.HIGH),
    "f-5": (ScannerTool.ZAP, Severity.LOW),
    "f-1": (ScannerTool.TRIVY, Severity.MEDIUM),
    "f-9": (ScannerTool.TRIVY, Severity.HIGH),
}


def _key(*, package=None, url=None, confidence=None):
    """The builder's result, hand-built. `confidence` defaults to what the real builder
    would have produced for this shape, so a scenario only names it when that is the point."""
    key = MatchKey(project_id=PROJECT, package=package, url=url)
    if confidence is None:
        confidence = Confidence.REPORTED if key.has_signal else Confidence.UNGROUPED
    return MatchKeyResult(key=key, confidence=confidence)


_GROUPS = group_by_match_key(
    [
        ("f-2", _key()),
        ("f-7", _key()),
        ("f-3", _key(url="/calculate")),
        ("f-5", _key(url="/calculate")),
        ("f-9", _key(package="urllib3")),
        ("f-1", _key(package="urllib3")),
    ]
)


class _FakeCandidateRisks:
    def __init__(self, groups):
        self._groups = groups

    async def candidate_risks(self, *, project_id, user_id):
        return self._groups


class _DenyingCandidateRisks:
    async def candidate_risks(self, *, project_id, user_id):
        raise CandidateRiskAccessDenied(f"No readable project with id '{project_id}'")


class _Findings:
    """`FindingRepositoryPort.get_by_project_id` over scalar stand-ins."""

    async def get_by_project_id(self, project_id):
        return [
            SimpleNamespace(id=finding_id, source=source, severity=severity)
            for finding_id, (source, severity) in _FINDINGS.items()
        ]


def _provider(candidate_risks=None):
    compute = ComputeRiskUseCase(
        candidate_risks=candidate_risks or _FakeCandidateRisks(_GROUPS), findings=_Findings()
    )
    return ScoredExplainableRisks(compute)


async def _surfaces():
    compute = ComputeRiskUseCase(candidate_risks=_FakeCandidateRisks(_GROUPS), findings=_Findings())
    return await compute.execute(project_id=PROJECT, user_id=USER)


async def _select(finding_ids, provider=None):
    return await (provider or _provider()).explainable_risk(
        project_id=PROJECT, user_id=USER, finding_ids=finding_ids
    )


async def test_an_exact_set_returns_that_surfaces_decision_and_its_own_finding_ids():
    surface = next(s for s in await _surfaces() if s.url == "/calculate")

    risk = await _select(("f-3", "f-5"))

    assert risk == ExplainableRisk(
        finding_ids=surface.finding_ids,
        decision=explainable_decision(surface),
        confidence=surface.confidence,
    )
    assert risk.decision.priority == "fix_now"


async def test_the_request_order_does_not_matter_and_the_surface_order_is_returned():
    risk = await _select(("f-5", "f-3"))

    assert risk.finding_ids == ("f-3", "f-5")


@pytest.mark.parametrize(
    "finding_ids",
    [("f-3",), ("f-3", "f-5", "f-1"), ("f-404",), ("f-3", "f-3", "f-5")],
    ids=["subset", "superset", "unknown", "repeated-id"],
)
async def test_a_set_that_is_not_exactly_a_current_surface_fails_closed(finding_ids):
    """ADR-0033 decision 1: a changed membership refuses, never narrates the nearest surface."""
    with pytest.raises(NoCurrentRisk):
        await _select(finding_ids)


async def test_two_no_signal_surfaces_with_equal_keys_each_resolve_to_their_own_decision():
    """The collision that rules out the match key as a Brief's reference, made concrete."""
    no_signal = [s for s in await _surfaces() if s.package is None and s.url is None]
    assert len(no_signal) == 2

    first = await _select(("f-2",))
    second = await _select(("f-7",))

    assert first.finding_ids == ("f-2",)
    assert second.finding_ids == ("f-7",)
    assert first.decision.severity.produced_by == ("f-2",)
    assert second.decision.severity.produced_by == ("f-7",)


async def test_a_denial_arrives_as_the_ports_own_type_and_not_correlations():
    with pytest.raises(ExplainableRiskAccessDenied) as raised:
        await _select(("f-3", "f-5"), provider=_provider(_DenyingCandidateRisks()))

    assert not isinstance(raised.value, CandidateRiskAccessDenied)


async def test_disagreeing_reads_arrive_as_the_ports_inconsistency_type():
    ghost = [*_GROUPS, *group_by_match_key([("f-ghost", _key(package="ghost"))])]

    with pytest.raises(ExplainableRiskInconsistent):
        await _select(("f-ghost",), provider=_provider(_FakeCandidateRisks(ghost)))


def test_the_carriers_finding_ids_annotation_is_the_surfaces_own():
    """G33's derivation: compared against the copied type, never a hand-written annotation."""
    carrier = {field.name: field.type for field in dataclasses.fields(ExplainableRisk)}
    surface = {field.name: field.type for field in dataclasses.fields(ScoredSurface)}

    assert carrier["finding_ids"] == surface["finding_ids"]
