"""`SecurityBrief`'s field set: ADR-0033 decision 2's enumeration, plus one part each from
M7.3 and M8.5.

Equality, not containment. An `estimated_effort`, `recommended_action` or `risk_id` added in
passing fails here rather than being depended on, and so does losing a field. `what_happened`
joined at M7.3 (ADR-0034 decision 3) and `confidence` at M8.5 (ADR-0037 decision 8), each by
decision rather than in passing — which is what this assertion exists to force.
"""

import dataclasses
from datetime import UTC, datetime

import pytest

from verion.modules.brief.domain.explanation import Explanation
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_FIELDS = {
    "id",
    "project_id",
    "finding_ids",
    "decision",
    "explanation",
    "what_happened",
    "confidence",
    "generated_at",
}


def test_the_field_set_equals_the_decisions_enumeration_exactly():
    assert {field.name for field in dataclasses.fields(SecurityBrief)} == _FIELDS


def test_a_brief_is_frozen():
    surface = score_surface(
        project_id="p",
        package="urllib3",
        url=None,
        members=[
            SurfaceMember(
                finding_id="f-1",
                source=ScannerTool.TRIVY,
                severity=Severity.HIGH,
                confidence=Confidence.REPORTED,
            )
        ],
    )
    brief = SecurityBrief(
        id="b-1",
        project_id="p",
        finding_ids=("f-1",),
        decision=explainable_decision(surface),
        explanation=Explanation(text="t", model="m", prompt_version="v"),
        what_happened=Explanation(text="w", model="m", prompt_version="v2"),
        confidence=Confidence.REPORTED,
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        brief.finding_ids = ("f-2",)  # type: ignore[misc]
