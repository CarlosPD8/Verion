"""The carrier `brief` receives, and the one site in `risk_engine` that fills it. ADR-0032.

**G33's instance at M7.1.** A copy of another type's fields is a construction site `mypy`
checks and nothing else, and a narrowed annotation there moves the check without failing
it. So the shared fields are compared against `dataclasses.fields(Signal)` itself, never a
hand-written list — section (b)'s derivation, over the type that is actually copied.

Every `SurfaceMember` here is hand-written, on `test_risk_scoring.py`'s precedent, and no
`Finding` is — G40's count is unchanged. The combinations are ones the pipeline emits.
"""

import dataclasses

from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import (
    CORROBORATION_DEFINITION,
    EXPOSURE_DEFINITION,
    FIX_NOW_AT,
    PLAN_AT,
    SEVERITY_DEFINITION,
    Priority,
    Signal,
    SurfaceMember,
    score_surface,
)
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# ADR-0032 decision 2's enumeration. Binding: the test below asserts EQUALITY, so adding
# `package`, `url`, `finding_ids` or `project_id` fails here instead of widening the prompt
# boundary silently — scanned content in the prompt is M7.3's scope.
_DECISION_FIELDS = {
    "priority",
    "priority_score",
    "fix_now_at",
    "plan_at",
    "severity",
    "exposure",
    "corroboration",
}


def _fields(cls):
    return {field.name: field.type for field in dataclasses.fields(cls)}


def _calculate_surface():
    """The §10 shape: a Semgrep HIGH and ZAP members on one route path — 4 + 1 + 1."""
    return score_surface(
        project_id="proj-1",
        package=None,
        url="/calculate",
        members=[
            SurfaceMember(
                finding_id="f-semgrep", source=ScannerTool.SEMGREP, severity=Severity.HIGH
            ),
            SurfaceMember(finding_id="f-zap-1", source=ScannerTool.ZAP, severity=Severity.LOW),
            SurfaceMember(finding_id="f-zap-2", source=ScannerTool.ZAP, severity=Severity.MEDIUM),
        ],
    )


# --- the carrier's shape ----------------------------------------------------------------


def test_the_signal_carrier_copies_signal_field_for_field_and_adds_only_definition():
    signal_fields = _fields(Signal)
    carrier_fields = _fields(ExplainableSignal)

    assert set(carrier_fields) == set(signal_fields) | {"definition"}
    for name, annotation in signal_fields.items():
        assert carrier_fields[name] == annotation, name
    assert carrier_fields["definition"] is str


def test_the_decision_carrier_field_set_equals_the_enumeration_exactly():
    assert set(_fields(ExplainableDecision)) == _DECISION_FIELDS


def test_both_carriers_are_frozen():
    decision = explainable_decision(_calculate_surface())

    for target, attribute in ((decision, "priority"), (decision.severity, "value")):
        try:
            setattr(target, attribute, "changed")
        except dataclasses.FrozenInstanceError:
            continue
        raise AssertionError(f"{type(target).__name__}.{attribute} is writable")


# --- the fill site ----------------------------------------------------------------------


def test_the_fill_copies_the_decided_bucket_score_and_thresholds():
    surface = _calculate_surface()
    decision = explainable_decision(surface)

    assert surface.priority is Priority.FIX_NOW
    assert decision.priority == "fix_now"
    assert decision.priority in {priority.value for priority in Priority}
    assert decision.priority_score == surface.priority_score == 6
    assert decision.fix_now_at is FIX_NOW_AT
    assert decision.plan_at is PLAN_AT


def test_the_fill_copies_every_signal_value_unchanged_and_attaches_its_own_definition():
    surface = _calculate_surface()
    decision = explainable_decision(surface)

    pairs = (
        (surface.reasoning.severity, decision.severity, SEVERITY_DEFINITION),
        (surface.reasoning.exposure, decision.exposure, EXPOSURE_DEFINITION),
        (surface.reasoning.corroboration, decision.corroboration, CORROBORATION_DEFINITION),
    )
    for signal, copied, definition in pairs:
        for field in dataclasses.fields(Signal):
            assert getattr(copied, field.name) == getattr(signal, field.name), field.name
        assert copied.definition == definition


def test_a_quiet_surface_carries_its_notes_through():
    """All three signals zero: every `note` is set, and the copy must not drop one."""
    surface = score_surface(
        project_id="proj-1",
        package="urllib3",
        url=None,
        members=[
            SurfaceMember(finding_id="f-1", source=ScannerTool.TRIVY, severity=Severity.UNKNOWN)
        ],
    )
    decision = explainable_decision(surface)

    assert decision.priority == "monitor"
    assert decision.severity.note == "no member stated a severity"
    assert decision.exposure.note == "no member was reported by a DAST scanner"
    assert decision.corroboration.note == "every member was reported by trivy"


def test_the_corroboration_definition_states_what_the_signal_does_not_mean():
    """G62 lives in the words forwarded to the narrator, so those words are pinned."""
    assert "does not mean the scanners agree" in CORROBORATION_DEFINITION
    assert "same vulnerability" in CORROBORATION_DEFINITION
