"""The stored `decision` value: versioned, derived, and loud when its carrier changes. ADR-0033.

**Why two assertions and not one** (ADR-0033 Consequences):

- **The literal v1 enumerations equal the `dataclasses.fields` derivation.** A field added to
  or removed from `ExplainableDecision` or `ExplainableSignal` fails this test. The same
  change must then bump the stored version and keep a v1 reader, or migrate the rows.
- **The serializer's output keys equal that derivation.** A serializer rewritten field by
  field, which would store short when the carrier grows, fails here.

Pinning the literal against the serializer's own output instead would make both checks
pass while the carrier changed. That is the defect this file exists to prevent.

The mapping functions are adapter-private and imported here directly, on the precedent of
the test that imports both route orderings (ADR-0030 decision 2). Importing them reaches no
database.
"""

import dataclasses

import pytest

from verion.modules.brief.adapters.outbound.db.repository import (
    _decision_from_json,
    _decision_to_json,
)
from verion.modules.brief.domain.exceptions import StoredBriefUnreadable
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.modules.risk_engine.ports.explainable_decision import (
    ExplainableDecision,
    ExplainableSignal,
)
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# Version 1's shape, written out. NOT derived: that is the point.
V1_DECISION_KEYS = {
    "priority",
    "priority_score",
    "fix_now_at",
    "plan_at",
    "severity",
    "exposure",
    "corroboration",
}
V1_SIGNAL_KEYS = {"name", "value", "produced_by", "note", "definition"}

_V1_STORED = {
    "version": 1,
    "decision": {
        "priority": "plan",
        "priority_score": 5,
        "fix_now_at": 6,
        "plan_at": 4,
        "severity": {
            "name": "severity_signal",
            "value": 4,
            "produced_by": ["f-1"],
            "note": None,
            "definition": "sev-def",
        },
        "exposure": {
            "name": "exposure_signal",
            "value": 1,
            "produced_by": ["f-2"],
            "note": None,
            "definition": "exp-def",
        },
        "corroboration": {
            "name": "corroboration_signal",
            "value": 0,
            "produced_by": [],
            "note": "every member was reported by zap",
            "definition": "cor-def",
        },
    },
}


def _decision() -> ExplainableDecision:
    return explainable_decision(
        score_surface(
            project_id="p",
            package=None,
            url="/calculate",
            members=[
                SurfaceMember(
                    finding_id="f-1",
                    source=ScannerTool.SEMGREP,
                    severity=Severity.HIGH,
                    confidence=Confidence.REPORTED,
                ),
                SurfaceMember(
                    finding_id="f-2",
                    source=ScannerTool.ZAP,
                    severity=Severity.LOW,
                    confidence=Confidence.REPORTED,
                ),
            ],
        )
    )


def _names(cls) -> set[str]:
    return {field.name for field in dataclasses.fields(cls)}


def test_the_literal_v1_shape_equals_the_carriers_fields():
    """Fails when the carrier changes. Bump the version and keep a v1 reader, then update."""
    assert _names(ExplainableDecision) == V1_DECISION_KEYS
    assert _names(ExplainableSignal) == V1_SIGNAL_KEYS


def test_the_serializer_writes_every_carrier_field_and_a_version():
    stored = _decision_to_json(_decision())

    assert set(stored) == {"version", "decision"}
    assert stored["version"] == 1
    assert set(stored["decision"]) == _names(ExplainableDecision)
    for signal in ("severity", "exposure", "corroboration"):
        assert set(stored["decision"][signal]) == _names(ExplainableSignal)


def test_a_decision_round_trips_whole():
    decision = _decision()

    assert _decision_from_json(_decision_to_json(decision)) == decision


def test_a_literal_v1_row_reads_back_as_that_decision():
    assert _decision_from_json(_V1_STORED) == ExplainableDecision(
        priority="plan",
        priority_score=5,
        fix_now_at=6,
        plan_at=4,
        severity=ExplainableSignal(
            name="severity_signal", value=4, produced_by=("f-1",), note=None, definition="sev-def"
        ),
        exposure=ExplainableSignal(
            name="exposure_signal", value=1, produced_by=("f-2",), note=None, definition="exp-def"
        ),
        corroboration=ExplainableSignal(
            name="corroboration_signal",
            value=0,
            produced_by=(),
            note="every member was reported by zap",
            definition="cor-def",
        ),
    )


@pytest.mark.parametrize(
    "stored",
    [
        {**_V1_STORED, "version": 2},
        {"decision": _V1_STORED["decision"]},
        {"version": "1", "decision": _V1_STORED["decision"]},
        {"version": True, "decision": _V1_STORED["decision"]},
        {"version": 1.0, "decision": _V1_STORED["decision"]},
        ["not", "a", "mapping"],
    ],
    ids=[
        "unknown-version",
        "missing-version",
        "string-version",
        "bool-version",
        "float-version",
        "not-a-mapping",
    ],
)
def test_an_unreadable_version_raises_the_brief_error(stored):
    with pytest.raises(StoredBriefUnreadable):
        _decision_from_json(stored)


def _with(decision_changes=None, severity_changes=None):
    decision = {**_V1_STORED["decision"], **(decision_changes or {})}
    if severity_changes is not None:
        decision["severity"] = {**_V1_STORED["decision"]["severity"], **severity_changes}
    return {"version": 1, "decision": decision}


@pytest.mark.parametrize(
    "stored",
    [
        {"version": 1, "decision": []},
        _with({"priority_score": "x"}),
        _with({"fix_now_at": True}),
        _with({"severity": "not-an-object"}),
        _with(severity_changes={"produced_by": 5}),
        _with(severity_changes={"produced_by": ["f-1", 3]}),
        _with(severity_changes={"note": 7}),
        _with(severity_changes={"value": True}),
    ],
    ids=[
        "decision-not-an-object",
        "string-score",
        "bool-threshold",
        "signal-not-an-object",
        "int-produced-by",
        "mixed-produced-by",
        "int-note",
        "bool-value",
    ],
)
def test_a_v1_row_whose_values_are_not_v1s_types_raises_the_brief_error(stored):
    """Reaching only a hand-written row today, and still never read back as valid."""
    with pytest.raises(StoredBriefUnreadable):
        _decision_from_json(stored)


def test_a_v1_row_missing_a_field_raises_and_echoes_no_stored_content():
    """What an old row looks like after the carrier gains a field without a version bump."""
    decision = {k: v for k, v in _V1_STORED["decision"].items() if k != "plan_at"}
    decision["severity"] = {**decision["severity"], "note": "STORED-CONTENT-SENTINEL"}

    with pytest.raises(StoredBriefUnreadable) as raised:
        _decision_from_json({"version": 1, "decision": decision})

    assert "STORED-CONTENT-SENTINEL" not in str(raised.value)
