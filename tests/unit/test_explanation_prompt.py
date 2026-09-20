"""The prompt's wording and what it renders. ADR-0032 decision 4.

These pin the INSTRUCTIONS and the INPUT. Whether a real model follows them is not
something a unit test can show, and nothing in CI shows it (G62, G65).
"""

from verion.modules.brief.adapters.outbound.explanation.prompt import (
    DEVELOPER_INSTRUCTIONS,
    build_messages,
    render_facts,
)
from verion.modules.correlation.ports.candidate_risk import CONFIDENCE_DEFINITION
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import (
    CORROBORATION_DEFINITION,
    EXPOSURE_DEFINITION,
    SEVERITY_DEFINITION,
    SurfaceMember,
    score_surface,
)
from verion.shared_kernel.confidence import Confidence
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# Sentinels standing in for values that must never reach the model.
_IDS = ("id-semgrep-SENTINEL", "id-zap-SENTINEL")
_PACKAGE_OR_URL = "/calculate-SENTINEL"


def _decision():
    return explainable_decision(
        score_surface(
            project_id="project-SENTINEL",
            package=None,
            url=_PACKAGE_OR_URL,
            members=[
                SurfaceMember(
                    finding_id=_IDS[0],
                    source=ScannerTool.SEMGREP,
                    severity=Severity.HIGH,
                    confidence=Confidence.INFERRED,
                ),
                SurfaceMember(
                    finding_id=_IDS[1],
                    source=ScannerTool.ZAP,
                    severity=Severity.LOW,
                    confidence=Confidence.REPORTED,
                ),
            ],
        )
    )


def test_the_instructions_are_the_developer_message_and_the_facts_the_user_message():
    messages = build_messages(_decision())

    assert [message["role"] for message in messages] == ["developer", "user"]
    assert messages[0]["content"] == DEVELOPER_INSTRUCTIONS
    assert messages[1]["content"] == render_facts(_decision())


def test_the_facts_carry_the_decided_bucket_score_and_thresholds():
    facts = render_facts(_decision())

    assert "Priority: fix_now (score 6)" in facts
    assert "fix_now at 6 or more; plan at 4 or more; monitor below 4." in facts


def test_each_signal_is_rendered_with_its_definition_verbatim():
    facts = render_facts(_decision())

    assert "severity_signal = 4 (high). Definition: " + SEVERITY_DEFINITION in facts
    assert "exposure_signal = 1. Definition: " + EXPOSURE_DEFINITION in facts
    assert (
        "corroboration_signal = 1 (from 2 distinct scanners). Definition: "
        + CORROBORATION_DEFINITION
        in facts
    )


def test_nothing_identifying_or_scanned_reaches_the_model():
    rendered = "\n".join(message["content"] for message in build_messages(_decision()))

    for forbidden in (*_IDS, _PACKAGE_OR_URL, "project-SENTINEL", "SENTINEL"):
        assert forbidden not in rendered


def test_a_zero_signal_renders_its_note_and_no_severity_label():
    decision = explainable_decision(
        score_surface(
            project_id="p",
            package="urllib3",
            url=None,
            members=[
                SurfaceMember(
                    finding_id="f",
                    source=ScannerTool.TRIVY,
                    severity=Severity.UNKNOWN,
                    confidence=Confidence.REPORTED,
                )
            ],
        )
    )
    facts = render_facts(decision)

    assert "severity_signal = 0. Definition: " in facts
    assert "  Note: no member stated a severity" in facts
    assert "corroboration_signal = 0. Definition: " in facts


def test_the_instructions_forbid_redeciding_and_every_fr8_part_this_input_lacks():
    """Rule 6, and the FR-8 parts with no source in this input (ADR-0032 decision 2)."""
    assert "The decision is final." in DEVELOPER_INSTRUCTIONS
    assert (
        "Do not recommend, imply or speculate about a different priority" in DEVELOPER_INSTRUCTIONS
    )
    for missing in ("how to fix it", "how much effort", "how confident anyone is"):
        assert missing in DEVELOPER_INSTRUCTIONS
    assert "only in the terms of its definition" in DEVELOPER_INSTRUCTIONS


# ---------------------------------------------------------------------------
# M8.5, ADR-0037 decision 9 — the confidence reaches no prompt
# ---------------------------------------------------------------------------


def test_no_message_carries_a_confidence_key_or_its_definition():
    """A REGRESSION GUARD, not the mechanism, and the distinction is the point.

    The property already holds structurally: `render_facts` takes `ExplainableDecision`, and
    ADR-0037 decision 8 deliberately keeps the confidence OFF that carrier precisely so the
    narrator cannot be handed it — rule 6 by the type rather than by a convention. This test
    is what keeps that true for a later issue that widens the input.

    **Asserted positionally and over the WHOLE definition, never as a value substring**, and
    that choice was measured rather than preferred. `Confidence.REPORTED == "reported"`, and
    the word already appears in this very message: `CORROBORATION_DEFINITION` renders *"were
    reported by two or more different scanners"*, and `scoring.py`'s `Signal.note` texts add
    two more literals that `_signal_line` renders whenever a signal does not fire. A
    `"reported" not in message` assertion is red on day one, and the repair that makes it
    green — narrowing to the two values that happen to pass — deletes its own subject.
    """
    messages = build_messages(_decision())
    rendered = {message["role"]: message["content"] for message in messages}

    for role, content in rendered.items():
        # The whole word, anywhere, case-insensitively — and it is SAFE to assert that
        # strongly, which was measured rather than assumed. The collision that forced this
        # test's shape is on the VALUES (`"reported"` appears in `CORROBORATION_DEFINITION`
        # and in two `Signal.note` texts `_signal_line` renders), not on the word
        # `confidence`. `DEVELOPER_INSTRUCTIONS` says "how confident anyone is", and
        # `confident` is not `confidence`.
        #
        # An earlier draft checked `line.lower().startswith("confidence")` over unstripped
        # lines. An indented line — the shape `_signal_line` already emits for a note — walks
        # straight past that, and so does a confidence appended to an existing line.
        assert "confidence" not in content.lower(), role
        assert CONFIDENCE_DEFINITION not in content, role


def test_rule_four_still_says_the_model_is_not_told_how_confident_anyone_is():
    """The sentence the test above rests on, pinned so a repair cannot delete it.

    If a later issue renders the confidence and then "fixes" the assertion by removing this
    clause from the instructions, both halves would go green while the property was gone.
    """
    assert "how confident anyone is" in DEVELOPER_INSTRUCTIONS
    assert "You are not told" in DEVELOPER_INSTRUCTIONS
