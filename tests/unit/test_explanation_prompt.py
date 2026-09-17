"""The prompt's wording and what it renders. ADR-0032 decision 4.

These pin the INSTRUCTIONS and the INPUT. Whether a real model follows them is not
something a unit test can show, and nothing in CI shows it (G62, G65).
"""

from verion.modules.brief.adapters.outbound.explanation.prompt import (
    DEVELOPER_INSTRUCTIONS,
    build_messages,
    render_facts,
)
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import (
    CORROBORATION_DEFINITION,
    EXPOSURE_DEFINITION,
    SEVERITY_DEFINITION,
    SurfaceMember,
    score_surface,
)
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
                    finding_id=_IDS[0], source=ScannerTool.SEMGREP, severity=Severity.HIGH
                ),
                SurfaceMember(finding_id=_IDS[1], source=ScannerTool.ZAP, severity=Severity.LOW),
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
                SurfaceMember(finding_id="f", source=ScannerTool.TRIVY, severity=Severity.UNKNOWN)
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
