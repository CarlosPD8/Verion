from collections.abc import Callable
from pathlib import Path

import pytest

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (
    DESCRIBE_PROMPT_VERSION,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import PROMPT_VERSION
from verion.modules.brief.domain.brief_member import BriefMember
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision

_SCANNER_FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class FakeExplanationProvider:
    """`ExplanationProviderPort`, deterministic. Records its calls, and the calls are READ.

    Its text restates only the decision's own numbers, so a test using it can never be
    passing on prose the Risk Engine did not decide. `fail=True` stands in for every
    provider failure, which the real adapter collapses to the same one exception.

    **`describe` since M7.3**, recording into `describe_calls`. Its text only echoes each
    member's scanner and title, so it states nothing the members did not supply.

    **It obeys no instructions, so it proves nothing about prompt safety.** A test that feeds it
    injected text and asserts the Brief is unaffected passes with every sanitizer deleted
    (ADR-0034 decision 5). Sanitizer tests read the rendered prompt instead.

    **Moved here from `tests/integration/test_explanation_provider_contract.py` at M7.2**,
    because M7.2's unit and route tests use it and `tests/` is not a package. It
    arrives through `explanation_provider_factory`, which returns this CLASS, so the contract
    test still holds this fake and the real adapter to the same assertions (G65).
    """

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.calls: list[ExplainableDecision] = []
        self.describe_calls: list[tuple[tuple[BriefMember, ...], int]] = []

    async def explain(self, *, decision: ExplainableDecision) -> Explanation:
        self.calls.append(decision)
        if self._fail:
            raise ExplanationUnavailable("fake provider failure")
        text = (
            f"{decision.priority} at {decision.priority_score}: severity "
            f"{decision.severity.value} + exposure {decision.exposure.value} + corroboration "
            f"{decision.corroboration.value}."
        )
        return Explanation(text=text, model="fake", prompt_version=PROMPT_VERSION)

    async def describe(self, *, members: tuple[BriefMember, ...], member_count: int) -> Explanation:
        self.describe_calls.append((members, member_count))
        if self._fail:
            raise ExplanationUnavailable("fake provider failure")
        text = f"{member_count} findings: " + "; ".join(
            f"{member.source} {member.title}" for member in members
        )
        return Explanation(text=text, model="fake", prompt_version=DESCRIBE_PROMPT_VERSION)


@pytest.fixture
def explanation_provider_factory() -> type[FakeExplanationProvider]:
    """The contract-tested fake `ExplanationProviderPort`, as a class to construct.

    Same shape as `tests/unit/conftest.py`'s `*_factory` fixtures, so a test chooses
    `fail=True` itself.
    """
    return FakeExplanationProvider


@pytest.fixture
def scanner_fixture() -> Callable[[str], str]:
    """Reads a captured scanner-output fixture by file name.

    Root-level rather than in `tests/unit/`, because both trees need it: M4.1's
    mapper unit tests read these, and M4.4's `test_normalize_scan_pipeline.py`
    feeds the same files to in-process fake scanners as their `raw_output` (which
    is what keeps that test off the container-bound budget CLAUDE.md tracks).
    `tests/` is not a package, so a shared path constant has to arrive as a
    fixture — otherwise the second consumer duplicates it or the files get moved
    into its tree, and one issue's work lands in another issue's diff.

    Returns the file's text exactly as committed, since that is what a scanner
    adapter would have handed to `ScanResult.raw_output`.
    """

    def _read(name: str) -> str:
        path = _SCANNER_FIXTURES / name
        if not path.is_file():
            available = sorted(p.name for p in _SCANNER_FIXTURES.glob("*.json"))
            raise FileNotFoundError(f"No scanner fixture '{name}'. Available: {available}")
        return path.read_text(encoding="utf-8")

    return _read
