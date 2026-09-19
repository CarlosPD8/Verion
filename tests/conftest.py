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


class InMemoryProjectAccess:
    """`ProjectAccessPort` — sets of (project_id, user_id) pairs, one per verdict.

    A set rather than a membership store, deliberately: the port returns verdicts
    and cannot say WHY access was denied, so a fake that modelled memberships
    would be modelling more than the port exposes and would invite a test to
    assert on a distinction no consumer can observe.

    **Moved here from `tests/unit/conftest.py` at M8.8**, when the port gained
    `may_manage_project`, so `tests/integration/test_project_access_contract.py`
    can hold this fake and `PostgresProjectAccessReader` to the same assertions
    (G65). `permit_manage` also permits reading, because the real rule does: an
    owner is a member.
    """

    def __init__(self, permitted: set[tuple[str, str]] | None = None) -> None:
        self._permitted = permitted or set()
        self._managers: set[tuple[str, str]] = set()
        self.calls: list[tuple[str, str]] = []
        self.manage_calls: list[tuple[str, str]] = []

    def permit(self, project_id: str, user_id: str) -> None:
        self._permitted.add((project_id, user_id))

    def permit_manage(self, project_id: str, user_id: str) -> None:
        self._permitted.add((project_id, user_id))
        self._managers.add((project_id, user_id))

    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        self.calls.append((project_id, user_id))
        return (project_id, user_id) in self._permitted

    async def may_manage_project(self, *, project_id: str, user_id: str) -> bool:
        self.manage_calls.append((project_id, user_id))
        return (project_id, user_id) in self._managers


@pytest.fixture
def project_access() -> InMemoryProjectAccess:
    return InMemoryProjectAccess()


@pytest.fixture
def project_access_factory() -> type[InMemoryProjectAccess]:
    """The contract-tested fake `ProjectAccessPort`, as a class to construct."""
    return InMemoryProjectAccess


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
