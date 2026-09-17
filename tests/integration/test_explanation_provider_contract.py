"""`ExplanationProviderPort`'s contract, held by the fake AND the real adapter alike.

**Why the fake is tested at all.** M7.2 tests its use case and routes against
`FakeExplanationProvider`, and a fake nobody checks against the real implementation proves
only the consumer's side of a contract (G65). Running the same assertions over both is what
lets a test built on the fake stand on something. The real adapter runs over
`MockTransport`, so this is its code against the port's promises — not OpenAI's behaviour,
which nothing in CI reaches (ADR-0032, M7.1's departure).

**The fake lives in `tests/conftest.py` since M7.2**, reached through the
`explanation_provider_factory` fixture, because `tests/` is not a package and M7.2's tests
needed it too. The parametrization below is by name and resolves the fake through that
fixture, so it is the same class every consumer uses.
"""

import httpx2
import pytest

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (
    DESCRIBE_PROMPT_VERSION,
)
from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import PROMPT_VERSION
from verion.modules.brief.domain.brief_member import BriefMember
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_COMPLETION = {
    "id": "chatcmpl-contract",
    "object": "chat.completion",
    "created": 1_758_067_200,
    "model": "gpt-5-mini-2025-08-07",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "A narrative.", "refusal": None},
            "finish_reason": "stop",
        }
    ],
}


def _real(*, fail: bool = False) -> OpenAIExplanationProvider:
    def handler(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(500) if fail else httpx2.Response(200, json=_COMPLETION)

    return OpenAIExplanationProvider(
        api_key="sk-contract", model="gpt-5-mini", transport=httpx2.MockTransport(handler)
    )


_PROVIDER_NAMES = ["fake", "openai-over-mock-transport"]


@pytest.fixture
def make(request, explanation_provider_factory):
    """The provider constructor named by the test's `provider` parameter."""
    return {"fake": explanation_provider_factory, "openai-over-mock-transport": _real}[
        request.param
    ]


def _decision(*members: SurfaceMember) -> ExplainableDecision:
    return explainable_decision(
        score_surface(project_id="p", package=None, url="/x", members=list(members))
    )


_FIX_NOW = (
    SurfaceMember(finding_id="f-1", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
    SurfaceMember(finding_id="f-2", source=ScannerTool.ZAP, severity=Severity.LOW),
)
_QUIET = (SurfaceMember(finding_id="f-3", source=ScannerTool.TRIVY, severity=Severity.UNKNOWN),)


@pytest.mark.parametrize("make", _PROVIDER_NAMES, indirect=True)
@pytest.mark.parametrize("members", [_FIX_NOW, _QUIET], ids=["fix-now", "all-signals-zero"])
async def test_a_provider_returns_a_non_empty_explanation_with_its_producer(make, members):
    explanation = await make().explain(decision=_decision(*members))

    assert isinstance(explanation, Explanation)
    assert explanation.text.strip()
    assert explanation.model
    assert explanation.prompt_version == PROMPT_VERSION


@pytest.mark.parametrize("make", _PROVIDER_NAMES, indirect=True)
async def test_a_failing_provider_raises_only_explanation_unavailable(make):
    with pytest.raises(ExplanationUnavailable):
        await make(fail=True).explain(decision=_decision(*_FIX_NOW))


_MEMBERS = (
    BriefMember.from_scalars(
        finding_id="f-1",
        source=ScannerTool.SEMGREP,
        title="dangerous-eval",
        file_path="app.py",
        start_line=28,
        end_line=28,
        package=None,
        installed_version=None,
        url=None,
        http_method=None,
        parameter=None,
    ),
)


@pytest.mark.parametrize("make", _PROVIDER_NAMES, indirect=True)
async def test_describe_returns_a_non_empty_explanation_with_its_own_prompt_version(make):
    """M7.3: the second method holds to the same promises as the first (G65)."""
    explanation = await make().describe(members=_MEMBERS, member_count=3)

    assert isinstance(explanation, Explanation)
    assert explanation.text.strip()
    assert explanation.model
    assert explanation.prompt_version == DESCRIBE_PROMPT_VERSION


@pytest.mark.parametrize("make", _PROVIDER_NAMES, indirect=True)
async def test_a_failing_describe_raises_only_explanation_unavailable(make):
    with pytest.raises(ExplanationUnavailable):
        await make(fail=True).describe(members=_MEMBERS, member_count=1)


async def test_the_fake_records_exactly_the_members_and_count_it_was_given(
    explanation_provider_factory,
):
    fake = explanation_provider_factory()

    await fake.describe(members=_MEMBERS, member_count=3)

    assert fake.describe_calls == [(_MEMBERS, 3)]
    assert fake.describe_calls[0][0] is _MEMBERS
    assert fake.calls == []


async def test_the_fake_records_exactly_the_decision_it_was_given(explanation_provider_factory):
    """M6.2's lesson: a fake that "records its calls" proves nothing until a test reads them."""
    fake = explanation_provider_factory()
    decision = _decision(*_FIX_NOW)

    await fake.explain(decision=decision)

    assert fake.calls == [decision]
    assert fake.calls[0] is decision


async def test_the_fake_narrates_only_the_numbers_it_was_given(explanation_provider_factory):
    explanation = await explanation_provider_factory().explain(decision=_decision(*_FIX_NOW))

    assert explanation.text == "fix_now at 6: severity 4 + exposure 1 + corroboration 1."
