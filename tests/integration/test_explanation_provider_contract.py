"""`ExplanationProviderPort`'s contract, held by the fake AND the real adapter alike.

**Why the fake is tested at all.** M7.2 will test its use case against
`FakeExplanationProvider`, and a fake nobody checks against the real implementation proves
only the consumer's side of a contract (G65). Running the same assertions over both is what
lets a test built on the fake stand on something. The real adapter runs over
`MockTransport`, so this is its code against the port's promises — not OpenAI's behaviour,
which nothing in CI reaches (ADR-0032, M7.1's departure).

M7.2 moves the fake if its tests need to import it from elsewhere.
"""

import httpx2
import pytest

from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import PROMPT_VERSION
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity


class FakeExplanationProvider:
    """`ExplanationProviderPort`, deterministic. Records its calls, and the calls are READ.

    Its text restates only the decision's own numbers, so a test using it can never be
    passing on prose the Risk Engine did not decide. `fail=True` stands in for every
    provider failure, which the real adapter collapses to the same one exception.
    """

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.calls: list[ExplainableDecision] = []

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


_PROVIDERS = {
    "fake": FakeExplanationProvider,
    "openai-over-mock-transport": _real,
}


def _decision(*members: SurfaceMember) -> ExplainableDecision:
    return explainable_decision(
        score_surface(project_id="p", package=None, url="/x", members=list(members))
    )


_FIX_NOW = (
    SurfaceMember(finding_id="f-1", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
    SurfaceMember(finding_id="f-2", source=ScannerTool.ZAP, severity=Severity.LOW),
)
_QUIET = (SurfaceMember(finding_id="f-3", source=ScannerTool.TRIVY, severity=Severity.UNKNOWN),)


@pytest.mark.parametrize("make", _PROVIDERS.values(), ids=_PROVIDERS.keys())
@pytest.mark.parametrize("members", [_FIX_NOW, _QUIET], ids=["fix-now", "all-signals-zero"])
async def test_a_provider_returns_a_non_empty_explanation_with_its_producer(make, members):
    explanation = await make().explain(decision=_decision(*members))

    assert isinstance(explanation, Explanation)
    assert explanation.text.strip()
    assert explanation.model
    assert explanation.prompt_version == PROMPT_VERSION


@pytest.mark.parametrize("make", _PROVIDERS.values(), ids=_PROVIDERS.keys())
async def test_a_failing_provider_raises_only_explanation_unavailable(make):
    with pytest.raises(ExplanationUnavailable):
        await make(fail=True).explain(decision=_decision(*_FIX_NOW))


async def test_the_fake_records_exactly_the_decision_it_was_given():
    """M6.2's lesson: a fake that "records its calls" proves nothing until a test reads them."""
    fake = FakeExplanationProvider()
    decision = _decision(*_FIX_NOW)

    await fake.explain(decision=decision)

    assert fake.calls == [decision]
    assert fake.calls[0] is decision


async def test_the_fake_narrates_only_the_numbers_it_was_given():
    explanation = await FakeExplanationProvider().explain(decision=_decision(*_FIX_NOW))

    assert explanation.text == "fix_now at 6: severity 4 + exposure 1 + corroboration 1."
