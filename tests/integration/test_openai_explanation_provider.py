"""`OpenAIExplanationProvider` over `httpx2.MockTransport`, and this module's rule-12 tests.

**What this file exercises, and what it does not.** It runs the adapter's OWN code: the
request it builds, where the credential goes, how every failure is translated, and that no
response body reaches an exception. **It does not exercise OpenAI's real contract.** The
fixtures below follow openai-python's typed models (`ChatCompletion`,
`ChatCompletionMessage`) and OpenAI's documented error shape, not a captured response — a
weaker footing than `test_github_adapter.py`'s captured payloads, and G19's shape. That is
the M7.1 departure from CLAUDE.md's definition of done, recorded with its end condition in
`ROADMAP.md`'s M7.1 entry (ADR-0032).

The 401 body carries a key's prefix and last four characters inside `error.message`,
because that is what a user-pasted OpenAI 401 showed (AutoGPT issue #1422, 2023). Whether
today's API still does so is unverified; the test assumes the worse case.

No skip anywhere: nothing here needs a credential, and no request leaves the process. Like
every file in `tests/integration/`, it does need the Postgres service, because
`conftest.py`'s autouse `_clean_all_tables` fixture migrates and cleans that database.
"""

import json
import logging
import traceback

import httpx2
import pytest

from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import (
    PROMPT_VERSION,
    build_messages,
)
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

_KEY = "sk-proj-KEYSENTINEL0123456789abcdefWXYZ"
# The fragments an echoing 401 would show: the visible prefix and the last four characters.
_KEY_FRAGMENTS = ("sk-proj-KEYSENTINEL", "WXYZ")
_MODEL = "gpt-5-mini"


def _decision():
    return explainable_decision(
        score_surface(
            project_id="p",
            package=None,
            url="/calculate",
            members=[
                SurfaceMember(finding_id="f-1", source=ScannerTool.SEMGREP, severity=Severity.HIGH),
                SurfaceMember(finding_id="f-2", source=ScannerTool.ZAP, severity=Severity.LOW),
            ],
        )
    )


def _completion(*, content="The priority is fix_now.", finish_reason="stop", refusal=None):
    """A body in openai-python's `ChatCompletion` shape. Schema-derived, not captured."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_758_067_200,
        "model": "gpt-5-mini-2025-08-07",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, "refusal": refusal},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 400, "completion_tokens": 120, "total_tokens": 520},
    }


_ECHOING_401 = {
    "error": {
        "message": (
            "Incorrect API key provided: sk-proj-KEYSENTINEL****************WXYZ. "
            "You can find your API key at https://platform.openai.com/account/api-keys."
        ),
        "type": "invalid_request_error",
        "param": None,
        "code": "invalid_api_key",
    }
}


def _provider(handler):
    requests: list[httpx2.Request] = []

    def recording(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return handler(request)

    provider = OpenAIExplanationProvider(
        api_key=_KEY, model=_MODEL, transport=httpx2.MockTransport(recording)
    )
    return provider, requests


def _leaks(exc: BaseException) -> list[str]:
    rendered = "".join(traceback.format_exception(exc)) + repr(exc)
    return [fragment for fragment in (_KEY, *_KEY_FRAGMENTS) if fragment in rendered]


# --- the request ------------------------------------------------------------------------


async def test_the_request_is_one_post_to_chat_completions_with_exactly_four_body_keys():
    provider, requests = _provider(lambda _: httpx2.Response(200, json=_completion()))

    await provider.explain(decision=_decision())

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://api.openai.com/v1/chat/completions"

    body = json.loads(request.content)
    assert set(body) == {"model", "messages", "max_completion_tokens", "store"}
    assert body["model"] == _MODEL
    assert body["store"] is False
    assert body["messages"] == build_messages(_decision())
    assert "temperature" not in body


async def test_the_key_travels_only_in_the_authorization_header():
    provider, requests = _provider(lambda _: httpx2.Response(200, json=_completion()))

    await provider.explain(decision=_decision())

    request = requests[0]
    assert request.headers["Authorization"] == f"Bearer {_KEY}"
    assert _KEY not in str(request.url)
    assert _KEY.encode() not in request.content


async def test_a_completed_answer_is_the_stripped_text_the_reported_model_and_the_prompt_version():
    provider, _ = _provider(
        lambda _: httpx2.Response(200, json=_completion(content="  Narrative.  \n"))
    )

    explanation = await provider.explain(decision=_decision())

    assert explanation.text == "Narrative."
    assert explanation.model == "gpt-5-mini-2025-08-07"
    assert explanation.prompt_version == PROMPT_VERSION


# --- rule 12: nothing from the credential or a response body reaches an exception or a log


async def test_an_echoing_401_leaks_no_part_of_the_key_into_the_exception_or_the_log(caplog):
    caplog.set_level(logging.DEBUG)
    provider, _ = _provider(lambda _: httpx2.Response(401, json=_ECHOING_401))

    with pytest.raises(ExplanationUnavailable) as exc_info:
        await provider.explain(decision=_decision())

    assert str(exc_info.value) == "OpenAI answered HTTP 401"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert _leaks(exc_info.value) == []
    assert not [fragment for fragment in (_KEY, *_KEY_FRAGMENTS) if fragment in caplog.text]


async def test_a_transport_error_carrying_the_key_is_not_chained_into_the_raised_error():
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(f"refused, header was {request.headers['Authorization']}")

    provider, _ = _provider(handler)

    with pytest.raises(ExplanationUnavailable) as exc_info:
        await provider.explain(decision=_decision())

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert _leaks(exc_info.value) == []


# --- every failure is ExplanationUnavailable --------------------------------------------


@pytest.mark.parametrize("status", [400, 403, 429, 500, 503])
async def test_a_non_200_status_is_unavailable_and_names_only_the_status(status):
    provider, _ = _provider(
        lambda _: httpx2.Response(status, json={"error": {"message": f"echo {_KEY}"}})
    )

    with pytest.raises(
        ExplanationUnavailable, match=f"^OpenAI answered HTTP {status}$"
    ) as exc_info:
        await provider.explain(decision=_decision())

    assert _leaks(exc_info.value) == []


async def test_a_timeout_is_unavailable():
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout("timed out", request=request)

    provider, _ = _provider(handler)

    with pytest.raises(ExplanationUnavailable):
        await provider.explain(decision=_decision())


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx2.Response(200, content=b"not json"), "not JSON"),
        (httpx2.Response(200, json={"model": "m", "choices": []}), "no choices"),
        (httpx2.Response(200, json=[1, 2]), "no choices"),
        (httpx2.Response(200, json=_completion(finish_reason="length")), "finish_reason length"),
        (
            httpx2.Response(200, json=_completion(finish_reason="content_filter")),
            "finish_reason content_filter",
        ),
        (httpx2.Response(200, json=_completion(finish_reason="new-reason")), "unrecognized"),
        (httpx2.Response(200, json=_completion(finish_reason=["stop"])), "unrecognized"),
        (httpx2.Response(200, json=_completion(content=None, refusal="I can't.")), "refused"),
        (httpx2.Response(200, json=_completion(content="   ")), "empty content"),
        (httpx2.Response(200, json={**_completion(), "model": None}), "without naming"),
    ],
    ids=[
        "not-json",
        "empty-choices",
        "not-an-object",
        "length",
        "content-filter",
        "unknown-finish-reason",
        "unhashable-finish-reason",
        "refusal",
        "blank-content",
        "no-model",
    ],
)
async def test_an_unusable_200_is_unavailable(response, message):
    provider, _ = _provider(lambda _: response)

    with pytest.raises(ExplanationUnavailable, match=message) as exc_info:
        await provider.explain(decision=_decision())

    assert _leaks(exc_info.value) == []
