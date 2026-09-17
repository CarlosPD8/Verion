"""`OpenAIExplanationProvider` over `httpx2.MockTransport`, replaying CAPTURED responses.

**What this file exercises.** The adapter's own code (the request it builds, where the
credential goes, how every failure is translated, that no response body reaches an
exception) against response bodies OpenAI actually sent. `tests/integration/fixtures/openai/`
holds a 200 per prompt and a 401, captured 2026-09-17 by `scripts/capture_openai_responses.py`
and redacted as that directory's README records. This is `test_github_adapter.py`'s footing,
and it ends the M7.1 departure (`ROADMAP.md`'s M7.1 entry; ADR-0032's M7.3 capture amendment).

**What it still does not exercise.** A replay proves the adapter reads what OpenAI sent on one
day, for one model at its default reasoning effort. It does not prove OpenAI sends that
tomorrow, and no test here reaches the API (**G65**).

**Most unusable-200 cases are a captured body with a field changed**, because OpenAI produced no
`length`, refusal or blank answer during the capture, and a replay cannot show a shape nobody
observed. The refusal case changes two fields, and the empty-choices and not-an-object cases are
built from scratch, because no capture can express a body that is not a completion.

**The 401 echoes the key it was sent**, as observed in the capture (**G71**): its first eight
characters, asterisks, and its last four. The fixture holds markers in their place, and
`_ECHOING_401` puts this module's key's fragments back, so the leak tests run against the real
message with a real echo in it.

No skip anywhere: nothing here needs a credential, and no request leaves the process. Like
every file in `tests/integration/`, it does need the Postgres service, because
`conftest.py`'s autouse `_clean_all_tables` fixture migrates and cleans that database.
"""

import copy
import json
import logging
import traceback
from pathlib import Path

import httpx2
import pytest

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (
    DESCRIBE_PROMPT_VERSION,
    build_describe_messages,
)
from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import (
    PROMPT_VERSION,
    build_messages,
)
from verion.modules.brief.domain.brief_member import BriefMember
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
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

_KEY = "sk-proj-KEYSENTINEL0123456789abcdefWXYZ"
# The fragments the captured 401 echoes: the first eight characters and the last four.
_KEY_FRAGMENTS = (_KEY[:8], _KEY[-4:])
_MODEL = "gpt-5-mini"

_FIXTURES = Path(__file__).parent / "fixtures" / "openai"
# What `scripts/capture_openai_responses.py` writes in place of the throwaway key's echo.
_KEY_FIRST_8_MARKER = "[REDACTED-KEY-FIRST-8]"
_KEY_LAST_4_MARKER = "[REDACTED-KEY-LAST-4]"


def _captured(name: str):
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


_EXPLAIN_200 = _captured("chat_completion_200_explain.json")
_DESCRIBE_200 = _captured("chat_completion_200_describe.json")
_CAPTURED_401 = _captured("chat_completion_401.json")


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


_KEEP = object()


def _completion(*, base=None, content=_KEEP, finish_reason=_KEEP, refusal=_KEEP):
    """A captured 200, whole, with at most the named fields changed. Defaults to explain's."""
    body = copy.deepcopy(_EXPLAIN_200 if base is None else base)
    choice = body["choices"][0]
    if content is not _KEEP:
        choice["message"]["content"] = content
    if finish_reason is not _KEEP:
        choice["finish_reason"] = finish_reason
    if refusal is not _KEEP:
        choice["message"]["refusal"] = refusal
    return body


# The captured 401, with THIS module's key echoed where OpenAI echoed the throwaway key.
_ECHOING_401 = json.loads(
    json.dumps(_CAPTURED_401)
    .replace(_KEY_FIRST_8_MARKER, _KEY[:8])
    .replace(_KEY_LAST_4_MARKER, _KEY[-4:])
)


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


# --- the captured fixtures -------------------------------------------------------------


async def test_the_captured_explain_200_replayed_unchanged_is_its_own_text_and_model():
    provider, _ = _provider(lambda _: httpx2.Response(200, json=_EXPLAIN_200))

    explanation = await provider.explain(decision=_decision())

    assert explanation.text == _EXPLAIN_200["choices"][0]["message"]["content"].strip()
    assert explanation.model == _EXPLAIN_200["model"]
    assert explanation.prompt_version == PROMPT_VERSION


async def test_the_captured_describe_200_replayed_unchanged_is_its_own_text_and_model():
    provider, _ = _provider(lambda _: httpx2.Response(200, json=_DESCRIBE_200))

    explanation = await provider.describe(members=_members(), member_count=2)

    assert explanation.text == _DESCRIBE_200["choices"][0]["message"]["content"].strip()
    assert explanation.model == _DESCRIBE_200["model"]
    assert explanation.prompt_version == DESCRIBE_PROMPT_VERSION


@pytest.mark.parametrize("body", [_EXPLAIN_200, _DESCRIBE_200], ids=["explain", "describe"])
def test_a_captured_200_keeps_usage_whole_and_its_id_redacted(body):
    """The M7.1 departure's condition: `usage` is not trimmed to the fields the adapter reads."""
    usage = body["usage"]
    assert {"prompt_tokens", "completion_tokens", "total_tokens"} <= set(usage)
    assert isinstance(usage["completion_tokens_details"]["reasoning_tokens"], int)
    assert body["id"] == "chatcmpl-REDACTED"


def test_the_captured_401_holds_each_marker_once_and_the_replay_echoes_this_modules_key():
    """Keeps the leak tests below from passing vacuously over a 401 that echoes nothing."""
    captured = json.dumps(_CAPTURED_401)
    assert captured.count(_KEY_FIRST_8_MARKER) == 1
    assert captured.count(_KEY_LAST_4_MARKER) == 1
    echoed = _ECHOING_401["error"]["message"]
    assert all(fragment in echoed for fragment in _KEY_FRAGMENTS)
    # The substitution really happened: a fixture holding no marker would leave this equal.
    assert echoed != _CAPTURED_401["error"]["message"]


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


# --- describe (M7.3, ADR-0034) ----------------------------------------------------------


# Sentinel member values: none of them may reach the priority request.
_MEMBER_SENTINELS = ("TITLE-SENTINEL", "app-SENTINEL.py", "pkg-SENTINEL", "/path-SENTINEL")


def _members() -> tuple[BriefMember, ...]:
    return (
        BriefMember.from_scalars(
            finding_id="f-1",
            source=ScannerTool.SEMGREP,
            title=_MEMBER_SENTINELS[0],
            file_path=_MEMBER_SENTINELS[1],
            start_line=28,
            end_line=28,
            package=None,
            installed_version=None,
            url=None,
            http_method=None,
            parameter=None,
        ),
        BriefMember.from_scalars(
            finding_id="f-2",
            source=ScannerTool.ZAP,
            title="Path Traversal",
            file_path=None,
            start_line=None,
            end_line=None,
            package=_MEMBER_SENTINELS[2],
            installed_version=None,
            url=_MEMBER_SENTINELS[3],
            http_method="GET",
            parameter="expr",
        ),
    )


async def test_describe_is_one_post_with_the_same_four_body_keys_and_its_own_messages():
    provider, requests = _provider(lambda _: httpx2.Response(200, json=_DESCRIBE_200))

    explanation = await provider.describe(members=_members(), member_count=2)

    assert len(requests) == 1
    body = json.loads(requests[0].content)
    assert set(body) == {"model", "messages", "max_completion_tokens", "store"}
    assert body["store"] is False
    assert body["messages"] == build_describe_messages(_members(), member_count=2)
    assert requests[0].headers["Authorization"] == f"Bearer {_KEY}"
    assert explanation.prompt_version == DESCRIBE_PROMPT_VERSION


async def test_the_priority_request_carries_no_member_byte_and_the_member_request_no_decision():
    """**M5, cross-call separation, over the bodies actually sent** (ADR-0034 decision 3).

    Mutations "pass members into explain" and "render the decision into describe" each fail
    here. **Three requests, describe then explain then describe**, so input carried across calls
    in EITHER direction lands in a body this test reads. The decision is `fix_now` at 6, so its
    bucket, score line, thresholds and three definitions are all distinctive strings.
    """
    provider, requests = _provider(lambda _: httpx2.Response(200, json=_completion()))
    decision = _decision()

    await provider.describe(members=_members(), member_count=2)
    await provider.explain(decision=decision)
    await provider.describe(members=_members(), member_count=2)

    first_describe, explain_body, second_describe = (r.content.decode() for r in requests)
    for sentinel in _MEMBER_SENTINELS:
        assert sentinel in first_describe
        assert sentinel in second_describe
        assert sentinel not in explain_body
    assert decision.priority == "fix_now"
    for decision_text in (
        "fix_now",
        f"score {decision.priority_score}",
        "Thresholds:",
        json.dumps(SEVERITY_DEFINITION)[1:-1],
        json.dumps(EXPOSURE_DEFINITION)[1:-1],
        json.dumps(CORROBORATION_DEFINITION)[1:-1],
    ):
        assert decision_text in explain_body
        assert decision_text not in first_describe
        assert decision_text not in second_describe


async def test_an_echoing_401_on_describe_leaks_no_part_of_the_key(caplog):
    caplog.set_level(logging.DEBUG)
    provider, _ = _provider(lambda _: httpx2.Response(401, json=_ECHOING_401))

    with pytest.raises(ExplanationUnavailable) as exc_info:
        await provider.describe(members=_members(), member_count=2)

    assert str(exc_info.value) == "OpenAI answered HTTP 401"
    assert exc_info.value.__cause__ is None
    assert _leaks(exc_info.value) == []
    assert not [fragment for fragment in (_KEY, *_KEY_FRAGMENTS) if fragment in caplog.text]


async def test_an_unusable_describe_200_is_unavailable():
    provider, _ = _provider(
        lambda _: httpx2.Response(200, json=_completion(base=_DESCRIBE_200, finish_reason="length"))
    )

    with pytest.raises(ExplanationUnavailable, match="finish_reason length"):
        await provider.describe(members=_members(), member_count=2)
