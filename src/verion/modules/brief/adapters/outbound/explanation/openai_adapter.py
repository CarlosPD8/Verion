import asyncio
from typing import Any

import httpx2

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (
    DESCRIBE_PROMPT_VERSION,
    build_describe_messages,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import (
    PROMPT_VERSION,
    build_messages,
)
from verion.modules.brief.domain.brief_member import BriefMember
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision

# Base URL and path as openai-python declares them ("https://api.openai.com/v1" and
# "/chat/completions"). A constant rather than a setting: a configurable URL is a place the
# key could be sent somewhere else, and nothing needs one (GitHubAdapter's precedent).
_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"

# MEASURED ONCE, and deliberately NOT moved. M7.3's capture sent 59 real calls with no
# `reasoning_effort` (figures and n in ADR-0032's Consequences). One, a `describe`, hit this bound
# at 30.32 s of client wall time; the tail past it is unmeasured, so any larger value would be
# invented. A synchronous bound answers to what a user will wait for, and by that 30 s is already
# too long. So the exceedance is evidence that generation does not belong in a request — the
# argument `_CALL_DEADLINE_SECONDS` below carries forward, and where the handoff to the
# asynchronous work now sits (ADR-0032's M7.3 capture amendment).
#
# **This is the PER-OPERATION value.** httpx applies it per phase, not to the whole call, and
# within the read phase it applies per read, so a response arriving in chunks under 30 s apart
# never trips it (ADR-0032's 2026-09-18 amendment). What bounds the call is the deadline below.
_TIMEOUT_SECONDS = 30.0

# THE CALL DEADLINE, one per port call, on `GitHubAdapter._ARCHIVE_DEADLINE_SECONDS`'s precedent:
# "httpx's timeout is per operation, so a server trickling one byte every nine seconds never trips
# it; this does." `_complete` is the one method both `explain` and `describe` pass through, so the
# deadline lands once and bounds each call — never the pair, which this adapter cannot see, and
# which at the measured per-Brief wall times no single 30 s deadline could cover anyway.
#
# **It is 30 s because that is what `_TIMEOUT_SECONDS` already declared, not because 30 s was
# chosen for a call.** M8.6 commit 1 changes which quantity 30 s measures and prices nothing. The
# generous bound belongs to whatever makes generation asynchronous (**G73**), as one decision with
# it, and THIS is the value that work re-decides. The precedent's deadline is six times its
# per-operation value; that ratio is that work's to set too.
#
# At today's equal values the per-operation bound above can fire first only when one read consumes
# the whole budget, where both expire together. That race is confined to which message this
# adapter raises: both are `ExplanationUnavailable`, which `brief`'s router maps to one 502 with a
# fixed detail, so no caller can tell which fired.
_CALL_DEADLINE_SECONDS = 30.0

# OpenAI's reasoning guide: "reserve at least 25,000 tokens for reasoning and outputs when
# you start experimenting with these models". gpt-5-mini is a reasoning model and
# `max_completion_tokens` counts reasoning tokens, so a smaller budget can be spent before
# any visible text is written — which surfaces here as `finish_reason == "length"`.
_MAX_COMPLETION_TOKENS = 25_000


class OpenAIExplanationProvider:
    """`ExplanationProviderPort` over OpenAI's Chat Completions API, by raw HTTP (M7.1, M7.3).

    **`explain` and `describe` are two requests through one path**, differing only in their
    messages and prompt version. Everything below holds for both.

    **The credential goes in exactly one place: the `Authorization: Bearer` header.** Never
    in the URL, never in an exception, never in a log (rules 12 and 13's spirit).

    **Every failure is `ExplanationUnavailable` with a fixed message, raised `from None`,**
    and the response body is never read into it. OpenAI's 401 `error.message` echoes the
    key's first eight and last four characters: reported in a user-pasted body (AutoGPT
    #1422), and observed by M7.3's capture on 2026-09-17, when this class held. Forwarding
    it, or chaining an exception that holds it, would put part of a credential in a traceback.
    That is **G71**'s second path, closed here and pinned by
    `tests/integration/test_openai_explanation_provider.py`.

    **Request body, exactly four keys.** `store: false` explicitly, because no default is
    documented in openai-python's parameter docstring. No `temperature`: nothing here claims
    the output is deterministic, and per-model support is unverified (ADR-0032).

    `transport` is the test seam, on `GitHubAdapter`'s precedent; production passes `None`.
    What that seam exercises is this class's own code, against responses captured from OpenAI
    on 2026-09-17 (M7.3), which ended the M7.1 departure in `ROADMAP.md`. **No test in CI
    reaches OpenAI**, so what it sends on any later day is unexercised (**G65**).
    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._transport = transport

    async def explain(self, *, decision: ExplainableDecision) -> Explanation:
        return await self._complete(build_messages(decision), prompt_version=PROMPT_VERSION)

    async def describe(self, *, members: tuple[BriefMember, ...], member_count: int) -> Explanation:
        # A separate request with its own messages: the decision never reaches this prompt, and
        # these members never reach `explain`'s (ADR-0034 decision 3).
        return await self._complete(
            build_describe_messages(members, member_count=member_count),
            prompt_version=DESCRIBE_PROMPT_VERSION,
        )

    async def _complete(
        self, messages: list[dict[str, str]], *, prompt_version: str
    ) -> Explanation:
        body = {
            "model": self._model,
            "messages": messages,
            "max_completion_tokens": _MAX_COMPLETION_TOKENS,
            "store": False,
        }
        try:
            # The deadline is OUTSIDE the client, so it covers connecting, sending, the wait and
            # the body, which is the whole of what `_TIMEOUT_SECONDS` bounds only phase by phase.
            async with asyncio.timeout(_CALL_DEADLINE_SECONDS):
                async with httpx2.AsyncClient(
                    timeout=_TIMEOUT_SECONDS, transport=self._transport
                ) as client:
                    response = await client.post(
                        _CHAT_COMPLETIONS_URL,
                        json=body,
                        headers={"Authorization": f"Bearer {self._api_key}"},
                    )
        # Measured against the installed httpx2 2.12.0 on CPython 3.12.14, not assumed: these two
        # are disjoint in BOTH directions, so their order is immaterial — `TimeoutError` descends
        # from `OSError`, `httpx2.HTTPError` straight from `Exception`. Outward-in by convention.
        #
        # `asyncio.TimeoutError` IS the builtin, so this clause is the whole of what the deadline
        # above can raise; `socket.timeout` IS the builtin too, so a socket-level timeout escaping
        # httpcore2's wrapping lands here as well, which is the same translation. A cancelled
        # request still raises `CancelledError`, a BaseException, so this cannot swallow one.
        #
        # Without this clause the deadline escapes every `except` in `brief`'s router and the
        # request answers 500 where ADR-0033 decision 9 fixes this failure at 502 (ADR-0032's
        # M8.6 amendment). It is the reason the bound is not a one-line change.
        except TimeoutError:
            raise ExplanationUnavailable("OpenAI did not answer within the deadline") from None
        except httpx2.HTTPError:
            raise ExplanationUnavailable("OpenAI request failed before a response") from None

        if response.status_code != 200:
            raise ExplanationUnavailable(f"OpenAI answered HTTP {response.status_code}") from None

        return _parse(response, prompt_version=prompt_version)


def _parse(response: httpx2.Response, *, prompt_version: str) -> Explanation:
    """Read the one field set this adapter relies on, trusting none of it.

    Shapes from openai-python's `ChatCompletion`: `choices[].message.content: str | None`,
    `choices[].message.refusal: str | None`, `choices[].finish_reason` in
    `stop`/`length`/`tool_calls`/`content_filter`/`function_call`, and `model: str`.
    """
    try:
        payload: Any = response.json()
    except ValueError:
        raise ExplanationUnavailable("OpenAI answered with a body that is not JSON") from None

    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ExplanationUnavailable("OpenAI answered with no choices") from None

    choice = choices[0]
    finish_reason = choice.get("finish_reason")
    if finish_reason != "stop":
        # `finish_reason` is one of a closed vocabulary; anything else is not echoed. The
        # `isinstance` comes first because a non-string could be unhashable, and a TypeError
        # from the set lookup would escape the port as something other than this exception.
        known = isinstance(finish_reason, str) and finish_reason in _FINISH_REASONS
        shown = finish_reason if known else "unrecognized"
        raise ExplanationUnavailable(f"OpenAI stopped with finish_reason {shown}") from None

    message = choice.get("message")
    if not isinstance(message, dict):
        raise ExplanationUnavailable("OpenAI answered with no message") from None
    if message.get("refusal") is not None:
        raise ExplanationUnavailable("OpenAI refused to answer") from None

    content = message.get("content")
    model = payload.get("model")
    if not isinstance(content, str) or not content.strip():
        raise ExplanationUnavailable("OpenAI answered with empty content") from None
    if not isinstance(model, str) or not model:
        raise ExplanationUnavailable("OpenAI answered without naming its model") from None

    return Explanation(text=content.strip(), model=model, prompt_version=prompt_version)


_FINISH_REASONS = frozenset({"stop", "length", "tool_calls", "content_filter", "function_call"})
