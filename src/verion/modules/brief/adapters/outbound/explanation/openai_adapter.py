from typing import Any

import httpx2

from verion.modules.brief.adapters.outbound.explanation.prompt import (
    PROMPT_VERSION,
    build_messages,
)
from verion.modules.brief.domain.exceptions import ExplanationUnavailable
from verion.modules.brief.domain.explanation import Explanation
from verion.modules.risk_engine.ports.explainable_decision import ExplainableDecision

# Base URL and path as openai-python declares them ("https://api.openai.com/v1" and
# "/chat/completions"). A constant rather than a setting: a configurable URL is a place the
# key could be sent somewhere else, and nothing needs one (GitHubAdapter's precedent).
_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"

# UNMEASURED. Nothing in CI calls OpenAI, so this is a placeholder bound, not a measured
# latency. M7.2's `POST /projects/{project_id}/briefs` is the first production call path and
# does not measure it either: measuring needs real calls, and the capture that would provide
# them is not taken, because `_parse` discards `usage` and recording a response whole needs
# tooling and an adapter change M7.2 does not make (ADR-0032's 2026-09-17 amendment).
_TIMEOUT_SECONDS = 30.0

# OpenAI's reasoning guide: "reserve at least 25,000 tokens for reasoning and outputs when
# you start experimenting with these models". gpt-5-mini is a reasoning model and
# `max_completion_tokens` counts reasoning tokens, so a smaller budget can be spent before
# any visible text is written — which surfaces here as `finish_reason == "length"`.
_MAX_COMPLETION_TOKENS = 25_000


class OpenAIExplanationProvider:
    """`ExplanationProviderPort` over OpenAI's Chat Completions API, by raw HTTP (M7.1).

    **The credential goes in exactly one place: the `Authorization: Bearer` header.** Never
    in the URL, never in an exception, never in a log (rules 12 and 13's spirit).

    **Every failure is `ExplanationUnavailable` with a fixed message, raised `from None`,**
    and the response body is never read into it. OpenAI's 401 `error.message` has been
    reported echoing the key's prefix and last four characters (user-pasted, AutoGPT #1422);
    forwarding it, or chaining an exception that holds it, would put part of a credential in
    a traceback. That is **G71**'s second path, closed here and pinned by
    `tests/integration/test_openai_explanation_provider.py`.

    **Request body, exactly four keys.** `store: false` explicitly, because no default is
    documented in openai-python's parameter docstring. No `temperature`: nothing here claims
    the output is deterministic, and per-model support is unverified (ADR-0032).

    `transport` is the test seam, on `GitHubAdapter`'s precedent; production passes `None`.
    What that seam exercises is this class's own code. **OpenAI's real contract is exercised
    by nothing in CI** — the fixtures follow openai-python's types, not a capture (**G65**,
    and the M7.1 departure in `ROADMAP.md`).
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
        body = {
            "model": self._model,
            "messages": build_messages(decision),
            "max_completion_tokens": _MAX_COMPLETION_TOKENS,
            "store": False,
        }
        try:
            async with httpx2.AsyncClient(
                timeout=_TIMEOUT_SECONDS, transport=self._transport
            ) as client:
                response = await client.post(
                    _CHAT_COMPLETIONS_URL,
                    json=body,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
        except httpx2.HTTPError:
            raise ExplanationUnavailable("OpenAI request failed before a response") from None

        if response.status_code != 200:
            raise ExplanationUnavailable(f"OpenAI answered HTTP {response.status_code}") from None

        return _parse(response)


def _parse(response: httpx2.Response) -> Explanation:
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

    return Explanation(text=content.strip(), model=model, prompt_version=PROMPT_VERSION)


_FINISH_REASONS = frozenset({"stop", "length", "tool_calls", "content_filter", "function_call"})
