"""Capture real OpenAI Chat Completions responses for the Explanation Layer (M7.3 commit 3).

Nothing in CI calls OpenAI (**G65**), so `OpenAIExplanationProvider` has been tested only
against fixtures shaped from openai-python's types: the M7.1 departure in `ROADMAP.md`, and
ADR-0034 decision 7. This script takes the capture that ends it, and measures what
`_TIMEOUT_SECONDS` and M6's `MAX_WHAT_HAPPENED_CHARS` were set without.

**Nothing shipped is modified or re-implemented.** Each exercise is one
`GenerateSecurityBriefUseCase.execute`, over the real mappers, the real correlation and
scoring use cases, the real `BriefMember` fill and the real `OpenAIExplanationProvider`. Only
the storage ports are in-memory fakes. So the order (`describe`, then M6's validation, then
`explain`), the member caps and M6's verdict are the application's own. The one addition is
the adapter's existing `transport=` seam, filled with `RecordingTransport` below.

**Inputs.** The committed demo-target corpus: `semgrep_scan.json`, `trivy_scan.json` and the
active `zap_active_scan.json`, with the route map extracted from the committed GitHub
tarball. Three surfaces, whose member counts are checked before any call: `Flask` (2),
`/calculate` (7, `fix_now`) and `urllib3` (12). The scanned content sent is already committed
in this repository.

**The key is read the way the app reads it**: from `infra/.env` through `Settings`, and from
the process environment only if the file has no usable key, never the other way round.
PowerShell's PSReadLine writes typed command lines to a history file, so a key set with
`$env:OPENAI_API_KEY = ...` would be stored in plaintext in the owner's profile. The script
refuses to run on the dev placeholder and prints which source it used, never the value.

**Three modes, and only one writes into the repository:**

- `--repetitions 1`, the first pass. Per surface it prints the member count, the rendered
  prompt size, the `describe` text whole and M6's verdict, with the failing rule named from
  the exception the use case raised. It writes no file.
- `--repetitions 10` makes the capture: 30 exercises, up to 60 calls. It prints tables and no
  narrative text, and writes `chat_completion_200_explain.json`,
  `chat_completion_200_describe.json` and `measurements.json`. `Ctrl+C` stops it early and
  writes what exists, marked as interrupted.
- `--invalid-key-401` sends one `explain` call with a throwaway key and ignores both key
  sources. It writes `chat_completion_401.json`, after redacting the key's echo (below).

**The throwaway key does not imitate OpenAI's `sk-` prefix.** It is built at runtime and
never written into source. A committed `sk-`-shaped string is what secret scanners hunt for,
so push protection could refuse the commit. It would also force the leak scan to tolerate
the very shape it exists to catch.

**What is never recorded:** request headers (the `Authorization` header is among them),
request bodies (the prompt is reproducible from the prompt versions and the corpus), and
every response header except `content-type` and `openai-processing-ms`. A response `id` is
replaced with `chatcmpl-REDACTED`. **The 401 echoes the key it was sent**, as its first eight
characters, a run of asterisks and its last four (observed 2026-09-17, **G71**). That run is
rewritten to `[REDACTED-KEY-FIRST-8]`, the same asterisks, and `[REDACTED-KEY-LAST-4]`, so the
message keeps its shape and a replay test can put its own key's fragments back. The script
generated the key, so it knows the fragments; the field is never dropped or truncated. Bodies are
written with `ensure_ascii=True`, so a fixture holds no raw non-ASCII character, and so none of
G80's invisible ones.

**Before anything is written, every file is leak-scanned**, after redaction, with
`capture_active_scan.leak_scan`, imported and not copied, plus key-shaped patterns. On any hit
nothing is written into the repository: the files go to a new temp directory outside it, and the
script exits 1.

**No call is retried**, on `capture_active_scan.py`'s precedent. A timeout, an unusable 200
or an M6 rejection is recorded as a measurement and the run continues. A non-200 status
stops the run, because it means the calls after it would not capture normal operation.

Run from the repository root:

    uv run python scripts/capture_openai_responses.py --repetitions 1
    uv run python scripts/capture_openai_responses.py --repetitions 10
    uv run python scripts/capture_openai_responses.py --invalid-key-401
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import secrets
import statistics
import sys
import tarfile
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import httpx2  # noqa: E402
from capture_active_scan import leak_scan  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from verion.modules.brief.adapters.outbound.explanation.describe_prompt import (  # noqa: E402
    DESCRIBE_PROMPT_VERSION,
    build_describe_messages,
)
from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (  # noqa: E402
    OpenAIExplanationProvider,
)
from verion.modules.brief.adapters.outbound.explanation.prompt import (  # noqa: E402
    PROMPT_VERSION,
    build_messages,
)
from verion.modules.brief.application.generate_security_brief import (  # noqa: E402
    GenerateSecurityBriefUseCase,
)
from verion.modules.brief.domain.exceptions import (  # noqa: E402
    ExplanationUnavailable,
    WhatHappenedRejected,
)
from verion.modules.correlation.application.candidate_risk_provider import (  # noqa: E402
    CorrelationCandidateRisks,
)
from verion.modules.correlation.application.correlate_findings import (  # noqa: E402
    CorrelateFindingsUseCase,
)
from verion.modules.normalization.domain.mappers.semgrep import map_semgrep_output  # noqa: E402
from verion.modules.normalization.domain.mappers.trivy import map_trivy_output  # noqa: E402
from verion.modules.normalization.domain.mappers.zap import map_zap_output  # noqa: E402
from verion.modules.projects.domain.route_extraction import extract_routes  # noqa: E402
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase  # noqa: E402
from verion.modules.risk_engine.application.explainable_risk_provider import (  # noqa: E402
    ScoredExplainableRisks,
)
from verion.platform.clock import SystemClock  # noqa: E402
from verion.platform.id_generator import UuidIdGenerator  # noqa: E402
from verion.platform.settings import _DEV_ONLY_OPENAI_API_KEY, Settings  # noqa: E402

_FIXTURES_DIR = ROOT / "tests" / "integration" / "fixtures" / "openai"
_ENV_FILE = ROOT / "infra" / ".env"
_PROJECT_ID = "capture-project"
_USER_ID = "capture-user"

# (label, package, url, expected member count), from ADR-0034's measured aggregate.
_SURFACES = (
    ("Flask", "Flask", None, 2),
    ("/calculate", None, "/calculate", 7),
    ("urllib3", "urllib3", None, 12),
)

_KEPT_RESPONSE_HEADERS = ("content-type", "openai-processing-ms")

# Uppercase, so neither marker can contain the lowercase hex a throwaway key's last four are drawn
# from, and a leak scan for those four cannot be satisfied by the marker itself.
KEY_FIRST_8_MARKER = "[REDACTED-KEY-FIRST-8]"
KEY_LAST_4_MARKER = "[REDACTED-KEY-LAST-4]"
_DROPPED_ON_REBUILD = frozenset({"content-encoding", "content-length"})

# M6's rules, recognized from the message `_check_what_happened` raises with. Nothing here
# decides a verdict: the use case already raised, and this only names which check it was.
_M6_RULES = (
    ("control or format character", "(i) control or format character"),
    ("longer than", "(ii) length"),
    ("priority bucket", "(iii) a fix_now the members did not supply"),
)


class CaptureAborted(Exception):
    pass


def _log(message: str) -> None:
    print(f"[capture] {message}", flush=True)


# --- the key and the model, file first ----------------------------------------------------


class _FromEnvFile(Settings):
    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        return (init_settings, dotenv_settings)


class _FromEnvironment(Settings):
    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        return (init_settings, env_settings)


def _load(settings_class: type[Settings], **kwargs: Any) -> Settings:
    try:
        return settings_class(**kwargs)
    except ValidationError:
        # Not printed: pydantic's message can echo other secrets' values (G71).
        raise CaptureAborted(
            "Settings refused to load; its error is not printed because it can carry "
            "secret values (G71). Check APP_ENV and the placeholders in infra/.env."
        ) from None


def _usable(key: str) -> bool:
    return bool(key.strip()) and key != _DEV_ONLY_OPENAI_API_KEY


def resolve_key_and_model() -> tuple[str, str]:
    from_file = _load(_FromEnvFile, _env_file=_ENV_FILE)
    from_environment = _load(_FromEnvironment, _env_file=None)
    if _usable(from_file.openai_api_key):
        _log("OPENAI_API_KEY source: infra/.env, through Settings")
        if _usable(from_environment.openai_api_key):
            _log("the process environment also sets OPENAI_API_KEY; it is ignored")
        return from_file.openai_api_key, from_file.openai_model
    if _usable(from_environment.openai_api_key):
        _log("OPENAI_API_KEY source: process environment (fallback; infra/.env has no usable key)")
        return from_environment.openai_api_key, from_environment.openai_model
    raise CaptureAborted(
        "OPENAI_API_KEY resolves to nothing but the dev placeholder in both infra/.env and the "
        "environment. Put the key in infra/.env with an editor, not on a command line."
    )


def resolve_model_only() -> str:
    return _load(_FromEnvFile, _env_file=_ENV_FILE).openai_model


# --- the recording transport ---------------------------------------------------------------


class RecordingTransport(httpx2.AsyncBaseTransport):
    """Forward each request over a fresh `AsyncHTTPTransport`, and record the response.

    **A fresh inner transport per request** matches production, where the adapter passes
    `transport=None` and every call opens its own client, so the measured wall time includes
    the connection it really pays for. It also means the adapter's `AsyncClient` closing this
    wrapper cannot close a pool a later call needs.

    The response is rebuilt from the decoded body **without `content-encoding` and
    `content-length`**. Keeping them makes the adapter decode an already-decoded body, and
    it reports `ExplanationUnavailable` while the recorder holds a good response.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.context: dict[str, Any] = {}

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        record: dict[str, Any] = {**self.context, "at": SystemClock().now().isoformat()}
        self.calls.append(record)
        inner = httpx2.AsyncHTTPTransport()
        started = time.perf_counter()
        try:
            response = await inner.handle_async_request(request)
            body = await response.aread()
        except asyncio.CancelledError:
            record.update(wall_s=time.perf_counter() - started, timed_out=False, error="cancelled")
            raise
        except httpx2.TimeoutException:
            record.update(wall_s=time.perf_counter() - started, timed_out=True, error="timeout")
            raise
        except httpx2.HTTPError as exc:
            record.update(
                wall_s=time.perf_counter() - started, timed_out=False, error=type(exc).__name__
            )
            raise
        finally:
            await inner.aclose()

        record.update(wall_s=time.perf_counter() - started, timed_out=False, error=None)
        record["status"] = response.status_code
        record["response_headers"] = {
            name: response.headers[name]
            for name in _KEPT_RESPONSE_HEADERS
            if name in response.headers
        }
        record["_body"] = body
        _read_usage(record, body)
        headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in _DROPPED_ON_REBUILD
        ]
        return httpx2.Response(response.status_code, headers=headers, content=body)


def _read_usage(record: dict[str, Any], body: bytes) -> None:
    try:
        payload = json.loads(body)
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        record["finish_reason"] = choices[0].get("finish_reason")
    record["returned_model"] = payload.get("model")
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    details = usage.get("completion_tokens_details")
    record["prompt_tokens"] = usage.get("prompt_tokens")
    record["completion_tokens"] = usage.get("completion_tokens")
    record["reasoning_tokens"] = (
        details.get("reasoning_tokens") if isinstance(details, dict) else None
    )


class ObservedProvider:
    """`ExplanationProviderPort` around the real adapter. It observes and changes nothing sent.

    It labels each call for the recorder, measures the rendered prompt with the adapter's own
    message builders, and keeps the last `describe` result so the one-repetition pass can
    print it.
    """

    def __init__(self, inner: OpenAIExplanationProvider, recorder: RecordingTransport) -> None:
        self._inner = inner
        self._recorder = recorder
        self.last_describe_text: str | None = None
        self.surface = ""
        self.repetition = 0

    async def describe(self, *, members, member_count):
        messages = build_describe_messages(members, member_count=member_count)
        return await self._observe(
            "describe",
            DESCRIBE_PROMPT_VERSION,
            messages,
            self._inner.describe(members=members, member_count=member_count),
            member_count=member_count,
            members_rendered=len(members),
        )

    async def explain(self, *, decision):
        return await self._observe(
            "explain",
            PROMPT_VERSION,
            build_messages(decision),
            self._inner.explain(decision=decision),
        )

    async def _observe(self, kind, prompt_version, messages, call, **extra):
        self._recorder.context = {
            "surface": self.surface,
            "repetition": self.repetition,
            "kind": kind,
            "prompt_version": prompt_version,
            "rendered_prompt_chars": sum(len(message["content"]) for message in messages),
            **extra,
        }
        before = len(self._recorder.calls)
        try:
            result = await call
        except ExplanationUnavailable as exc:
            self._annotate(before, adapter=f"unavailable: {exc}")
            raise
        self._annotate(before, adapter="accepted")
        if kind == "describe":
            self.last_describe_text = result.text
        return result

    def _annotate(self, before: int, **values: Any) -> None:
        if len(self._recorder.calls) == before:
            self._recorder.calls.append({**self._recorder.context, "error": "no request sent"})
        self._recorder.calls[-1].update(values)


# --- the corpus, through the real pipeline -------------------------------------------------


class _Findings:
    def __init__(self, findings: list[Any]) -> None:
        self._findings = findings
        self._by_id = {finding.id: finding for finding in findings}

    async def get_by_project_id(self, project_id: str) -> list[Any]:
        return [finding for finding in self._findings if finding.project_id == project_id]

    async def get_by_id(self, *, project_id: str, finding_id: str) -> Any:
        finding = self._by_id.get(finding_id)
        return finding if finding is not None and finding.project_id == project_id else None


class _Access:
    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        return True


class _Serving:
    async def url_serves_scanned_tree(self, *, project_id: str) -> bool:
        return True


class _RouteMaps:
    def __init__(self, route_map: Any) -> None:
        self._route_map = route_map

    async def route_map_for(self, *, project_id: str) -> Any:
        return self._route_map


class _Briefs:
    def __init__(self) -> None:
        self.added: list[Any] = []

    async def add(self, brief: Any) -> None:
        self.added.append(brief)


def _demo_route_map() -> Any:
    archive = ROOT / "tests/integration/fixtures/github_tarball/verion-demo-target-c68caa7.tar.gz"
    files: dict[str, str] = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if member.isreg() and member.name.endswith(".py") and "/" in member.name:
                handle = tar.extractfile(member)
                if handle is not None:
                    files[member.name.split("/", 1)[1]] = handle.read().decode("utf-8")
    route_map = extract_routes(framework="flask", files=files)
    if route_map.paths_serving(file_path="app.py", line=28) != ("/calculate",):
        raise CaptureAborted("the demo route map does not serve app.py line 28 from /calculate")
    return route_map


def _corpus() -> list[Any]:
    ids, clock = UuidIdGenerator(), SystemClock()
    sources = (
        ("tests/fixtures/scanners/semgrep_scan.json", map_semgrep_output),
        ("tests/fixtures/scanners/trivy_scan.json", map_trivy_output),
        ("tests/integration/fixtures/active_scan/zap_active_scan.json", map_zap_output),
    )
    findings: list[Any] = []
    for path, mapper in sources:
        findings.extend(
            mapper(
                project_id=_PROJECT_ID,
                scan_id="capture-scan",
                raw_output=(ROOT / path).read_text(encoding="utf-8"),
                id_generator=ids,
                clock=clock,
            )
        )
    return findings


@dataclass(frozen=True)
class Surface:
    label: str
    finding_ids: tuple[str, ...]


async def _build(
    api_key: str, model: str
) -> tuple[Any, ObservedProvider, RecordingTransport, list[Surface], Any]:
    findings = _Findings(_corpus())
    compute = ComputeRiskUseCase(
        CorrelationCandidateRisks(
            CorrelateFindingsUseCase(_Access(), findings, _Serving(), _RouteMaps(_demo_route_map()))
        ),
        findings,
    )
    scored = await compute.execute(project_id=_PROJECT_ID, user_id=_USER_ID)
    surfaces: list[Surface] = []
    for label, package, url, expected in _SURFACES:
        matches = [s for s in scored if s.package == package and s.url == url]
        if len(matches) != 1 or len(matches[0].finding_ids) != expected:
            found = [len(s.finding_ids) for s in matches]
            raise CaptureAborted(
                f"surface {label}: expected one surface of {expected} members, found {found}"
            )
        surfaces.append(Surface(label=label, finding_ids=matches[0].finding_ids))

    recorder = RecordingTransport()
    provider = ObservedProvider(
        OpenAIExplanationProvider(api_key=api_key, model=model, transport=recorder), recorder
    )
    risks = ScoredExplainableRisks(compute)
    use_case = GenerateSecurityBriefUseCase(
        risks, findings, provider, _Briefs(), SystemClock(), UuidIdGenerator()
    )
    return use_case, provider, recorder, surfaces, risks


# --- reporting -----------------------------------------------------------------------------


def _m6_rule(exc: WhatHappenedRejected) -> str:
    message = str(exc)
    for needle, label in _M6_RULES:
        if needle in message:
            return label
    return f"unrecognized rule, message: {message}"


def _numbers(calls: list[dict[str, Any]], field: str) -> str:
    values = [call[field] for call in calls if isinstance(call.get(field), (int, float))]
    if not values:
        return "-/-"
    median = statistics.median(values)
    shown = f"{median:.2f}" if field == "wall_s" else f"{median:g}"
    top = f"{max(values):.2f}" if field == "wall_s" else f"{max(values):g}"
    return f"{shown}/{top}"


def _row(label: str, calls: list[dict[str, Any]]) -> str:
    finish = dict(Counter(str(call.get("finish_reason")) for call in calls))
    models = sorted({str(call.get("returned_model")) for call in calls})
    rejected = dict(
        Counter(call["m6"] for call in calls if str(call.get("m6", "")).startswith("("))
    )
    timeouts = sum(1 for call in calls if call.get("timed_out"))
    return (
        f"{label:<28} n={len(calls):<3} wall_s={_numbers(calls, 'wall_s'):<13} "
        f"prompt={_numbers(calls, 'prompt_tokens'):<11} "
        f"completion={_numbers(calls, 'completion_tokens'):<11} "
        f"reasoning={_numbers(calls, 'reasoning_tokens'):<11} "
        f"finish={finish} models={models} m6_rejections={rejected or 0} timeouts={timeouts}"
    )


def _print_tables(calls: list[dict[str, Any]]) -> None:
    _log("--- per cell (kind, surface); numbers are median/max ---")
    for kind in ("describe", "explain"):
        for label, *_ in _SURFACES:
            cell = [c for c in calls if c.get("kind") == kind and c.get("surface") == label]
            if cell:
                print(_row(f"{kind} {label}", cell))
    _log("--- pooled ---")
    for kind in ("describe", "explain"):
        pooled = [c for c in calls if c.get("kind") == kind]
        if pooled:
            print(_row(f"{kind} (all surfaces)", pooled))
    print(_row("all calls", calls))


def _cumulative(calls: list[dict[str, Any]]) -> str:
    def total(field: str) -> int:
        return sum(call[field] for call in calls if isinstance(call.get(field), int))

    return (
        f"cumulative tokens: prompt={total('prompt_tokens')} "
        f"completion={total('completion_tokens')} reasoning={total('reasoning_tokens')} "
        f"over {len(calls)} calls"
    )


# --- writing, behind the leak scan ---------------------------------------------------------


def _json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


def _redacted_body(body: bytes) -> str:
    payload = json.loads(body)
    if isinstance(payload, dict) and "id" in payload:
        payload["id"] = "chatcmpl-REDACTED"
    return _json_text(payload)


def _key_patterns(real_key: str | None, throwaway: str | None) -> dict[str, str]:
    patterns = {
        "sk-shaped-key": r"sk-[A-Za-z0-9_-]{8,}",
        "unredacted-completion-id": r"chatcmpl-(?!REDACTED\b)[A-Za-z0-9]",
        "openai-organization-id": r"\borg-[A-Za-z0-9]{8,}",
        "openai-project-id": r"\bproj_[A-Za-z0-9]{8,}",
    }
    if real_key:
        patterns["real-key"] = re.escape(real_key)
    if throwaway:
        patterns["throwaway-key"] = re.escape(throwaway)
        patterns["throwaway-key-first-8"] = re.escape(throwaway[:8])
        patterns["throwaway-key-last-4"] = re.escape(throwaway[-4:])
    return patterns


def _write_behind_leak_scan(files: dict[str, str], patterns: dict[str, str]) -> None:
    report = leak_scan(files, patterns)
    _log("--- leak scan (a zero is a claim about the pattern list) ---")
    print(json.dumps(report, indent=2))
    hits = {name: {k: v for k, v in counts.items() if v} for name, counts in report.items()}
    hits = {name: counts for name, counts in hits.items() if counts}
    if hits:
        out_dir = Path(tempfile.mkdtemp(prefix="verion-openai-capture-")).resolve()
        if out_dir == ROOT or ROOT in out_dir.parents:
            raise CaptureAborted(f"temp directory {out_dir} is inside the repository")
        for name, text in files.items():
            (out_dir / name).write_text(text, encoding="utf-8", newline="\n")
        raise CaptureAborted(
            f"leak scan hits {hits}; nothing written into the repository, files are in {out_dir}"
        )
    _FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (_FIXTURES_DIR / name).write_text(text, encoding="utf-8", newline="\n")
        _log(f"wrote {name} into the fixtures directory")


# --- the modes -----------------------------------------------------------------------------


async def run_repetitions(repetitions: int) -> None:
    api_key, model = resolve_key_and_model()
    use_case, provider, recorder, surfaces, _ = await _build(api_key, model)
    _log(f"requested model: {model}; reasoning_effort: not sent; repetitions: {repetitions}")
    total = repetitions * len(surfaces)
    done = 0
    interrupted = False
    try:
        for repetition in range(1, repetitions + 1):
            for surface in surfaces:
                provider.surface, provider.repetition = surface.label, repetition
                provider.last_describe_text = None
                before = len(recorder.calls)
                verdict = "accepted"
                try:
                    await use_case.execute(
                        project_id=_PROJECT_ID, user_id=_USER_ID, finding_ids=surface.finding_ids
                    )
                except WhatHappenedRejected as exc:
                    verdict = f"rejected: {_m6_rule(exc)}"
                    _mark_describe(recorder.calls[before:], _m6_rule(exc))
                except ExplanationUnavailable as exc:
                    verdict = f"not reached: the adapter said '{exc}'"
                else:
                    _mark_describe(recorder.calls[before:], "accepted")
                done += 1
                exercise = recorder.calls[before:]
                _log(f"exercise {done}/{total} {surface.label}: {_cumulative(recorder.calls)}")
                if repetitions == 1:
                    _print_narrative(surface, exercise, provider.last_describe_text, verdict)
                bad = [c.get("status") for c in exercise if c.get("status") not in (None, 200)]
                if bad:
                    raise CaptureAborted(f"OpenAI answered HTTP {bad[0]}; the run stops here")
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Under `asyncio.run`, Ctrl+C arrives in this task as a cancellation.
        interrupted = True
        _log(f"interrupted after {done} of {total} exercises")
    finally:
        _print_tables(recorder.calls)

    if repetitions == 1:
        return
    files = _capture_files(recorder.calls, model, repetitions, done, interrupted)
    _write_behind_leak_scan(files, _key_patterns(api_key, None))


def _mark_describe(calls: list[dict[str, Any]], m6: str) -> None:
    for call in calls:
        if call.get("kind") == "describe" and call.get("adapter") == "accepted":
            call["m6"] = m6


def _print_narrative(
    surface: Surface, exercise: list[dict[str, Any]], text: str | None, verdict: str
) -> None:
    describe = next((c for c in exercise if c.get("kind") == "describe"), {})
    print()
    print(f"===== {surface.label} =====")
    count, rendered = describe.get("member_count"), describe.get("members_rendered")
    print(f"member count: {count} (rendered {rendered})")
    print(f"rendered describe prompt: {describe.get('rendered_prompt_chars')} chars")
    print(f"describe finish_reason: {describe.get('finish_reason')}")
    print("describe text, whole:")
    print(text if text is not None else f"(no text: {describe.get('adapter')})")
    print(f"M6: {verdict}")
    print()


def _capture_files(
    calls: list[dict[str, Any]], model: str, repetitions: int, done: int, interrupted: bool
) -> dict[str, str]:
    files: dict[str, str] = {}
    for kind in ("explain", "describe"):
        first = next(
            (
                c
                for c in calls
                if c.get("kind") == kind
                and c.get("status") == 200
                and c.get("adapter") == "accepted"
            ),
            None,
        )
        if first is None:
            raise CaptureAborted(f"no accepted 200 for {kind}; there is no body to keep")
        files[f"chat_completion_200_{kind}.json"] = _redacted_body(first["_body"])
    measurements = {
        "captured_by": "scripts/capture_openai_responses.py",
        "requested_model": model,
        "reasoning_effort": None,
        "prompt_versions": {"explain": PROMPT_VERSION, "describe": DESCRIBE_PROMPT_VERSION},
        "repetitions": repetitions,
        "exercises_completed": done,
        "interrupted": interrupted,
        "surfaces": [label for label, *_ in _SURFACES],
        "calls": [{k: v for k, v in call.items() if k != "_body"} for call in calls],
    }
    files["measurements.json"] = _json_text(measurements)
    return files


def redact_key_echo(text: str, key: str) -> tuple[str, int]:
    """Rewrite each `<first 8>***<last 4>` echo of `key` to the markers, keeping the asterisks.

    Only that exact run is rewritten. An echo in any other form is left alone, and the leak scan
    that follows reports it, so the capture aborts rather than committing a partial redaction.
    Built with `re.escape` and a character class, so the pattern holds no escape sequence.
    """
    echo = re.compile(re.escape(key[:8]) + "([*]+)" + re.escape(key[-4:]))
    return echo.subn(lambda match: KEY_FIRST_8_MARKER + match.group(1) + KEY_LAST_4_MARKER, text)


async def run_invalid_key_401() -> None:
    # Built at runtime and never written into source; NOT OpenAI's key prefix (see docstring).
    throwaway = "verion-capture-invalid-" + secrets.token_hex(16)
    model = resolve_model_only()
    _log("key: a throwaway built at runtime; infra/.env and the environment are ignored")
    _, provider, recorder, surfaces, risks = await _build(throwaway, model)
    risk = await risks.explainable_risk(
        project_id=_PROJECT_ID, user_id=_USER_ID, finding_ids=surfaces[0].finding_ids
    )
    provider.surface, provider.repetition = surfaces[0].label, 1
    try:
        await provider.explain(decision=risk.decision)
    except ExplanationUnavailable as exc:
        message = str(exc)
        _log(f"adapter raised ExplanationUnavailable: '{message}'")
        fragments = (throwaway, throwaway[:8], throwaway[-4:])
        _log(f"exception message carries a key fragment: {any(f in message for f in fragments)}")
    else:
        raise CaptureAborted("a throwaway key was accepted; nothing is written")
    call = recorder.calls[-1]
    _log(f"status: {call.get('status')}; wall_s: {call.get('wall_s', 0):.2f}")
    if call.get("status") != 401:
        raise CaptureAborted(f"expected HTTP 401, got {call.get('status')}; nothing is written")
    body, redacted = redact_key_echo(_json_text(json.loads(call["_body"])), throwaway)
    _log(f"key echoes redacted in the 401 body: {redacted}")
    _write_behind_leak_scan({"chat_completion_401.json": body}, _key_patterns(None, throwaway))


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture real OpenAI responses (M7.3, G65).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repetitions", type=int, choices=(1, 10))
    mode.add_argument("--invalid-key-401", action="store_true")
    args = parser.parse_args()
    try:
        if args.invalid_key_401:
            asyncio.run(run_invalid_key_401())
        else:
            asyncio.run(run_repetitions(args.repetitions))
    except CaptureAborted as exc:
        _log(f"ABORTED: {exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
