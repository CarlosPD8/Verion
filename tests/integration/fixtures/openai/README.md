# Captured OpenAI Chat Completions responses (M7.3)

Real responses from OpenAI's Chat Completions API, captured once by
`scripts/capture_openai_responses.py` and committed so that `OpenAIExplanationProvider` is tested
against what OpenAI actually sends, not against what this project believes it sends. They replace the
schema-derived bodies `tests/integration/test_openai_explanation_provider.py` used before, which ends
the M7.1 departure (`docs/ROADMAP.md`'s M7.1 entry, ADR-0032's M7.3 capture amendment).

**No test regenerates these files.** Re-capturing is a deliberate act that bills real calls; see
*How to re-capture*.

## Provenance

| | |
|---|---|
| captured | 2026-09-17; the ten-repetition pass ran 17:13:58 to 17:29:49 UTC (`measurements.json`'s `at` fields) |
| requested model | `gpt-5-mini` (`platform/settings.py`'s `openai_model`) |
| returned model | `gpt-5-mini-2025-08-07`, on every body |
| `reasoning_effort` | **not sent**: every figure measures the model's default effort |
| prompt versions | `explain`: `m7.1-1`; `describe`: `m7.3-1` |
| inputs | the committed demo corpus (`semgrep_scan.json`, `trivy_scan.json`, the active `zap_active_scan.json`), the route map extracted from `tests/integration/fixtures/github_tarball/`, through the real mappers, correlation, scoring and `GenerateSecurityBriefUseCase` |
| surfaces | `Flask` (2 members), `/calculate` (7), `urllib3` (12) |
| calls | 10 repetitions of `describe` then `explain` per surface: 59 calls, because one `describe` timed out and its exercise never called `explain` |

| file | what it is |
|---|---|
| `chat_completion_200_explain.json` | the first accepted `explain` 200 of the ten-repetition pass: `Flask`, repetition 1 |
| `chat_completion_200_describe.json` | the first accepted `describe` 200 of that pass: `Flask`, repetition 1 |
| `measurements.json` | one record per call, 59 in all, with no content: time, client wall time, status, `finish_reason`, returned model, token counts, prompt version, member count, rendered prompt size, and the adapter's and M6's verdicts |
| `chat_completion_401.json` | the answer to one `explain` call sent with a throwaway key built at runtime |

The figures derived from `measurements.json` are in ADR-0032's Consequences, with n.

## What was redacted, and what was not

| file | rewritten | from → to |
|---|---|---|
| both 200s | `id` | the completion id → `chatcmpl-REDACTED` |
| `chat_completion_401.json` | the key echo inside `error.message` | the throwaway key's first eight characters → `[REDACTED-KEY-FIRST-8]`, and its last four → `[REDACTED-KEY-LAST-4]`. The asterisks between them are kept. |
| `measurements.json` | **nothing** | — |

**Kept whole**, deliberately: `model`, `usage` (including `completion_tokens_details.reasoning_tokens`),
`choices`, `created`, `object`, `service_tier` and `system_fingerprint`. `usage` is the only measurement
of what a narration costs, so it is not trimmed to the fields the adapter reads.

**Never recorded, so never needing redaction:** request headers (the `Authorization` header is among
them), request bodies, and every response header except `content-type` and `openai-processing-ms`,
which `measurements.json` keeps per call.

### Why the 401 is redacted, and why not by deleting the message

OpenAI's 401 echoes the key it was sent: its first eight characters, a run of asterisks, and its last
four. This was observed in this capture on 2026-09-17, and it confirms **G71**'s second path. The first
`--invalid-key-401` run's leak scan reported `throwaway-key-first-8: 1` and `throwaway-key-last-4: 1`,
and the script aborted to a temp directory outside the repository, writing nothing here. That abort was
correct behaviour. The script now redacts that exact echo, then scans, then writes. The fixture here
comes from the second run.

- **Why redact a key that was never valid.** A body that matches the leak scan's fragment patterns can
  never be written under the rule that nothing is written unless every pattern reports zero. And the
  replay needs a known place to put its own key back.
- **Why markers, not a dropped field or a truncated message.** The shape is what the fixture is for.
  `test_openai_explanation_provider.py` replaces the markers with its own key's fragments, so its leak
  tests run against the real message with a real echo in it, and
  `test_the_captured_401_holds_each_marker_once_and_the_replay_echoes_this_modules_key` keeps them from
  passing over a 401 that echoes nothing.
- **What the kept asterisks still disclose:** the throwaway key's length, 55 characters. That key is
  invalid and not reused, so this is recorded rather than redacted.

### Verified, not assumed

Before writing, the script ran `capture_active_scan.leak_scan`, imported rather than copied, over every
file. It added patterns for any `sk-`-shaped string, any unredacted `chatcmpl-` id, OpenAI organization
and project ids, the real key for the 200 run, and the throwaway key whole and as its first eight and
last four characters for the 401 run. Every committed file reported zero, after redaction. **A zero is
a claim about the pattern list**, not about every possible leak.

Every file is written with `json.dumps(indent=2, ensure_ascii=True)` and LF endings, so it holds no raw
non-ASCII character, and so none of **G80**'s invisible ones.

## What the replay covers, and what it does not

- **Covered:** that the adapter reads the bodies OpenAI sent on 2026-09-17, for `gpt-5-mini` at its
  default effort, for both prompts, and that a real 401 carrying a key echo reaches no exception. The
  log half of that last claim rests on the adapter making no logging call, and on a `caplog`
  assertion, rather than on the capture.
- **Constructed from a capture, not captured:** most unusable-200 cases (`length`, `content_filter`, a
  missing model, blank content) are a captured 200 with a field changed, because OpenAI produced none
  of those during the capture. The refusal case changes two fields, and the empty-choices and
  not-an-object cases are built from scratch, because no capture can express a body that is not a
  completion.
- **Not covered:** what OpenAI sends on any later day, for another model or another reasoning effort.
  Nothing in CI calls OpenAI (**G65**).
- **Not shown by `measurements.json`:** that the model obeyed `describe`'s instructions beyond what M6
  checks. See ADR-0034's M7.3 capture amendment.

## How to re-capture

From the repository root, with `OPENAI_API_KEY` in `infra/.env` (edited in an editor, never typed on a
command line):

```text
uv run python scripts/capture_openai_responses.py --repetitions 1
uv run python scripts/capture_openai_responses.py --repetitions 10
uv run python scripts/capture_openai_responses.py --invalid-key-401
```

Read the one-repetition pass's `describe` paragraphs before running the ten-repetition pass. A
re-capture invalidates ADR-0032's Consequences figures and this README's provenance table: re-derive
both, or record why the old figures still stand.
