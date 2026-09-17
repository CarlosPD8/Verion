# ADR-0032 — The Explanation Layer's port, its OpenAI adapter, and where the prompt's input ends

## Status

Accepted — 2026-09-17 (M7.1). Written and accepted before any of M7.1's code is committed, on
ADR-0030's precedent.

## Context

M7.1's bullet reads *"structured `RiskReasoning` in, narrative text out"*. Three facts in the
tree make that sentence unbuildable as written, and they order the decisions below.

- **The port's parameter cannot be annotated.** `cross-module-brief` forbids
  `verion.modules.risk_engine.domain`, where `RiskReasoning` and `Signal` live, and
  `risk_engine/ports/` held one empty `__init__.py`. `ComputeRiskUseCase` takes `MatchGroup`
  by inference off a port's *return* annotation; a `Protocol` method's *parameter* has to be
  named in the port module itself, so that escape does not transfer.
- **`RiskReasoning` alone cannot explain a bucket.** Its fields are `severity`, `exposure` and
  `corroboration`. The bucket, the score and the thresholds sit on `ScoredSurface` and in
  `FIX_NOW_AT`/`PLAN_AT`. A narrator given only the reasoning would have to sum and bucket —
  the LLM deciding a priority, which rule 6 forbids.
- **A scored Risk carries no confidence** (**G63**), and tests assert the absence.

The provider is **OpenAI**, decided by the project owner. Verified 2026-09-17 against primary
sources — openai-python's `_client.py`, `types/chat/*` and `resources/chat/completions`, and
OpenAI's model page, reasoning guide, text guide and error-codes guide: the endpoint is
`POST https://api.openai.com/v1/chat/completions` with `Authorization: Bearer`; the model id
`gpt-5-mini` exists (default snapshot `gpt-5-mini-2025-08-07`) and lists
`v1/chat/completions` as supported; `max_tokens` is deprecated for `max_completion_tokens`,
which counts reasoning tokens; `developer` messages *"replace the previous `system` messages"*
for o1 and newer. **Unverified**: `store`'s default, whether `gpt-5-mini` accepts
`temperature`, and whether it accepts the `developer` role in particular — no model page says.

**A 401 from OpenAI has been reported echoing part of the key** — reported, not captured by this
project; "captured" is reserved below for a response this project records itself. A user-pasted body in
AutoGPT issue #1422 (2023) reads *"Incorrect API key provided: sk-…\*\*\*\*…"*, showing a
prefix and the last four characters, and OpenAI's Help Center tells a reader to compare their
key *"with the API key shown in the error message"* (search snippet; the article itself
returned 403). Today's format, and project keys' format, are unverified.

## Decision

### 1. `risk_engine` publishes the carrier; it is filled inside `risk_engine`

`risk_engine/ports/explainable_decision.py` declares two frozen, keyword-only dataclasses:

- `ExplainableSignal` — `name`, `value`, `produced_by`, `note`, carrying `Signal`'s own
  annotations field for field, plus `definition: str`;
- `ExplainableDecision` — `priority: str`, `priority_score`, `fix_now_at`, `plan_at`, and the
  three signals.

Filled by `explainable_decision(surface: ScoredSurface)` in `risk_engine/application/`.
**Declared in `ports/` so `brief` can name it** — `CandidateRiskAccessDenied`'s shape in
`correlation/ports/`. **Not a re-export of `RiskReasoning` through `ports/`**: legal to
`lint-imports` and `mypy`, against rule 3's intent, and with no precedent in `src/`. **Not a
carrier in `brief`**: that copies `Signal`'s four fields three times in another module (G67's
pattern one module over) and puts the fill site where `mypy` sees only one end (G33's subject).
Here both ends of the copy are in `risk_engine`.

A test derives the shared fields from `dataclasses.fields(Signal)` and asserts
`ExplainableDecision`'s field set **equals** its enumeration. **The port that delivers the
carrier to `brief` is M7.2's**: what it returns must also carry a Risk address, which is
**G68**'s decision.

### 2. The prompt's input is the decision and its working, and nothing scanned. M7.1 ends here

The model sees the bucket, the score, the thresholds, and each signal's value, `note`,
`definition` and — for corroboration only — the count of `produced_by`, which is the number of
distinct scanners. All of it is Verion-computed. All of it but the definitions is already public on
`/scored-risks` (ADR-0030 decision 3); the definitions are new fixed strings owned by `scoring.py`
(decision 4) and carry no project data.

**Absent by construction: `project_id`, `package`, `url`, `finding_ids`, and every `Finding`
field.** `package` and `url` are scanned content — a Trivy `PkgName`, a ZAP path, a route
derived from scanned source — and scanned content in a prompt is M7.3's scope. **So nothing
from a scanned repository reaches OpenAI through M7.1.**

**The cost, stated plainly.** FR-8's *what happened*, *evidence sources*, *recommended action*,
*estimated effort* and *confidence* cannot be produced from this input. The narrative explains
the bucket and nothing else — which is what ADR-0004 says the LLM's job is. The rest belongs to
M7.2 and M7.3, and M7.2's bullet carries the list.

### 3. No confidence is emitted, and the absence is recorded rather than decided around

Emitting one reaches a third module either way — a grouping confidence needs provenance out of
`correlation`, whose `MatchGroup` carries only `key` and `finding_ids`; an evidence confidence
needs `Finding.confidence`, which ADR-0005 decision 4 declined, and a migration. That is a
milestone, not an issue. **G63** stays open, re-pointed at M7.2, whose `SecurityBrief` design
carries a `confidence` field. **ADR-0003's 2026-09-16 amendment is corrected in this commit**:
it says ADR-0005 satisfies *"a bucket, a confidence, a `RiskReasoning`"*, which is false.

### 4. What each signal means is `risk_engine`'s text; the prompt forwards it

`scoring.py` declares `SEVERITY_DEFINITION`, `EXPOSURE_DEFINITION` and
`CORROBORATION_DEFINITION` beside the functions that compute them, each stating its signal's
limit. `CORROBORATION_DEFINITION` says the signal *"does not mean the scanners agree, confirm
each other, or found the same vulnerability"* — `_corroboration_signal`'s own rule (**G62**),
in the words a narrator receives. This is needed rather than decorative: `Signal.note` is
`None` whenever a signal fires, so without it a firing corroboration reaches the model as a
bare `1`.

`brief/adapters/outbound/explanation/prompt.py` builds a `developer` message — the decision is
final; state the priority as given and never another; explain it only as the sum of the signals
against the thresholds; describe a signal only in its definition's terms; state or guess nothing
the input lacks, naming the FR-8 parts above; no identifiers, at most four sentences — and a
`user` message of the facts. `PROMPT_VERSION` names the wording. **Instructions are not
guarantees**: whether a real model obeys them is verified by nothing in CI.

### 5. The port, the adapter, and the dependency

```python
class ExplanationProviderPort(Protocol):
    async def explain(self, *, decision: ExplainableDecision) -> Explanation: ...
```

`Explanation` (`brief/domain/`, frozen) carries `text`, the `model` the response reports, and
`prompt_version`, so a narrative M7.2 persists stays traceable to its producer. Every failure is
`ExplanationUnavailable` (`brief/domain/exceptions.py`).

`OpenAIExplanationProvider` calls Chat Completions by raw HTTP. The request body has **exactly
four keys**: `model`, `messages`, `max_completion_tokens`, and `store: false`, explicit because
no default is documented. **No `temperature`**: nothing claims determinism, and per-model support
is unverified. `max_completion_tokens` is **25,000**, per the reasoning guide's *"reserve at least
25,000 tokens for reasoning and outputs"*. The timeout is **30 s and UNMEASURED**, since no call
path exists; M7.2's is where it is measured. Chat Completions rather than the Responses API,
which OpenAI's text guide recommends: the shapes verified above are Chat Completions', the model
supports it, and a move is adapter-local behind the port.

**`httpx2` moves from the dev group to `[project]` dependencies. No SDK.** It is the client the
tree already uses, and ADR-0009's own Context is its verification. **That move also fixes a
separate defect as a by-product** — two production adapters imported a dev-only package, so a
`--no-dev` install failed on import while CI, which installs dev, could not see it. The fix is
incidental. The blind spot is registered as **G72** so it survives this issue resolving the
instance.

### 6. The credential — rule 16's credential-handling clause

- `openai_api_key` carries a dev placeholder and is the **fourth entry in
  `_DEV_ONLY_DEFAULTS`**, so a non-local boot with the placeholder fails fast (rule 11). A
  placeholder credential is the case rule 11 names, and `github_client_secret` is the precedent.
  **The cost is zero today**: no non-local deployment exists — M11.3 is not done. From the first
  one, it requires `OPENAI_API_KEY` even while nothing calls the adapter.
- `openai_model` is not a secret; its default is the verified id, with the date and source in a
  comment.
- The key travels **only** in the `Authorization` header — never a URL, an exception or a log.
- **Every failure raises a fixed message carrying at most a status code or a known
  `finish_reason`, `from None`, and never reads the response body into it**, on the 401 evidence
  above. Non-leakage tests put key fragments inside a 401's `error.message` and assert them absent
  from `str`, `repr`, the formatted traceback and the log.

**This adapter closes the provider's echo in shipped code; it does not close the settings leak.**
`_reject_dev_secrets_outside_local`'s `ValidationError` carries pydantic's truncated
`input_value`, and this decision adds the OpenAI key to the same dict. Registered as **G71**, not
fixed here.

### 7. How the adapter is tested, and the departure that is

- **The adapter's own code** — the request, the header, the failure translation, the
  non-leakage — runs over `httpx2.MockTransport`, on `GitHubAdapter`'s precedent. **No skip, and
  no credential in CI.**
- **A contract test** runs the same assertions over `FakeExplanationProvider` and the real
  adapter, and reads the fake's `.calls`, so M7.2's tests on the fake stand on something.
- **A factory test** in `tests/unit/test_di_wiring.py` sends a request through
  `get_explanation_provider` and asserts the key reached the header and the model the body.
  Both constructor arguments are `str`, so a factory passing them swapped type-checks and no test
  that builds the adapter directly can see it. The implementation commit records the mutation run
  that shows this test is what kills it.

**This is a departure from `CLAUDE.md`'s definition of done** — *"Integration tests for any new
adapter, against the real dependency"* — and weaker than its nearest precedent:
`test_github_adapter.py` replays **captured** payloads, while these fixtures follow
openai-python's types. **OpenAI's real contract is exercised by nothing in CI.** The departure,
its end condition and the check that re-reads it are in `ROADMAP.md`'s M7.1 entry and checklist
step 5.

## Consequences

**Rule 16.** Clause 3 fires: this adds a credential, its rule-11 control, its header-only
placement and a body-suppressing failure translation. Clause 2 arguably fires on `Explanation`.
A one-line "reversal is cheap" would be false — code is cheap to remove, but text already sent to
a third party cannot be recalled, and every non-local deployment inherits `OPENAI_API_KEY` —
so this ADR is owed.

**What leaves Verion.** Bucket names, integers, `scoring.py`'s fixed strings and severity labels.
No finding id, package, URL or finding text, so no scanned content and nothing identifying a
project reaches OpenAI through M7.1.

**What a narration costs is UNMEASURED, and the number the model was chosen against leaves
out the part a reasoning model bills.** *(Added 2026-09-17, in M7.1's implementation commit.)*
`gpt-5-mini` spends reasoning tokens that are billed as output and never appear in `content`,
so an estimate built from the visible text (the figure `gpt-5-mini` was chosen against assumed
250 output tokens) undercounts by exactly the unseen part. Only the request's ceiling is fixed
here: `max_completion_tokens` is 25,000, reasoning included. **The measurement comes from the
capture that ends decision 7's departure**, which keeps the response's `usage` object whole —
`prompt_tokens`, `completion_tokens`, and `completion_tokens_details.reasoning_tokens` — rather
than trimming the fixture to the fields the adapter reads. Those figures are recorded here when
taken, with the condition they hold under: the request sends no `reasoning_effort`, so they
measure the model's default effort. **`Explanation` does not carry usage**: nothing consumes it,
and ADR-016 decision 3 and ADR-0021 refuse fields with no consumer.

**Measured 2026-09-17, by M7.3's capture** *(added by M7.3's capture commit; the paragraph above is
left as written)*. `scripts/capture_openai_responses.py` ran `describe` then `explain` over three
surfaces of the committed demo corpus, 10 repetitions each. Requested model `gpt-5-mini`; every body
returned `gpt-5-mini-2025-08-07`. **No `reasoning_effort` was sent**, so every figure measures the
model's default effort, and changing it invalidates them. **59 calls, not 60**: one `describe` timed
out, so its exercise never called `explain`. Wall time is the client's, around the transport,
connection included. Token medians are over calls that returned a body. Median / maximum:

| call | surface (members) | n | wall s | prompt tokens | completion tokens | reasoning tokens |
|---|---|---|---|---|---|---|
| `describe` | `Flask` (2) | 10 | 6.67 / 10.47 | 302 / 302 | 457 / 649 | 384 / 576 |
| `describe` | `/calculate` (7) | 10, 9 with a body | 18.40 / 30.32 | 519 / 519 | 1,510 / 1,821 | 1,280 / 1,600 |
| `describe` | `urllib3` (12) | 10 | 16.59 / 28.14 | 941 / 941 | 1,338 / 2,086 | 928 / 1,664 |
| `explain` | `Flask` | 10 | 18.34 / 25.47 | 406 / 406 | 1,522.5 / 2,529 | 1,344 / 2,304 |
| `explain` | `/calculate` | 9 | 15.45 / 19.86 | 390 / 390 | 1,232 / 1,739 | 1,024 / 1,536 |
| `explain` | `urllib3` | 10 | 19.41 / 24.65 | 406 / 406 | 1,673 / 2,127 | 1,472 / 1,920 |
| `describe`, pooled | | 30, 29 with a body | 14.47 / 30.32 | 519 / 941 | 1,127 / 2,086 | 832 / 1,664 |
| `explain`, pooled | | 29 | 18.00 / 25.47 | 406 / 406 | 1,446 / 2,529 | 1,280 / 2,304 |
| all calls | | 59, 58 with a body | 16.46 / 30.32 | 406 / 941 | 1,362.5 / 2,529 | 1,120 / 2,304 |

- **The token totals are a FLOOR: 28,731 prompt and 76,518 completion tokens**, of which 64,192
  reasoning (84%), over the 58 calls that returned a body. The timed-out call returned none, so its
  usage is absent from both totals, while it was almost certainly billed.
- **Reasoning is most of what a narration costs.** The pooled medians are 1,120 reasoning tokens and
  1,362.5 completion tokens, over 58 calls — two medians of one set of calls, not one call's pair; per
  call the ratio's median is 0.85. Either way it dwarfs the 250 output tokens the model was chosen
  against. A Brief is two calls, and the two pooled per-call completion medians sum to 2,573.
- **The 30.32 s maximum is a censored value**: the call was cut off at the bound, so the pooled maximum
  bounds nothing above 30 s. The `/calculate` `describe` wall median includes it.
- **`openai-processing-ms` was sent** on all 58 responses with a body, which ADR-0034 decision 7 had
  as unverified.

**Register.** Opened by the commit that lands this ADR: **G71**, **G72**. Owed dated notes by the
implementation commit: **G33** (its trigger names M7.1), **G62**, **G63** (its trigger names M7.1),
**G65**, **G68**, and G71 and G72 themselves, for what that commit measures and fixes.
**`ExplainableDecision` does not fire G67**: it is not the six-field completeness envelope.

**Documents corrected in the commit that lands this ADR.** ADR-0003's amendment; ADR-0004, whose
Decision names `RiskReasoning` as the narrated input and whose Consequences promise a real-call
integration test, by dated amendment; `CLAUDE.md`'s
M5.7 departure sentence, and `ROADMAP.md`'s M5.7 copy of it, both forecasting *"one
network-bound integration test"* that M7.1 does not ship. **In the implementation commit:**
`CLAUDE.md` rule 11's field list; `ARCHITECTURE.md` §5.2, §6.2, §7 and §8.

## Amendments

- **2026-09-17 (M7.2, ADR-0033): decision 5's measurement promise is falsified. The decision itself
  is unchanged.**
  - **What decision 5 said.** *"The timeout is **30 s and UNMEASURED**, since no call path exists;
    M7.2's is where it is measured."*
  - **What happens instead.** M7.2's call path, `POST /projects/{project_id}/briefs` (ADR-0033), is
    the first production caller, and M7.2 does not measure the timeout.
  - **Why.** Measuring needs real calls, and the only planned real call is the capture that ends
    decision 7's departure. That capture is not taken in M7.2: `OpenAIExplanationProvider._parse`
    reads only `choices` and `model` and discards `usage`, so recording the response whole needs
    recording tooling that does not exist in `scripts/`~~, and a transport or adapter change M7.2 does
    not make~~. *(Clause STRUCK 2026-09-17 as false; see the first M7.3 amendment below.)*
  - **Result.** The timeout stays **30 s and UNMEASURED**, and its measurement moves to that capture.
    The Consequences paragraph on narration cost is unaffected.
- **2026-09-17 (M7.2, ADR-0033): decision 1's closing sentence is qualified, not struck.**
  - **What decision 1 says.** The delivering port's return *"must also carry a Risk address, which is
    **G68**'s decision"*.
  - **How G68 was decided.** The port returns the Risk's ordered `finding_ids`, and a Brief holds them
    as data rather than as an address, so no Risk address exists (ADR-0033 decisions 1 and 6).
  - **What still holds.** The obligation the sentence states, that the port carry what identifies the
    Risk at generation.
- **2026-09-17 (M7.3, ADR-0034): the first amendment's second reason is struck as false.**
  - **What it said.** Recording a response whole needs *"recording tooling that does not exist in
    `scripts/`, and a transport or adapter change M7.2 does not make"*.
  - **What is true.** Only the first half. No shipped code has to change: the adapter's `transport=`
    parameter, shipped in M7.1 as the test seam, is enough. M7.3's reconnaissance passed a recording
    wrapper through the **unmodified** adapter, offline over `MockTransport`, and got a valid
    `Explanation` while the wrapper held `usage` whole. The one pitfall found is the wrapper's, not the
    adapter's: rebuilding a gzip-encoded response with its `content-encoding` header fails to decode
    (ADR-0034's Context). No real call has been made.
  - **Where the false clause came from.** It was drafted in the M7.2 planning session and approved there
    by the owner. M7.2's design commit, `a1661dc`, wrote it into this ADR's amendment, ADR-0033's
    Consequences and `ROADMAP.md`'s M7.2 bullet. M7.2's implementation commit, `22c001b`, added it to
    `openai_adapter.py`'s timeout comment and to `ROADMAP.md`'s M7.1 departure bullet. It was not
    verified against the seam at either point. *(Located with `git log -S` on each wording.)*
  - **What changes.** The reason the capture was not taken in M7.2 is the missing script alone. The
    capture is taken in M7.3 by that script (ADR-0034 decision 7).
- **2026-09-17 (M7.3, ADR-0034): the Consequences paragraph *"What leaves Verion"* is true of M7.1 and
  no longer of the Explanation Layer.** From M7.3, each Brief member's typed `title` and `Location`
  reach OpenAI through `describe`'s prompt. `explain`'s prompt, which this ADR designed, still carries
  none of them. No finding id, no `raw_payload` and nothing parsed from it is sent.
- **2026-09-17 (M7.3 capture commit, ADR-0034): decision 5's timeout is measured, stays 30 s, and its
  value is handed to the work that makes generation asynchronous. This is ONE decision, not two.**
  - **The evidence.** One call of 59 exceeded the bound: `describe` on `/calculate`, at 30.32 s of
    client wall time. The next highest was 28.14 s. Figures with n are in the Consequences above.
  - **Why no new value.** A value cannot be derived from a single exceedance. The tail past 30 s is
    unmeasured, because the call was cut off there, so any number above it would be invented.
  - **What bounds a synchronous call.** What a user will wait for, not what the model takes, and by that
    criterion 30 s is already too long. The pooled median is 16.46 s per call, and a Brief is two calls.
  - **Therefore.** The exceedance is not a mis-set bound. It is evidence that generation does not belong
    in a request. **The VALUE is handed to the work that makes generation asynchronous, where a generous
    bound is free** because nobody waits on it. That work is **G73**'s queued generation job, which
    re-decides ADR-0033 decision 8 (ADR-0033's M7.3 capture amendment). No issue schedules it. Until
    then the bound is 30 s, and a Brief whose call exceeds it answers the fixed 502 and stores nothing.
  - **Superseded.** The first amendment's *"Result. The timeout stays **30 s and UNMEASURED**"*: it is
    measured.
- **2026-09-17 (M7.3 capture commit, ADR-0034): decision 7's departure has ended.**
  - **The end condition, met.** A 200 captured from the real API for each prompt, `usage` whole, and a
    captured 401, both redacted and committed under `tests/integration/fixtures/openai/`, are replayed by
    the same tests: `test_openai_explanation_provider.py`, and the contract test for the `explain` 200.
  - **What had to be redacted, unforeseen.** The 401 echoed the throwaway key's first eight and last
    four characters, confirming the behaviour decision 6 was designed against (**G71**). The fixture
    carries markers in their place, with the message's shape kept.
  - **Decision 6, verified against a real body.** The adapter's exception carried no fragment of the key.
  - **What stays unexercised.** What OpenAI sends on any later day. Nothing in CI calls it (**G65**).

## Alternatives considered

**Re-exporting `RiskReasoning` through `risk_engine/ports/`.** Rejected in decision 1.

**A carrier declared in `brief`.** Rejected in decision 1.

**`RiskReasoning` only, as the bullet reads.** Rejected in the Context: the bucket cannot be
named without being derived.

**`package` and `url` in the prompt.** Rejected in decision 2 as M7.3's scope.

**Emitting a confidence now.** Rejected in decision 3.

**An SDK.** Rejected in decision 5: a new dependency, where the tree already carries a verified
client.

**A live OpenAI integration test behind a credential.** Rejected: with no secret in `ci.yml` it
would be this repository's first skip, and it would skip on every run. That is the hazard
`test_active_scan_finds_the_sink.py`'s docstring names — *"a skip is itself a false negative that
reads as green"* — though that docstring argues it for its own test, calling it *"the one place this
repo should not introduce its first skip"*, not as a rule for every test. With a secret it costs money per
run and cannot be deterministic, and fork PRs are not given repository secrets — GitHub's
documented behaviour, not verified in this repository.

**An empty `openai_api_key` default outside `_DEV_ONLY_DEFAULTS`.** Rejected: a misconfiguration
would surface at the first narration rather than at boot, which is what rule 11 exists to prevent.
