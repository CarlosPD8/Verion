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
    re-decides ADR-0033 decision 8 (ADR-0033's M7.3 capture amendment). ~~No issue schedules it.~~ *(Struck 2026-09-21, M8.6 commit 2: **M8.6 schedules it**, and ADR-0038 replaces ADR-0033 decision 8. Assigned to M8.6 at the 2026-09-19 boundary review. Three sites, found by grepping the claim.)* ~~Until
    then the bound is 30 s, and a Brief whose call exceeds it answers the fixed 502 and stores nothing.~~
    *(STRUCK 2026-09-18 as falsified; see the post-M7 boundary amendment below.)*
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
- **2026-09-18 (post-M7 boundary review): the M7.3 capture amendment's *"the bound is 30 s, and a Brief
  whose call exceeds it answers the fixed 502 and stores nothing"* is FALSIFIED, and struck.** Read from
  the installed code, not from documentation.
  - **What the adapter sets.** `OpenAIExplanationProvider` builds `httpx2.AsyncClient(timeout=_TIMEOUT_SECONDS)`.
    A scalar sets `connect`, `read`, `write` and `pool` to 30 s each (`httpx2`'s `Timeout`).
  - **What the read timeout bounds.** `httpx2` 2.12.0's transport is `httpcore2` 2.12.0, whose
    `_async/http11.py` passes it to every `_receive_event`, in the response-body loop included, and
    `_receive_event` applies it to each `_network_stream.read`. It bounds the wait for the next
    bytes, not the response: a response delivering a chunk every 29 s never times out.
  - ~~**No overall deadline exists.** Nothing in the adapter, the use case or the route wraps the call in
    one, so the hold is bounded neither by 30 s nor by the sum of the phases.~~ `GitHubAdapter` records the
    same per-operation behaviour and bounds its archive fetch with `asyncio.timeout`; ~~this adapter has no
    counterpart.~~ *(Both clauses STRUCK 2026-09-21 as falsified by M8.6 commit 1, which gives this adapter
    that counterpart: `_CALL_DEADLINE_SECONDS`, one `asyncio.timeout` per port call in `_complete`. See the
    M8.6 amendment below.)* `openai_adapter.py`'s comment above `_TIMEOUT_SECONDS`, *"httpx applies it per
    phase, not to the whole call"*, is incomplete for the same reason: within the read phase it applies per
    read. *(That sentence stands as the dated reading it was; the comment it describes was qualified by the
    same commit.)*
  - **What still holds.** A read that waits 30 s with nothing arriving times out, and the Brief then
    answers the fixed 502 and stores nothing. What is false is that every call longer than 30 s ends
    that way. The capture's one cut-off call fits a read timeout at 30.32 s but does not show one:
    `measurements.json` records `"error": "timeout"`, which `scripts/capture_openai_responses.py`
    writes on any `httpx2.TimeoutException`, and all four phases raise one.
  - **Who could send such a response.** `_CHAT_COMPLETIONS_URL` is a module constant, so the realistic
    sender is OpenAI or the network path, not an attacker choosing the endpoint.
  - **Consequence.** It strengthens **G73**, which records it. The timeout's value stays G73's decision.

- **2026-09-20 (M8.5, documentation commit): decision 3's "No confidence is emitted" is SUPERSEDED, and this ADR's prompt boundary is untouched by that.** ADR-0037.
  - **What is superseded, and where it is also said.** Decision 3 states *"**G63** stays open, re-pointed at M7.2"*, and this ADR's Context states *"A scored Risk carries no confidence (**G63**), and tests assert the absence."* ADR-0037 decides a confidence — the Risk's **grouping provenance** — and it ships in M8.5's second commit, at which point both sentences describe M7.1 through M8.1 and no later state. **They are annotated rather than rewritten**, per this project's rule against editing an accepted Decision in line; this note is the record.
  - **Why the annotation is written here at all**, when the code has not landed: the claim is cited from two other documents and three `src/` docstrings, and an earlier M8.5 draft struck it at its own site and nowhere else. That is the defect `CLAUDE.md` records — *"After a correction narrows or strikes a cited claim, grep the claim across the tree before closing the round"* — which cost ADR-0016 decision 3 a milestone of staleness.
  - **Decision 2's prompt boundary is UNCHANGED, and deliberately.** ADR-0037 decision 9 sends the confidence to **neither** provider call. `ExplainableDecision` does not carry it (ADR-0037 decision 8), so *"the prompt's input ends at that carrier"* stays exactly true and `explain`'s prompt stays byte-identical at `PROMPT_VERSION = "m7.1-1"`. Nothing new leaves Verion.
  - **Decision 3's own reasoning is vindicated rather than overturned.** It declined to choose because *"emitting one reaches a third module either way"*. It does: M8.5 spans `correlation`, `risk_engine`, `brief` and `shared_kernel`. What changed is that an issue was scoped to pay that cost, not that the cost was wrong.
  - **Decisions 1, 4, 5, 6 and 7 are unaffected**, and decision 4's `CORROBORATION_DEFINITION` gains a sibling in `correlation` rather than a competitor: ADR-0037 decision 10 copies its shape — a definition declared beside the thing that computes it, carried to the reader verbatim.

- **2026-09-21 (M8.6 commit 1): the adapter now has an overall deadline, and it is a SECOND constant.**
  The **2026-09-18** amendment is amended by it — not the entry directly above, which is unrelated:
  two of that amendment's clauses are struck at their own site.
  - **What landed.** `_CALL_DEADLINE_SECONDS = 30.0`, and one `asyncio.timeout(_CALL_DEADLINE_SECONDS)`
    around the request in `_complete`. `_complete` is the one method `explain` and `describe` share, so
    the deadline lands once and bounds **each port call** — never the pair. That is `fetch_source_archive`'s
    structure read correctly: its single deadline covers the two HTTP requests of *one* port call, which
    that adapter can see. `describe` and `explain` are two port calls made by the application layer, and
    a deadline over both could not live here. It could not be 30 s either: over M7.3's capture the
    per-Brief wall time has median **32.32 s** and maximum **49.03 s** across **n=29** exercises that ran
    both calls, so one 30 s deadline over the pair would reject 17 of 29.
  - **Two constants, because the 2026-09-18 amendment established two quantities.** `_TIMEOUT_SECONDS` keeps
    its name and its meaning, the per-operation value; the deadline is a second name at the same value.
    One constant serving both roles would contradict the document it corrects. **No number changed**:
    this commit changes which quantity 30 s measures and prices nothing. The generous asynchronous bound
    remains **G73**'s, handed to the queued job, and it is `_CALL_DEADLINE_SECONDS` that the job re-decides
    — so the handoff sentence moved to that constant's comment rather than staying above the one the job
    does not re-price. ~~The precedent's deadline is six times its per-operation value; that ratio is the
    job's to set. At today's equal values the per-operation bound can fire first only when a single read
    consumes the whole budget, and that race is confined to which message this adapter raises: both are
    `ExplanationUnavailable`, which `brief`'s router maps to one 502 with a fixed detail.~~ *(All three
    clauses struck 2026-09-21, M8.6 commit 3. The ratio **is now set, at 4x not 6x**. The values are
    **no longer equal** — 30 s against 120 s — so the per-operation bound is the smaller and can fire
    first at any single read over 30 s: the clause **inverted** rather than needing qualification. And
    the router maps nothing to a 502 any more; both still raise `ExplanationUnavailable`, which the job
    maps to one `provider_unavailable` outcome, so the conclusion that no caller can tell which fired
    survives its three premises. **None of these three sites is on ADR-0038's owed list**, which named
    `openai_adapter.py`'s copy of the same claim and not this one; they were found by grepping the claim
    across the tree.)*
  - **Decision 6 is satisfied, not changed.** The new failure raises a fixed message, `from None`, naming
    no value — not even the number, since a deadline is neither a status code nor a `finish_reason`. No
    response body is read on this path. Measured, not assumed: `from None` sets `__suppress_context__` and
    leaves `__context__` populated, which is what stops the context being rendered; `test_github_adapter.py`
    can assert `__context__ is None` only because that adapter raises outside its handler, a discipline
    neither of `_complete`'s two handlers uses. The new test asserts `__suppress_context__` and the file's own
    leak check, because the deadline expires **during** the POST that carries `Authorization: Bearer`
    (**G71**).
  - **Catching the deadline is the substance, and the claim spans two links measured separately.** A
    builtin `TimeoutError` is not an `httpx2.HTTPError` — measured against the installed `httpx2` 2.12.0 on
    CPython 3.12.14, `issubclass` is `False` in **both** directions, `TimeoutError` descending from
    `OSError` and `httpx2.HTTPError` straight from `Exception`, so the two `except` clauses are disjoint
    and their order is immaterial. `asyncio.TimeoutError` **is** the builtin, so one clause is the whole of
    what the deadline can raise, and `socket.timeout` **is** the builtin too, so a socket timeout escaping
    `httpcore2`'s wrapping lands in the same translation.
    - **Link 1 — the adapter lets it escape.** Measured by mutation: with the `except TimeoutError` removed
      and the `asyncio.timeout` kept, the deadline leaves `_complete` as a bare `TimeoutError`, raised at
      `asyncio/timeouts.py`'s `raise TimeoutError from exc_val`.
    - **Link 2 — nothing downstream catches it.** Measured by probe: a `TimeoutError` raised from the use
      case is caught by none of the five `except` clauses on the POST route (the router has seven, the
      other two belonging to the list route), FastAPI's three default handlers
      cover `HTTPException` and the two validation errors only, no user middleware is installed, and
      Starlette's `ServerErrorMiddleware` answers **500** — where decision 9 of ADR-0033 fixes this failure
      at 502. Measured with `httpx2.ASGITransport(raise_app_exceptions=False)`, because at its default the
      exception propagates into the client instead of becoming the response a server would send. **The
      harness is not committed, so this figure is a record of the run, not a re-runnable claim.**
    - **The chain is their conjunction.** Neither measurement alone shows it: the mutation puts a
      `TimeoutError` on the wire out of the adapter, the probe shows what a caller then gets.
  - **What this does NOT do, because "bounds the hold" is the easy misreading.** It caps the provider
    call. ~~The request's session is still opened by `get_db_session` and still held across the member reads
    and both calls — now finite, at most two deadlines plus the request's own work, where before it was
    unbounded. It is not released. **G73** stays live on that mechanism and on repeats, and its
    2026-09-21 note carries the split.~~ *(Struck 2026-09-21, M8.6 commit 3, which is true of that commit
    and false now: the request holds no session across a provider call at all, because generation is a
    job. The session held across both calls is the **worker's**, bounded by arq's `max_jobs` default of
    10 under a 15-connection pool ceiling. **G73** resolves on that mechanism at commit 3 and its repeats
    half passes to **G100**; that the inequality holds by two library defaults nothing declares is
    **G101**.)*
  - **Found on the way.** The link-2 probe returned its 500 as a full traceback, because `debug` defaults
    to `True` and rule 11's validator never looks at it. **G98**.

- **2026-09-21 (M8.6 commit 2, ADR-0038): the adapter runs in a second process, and the call deadline
  is re-priced there.** Documentation only; the wiring lands in M8.6's code commit.
  - **`OPENAI_API_KEY` is read by the worker from that commit.** **Checked, no change to any claim**:
    nothing in this ADR or elsewhere said only the API process reads it. This ADR's **Consequences**
    say *"every non-local deployment inherits `OPENAI_API_KEY`"* and **decision 6** says *"it requires
    `OPENAI_API_KEY` even while nothing calls the adapter"* — both process-agnostic, both still true.
  - **Which rules that moves.** **Rule 11** is satisfied unchanged **as to `openai_api_key`**, already this
    dict's fourth entry, with the guard running wherever `Settings` is constructed — not a claim that
    rule 11 holds generally, which **G98** records as false for `debug`. **Rule 12** gains
    surface: a provider failure now renders into a worker log rather than an HTTP response, and
    decision 6's fixed messages raised `from None` are what hold it, unchanged. **Rule 13** is
    untouched — no redirect exists on this path.
  - **`_CALL_DEADLINE_SECONDS` is spent, not deferred a third time** (ADR-0038 decision 12). The
    value rises because under a job it is free, **not because it is derived from the observed
    maximum**. The M7.3 capture's per-call figures are **right-censored at 30 s**: the maximum,
    30.32 s, *is* the call that hit the bound, and `describe`'s 28.14 s and `explain`'s 25.47 s are
    clean only conditional on not having exceeded 30. Deriving a value from a single exceedance is
    what this ADR's M7.3 amendment refused, and ADR-0038 does not do it by the back door.
  - **`_TIMEOUT_SECONDS` does not move**, and ~~the M8.6 commit-1 amendment above stands in full~~
    *(struck 2026-09-21, M8.6 commit 3: it does not. Four of its clauses are struck at their own site
    by that commit — the 6x ratio, the equal-values race, the 502 mapping, and the request's session
    being held across both calls. What stands is everything about **what landed at commit 1**: the two
    constants, their disjointness measurement, decision 6 being satisfied, and both links of the
    escape claim.)*

- **2026-09-21 (M8.6 commit 3, ADR-0038): it is built, and the adapter's second process is real.**
  - **`_CALL_DEADLINE_SECONDS` is 120.0.** `_TIMEOUT_SECONDS` stays 30.0. The ground is unchanged from
    the commit-2 amendment above and is worth restating because the number invites the wrong reading:
    the value is generous **because nothing waits on it under a job**, bounded by
    `WorkerSettings.job_timeout` at 600 s, and **not** derived from any measured latency. Every
    per-call figure this project holds is right-censored at 30 s.
  - **`on_startup` builds `OpenAIExplanationProvider` into `ctx`**, reading `openai_api_key` and
    `openai_model` from `Settings`. The rules analysis in the commit-2 amendment stands as written; what
    changes is that it now describes code rather than a plan.
  - **Rule 12's new surface, checked rather than asserted.** A provider failure reaching a worker log
    is the surface commit 2 named. What holds it is unchanged — decision 6's fixed messages, `from None`
    — and the code commit adds a second assertion the route tests could not make: the terminal
    `brief_generations` row is queried directly and checked for a key-shaped sentinel, because a stored
    `detail` column would have been the obvious place for a provider's message to land. There is no such
    column; `detail` is derived from `failure_kind` at the adapter (ADR-0038 decision 6).

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
