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
