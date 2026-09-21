# ADR-0038 — Brief generation as a job: the generation record, where authorization lands, and what the poll reports

## Status

Accepted — 2026-09-21 (M8.6). Written and accepted before M8.6's code is committed, on ADR-0033's,
ADR-0035's and ADR-0036's precedent. M8.6's first commit, `8a81f2c`, already landed the call
deadline this ADR re-prices (decision 12).

**The asset this commit delivers is the response shape, not the code.** M8.6 sits before M8.2 in
M8's execution order so that M8.2 designs against the final shape once. Decisions 6 and 8 are that
shape, and they are final on this commit — M8.2 may build on them before the code lands.

## Context

ADR-0033 decision 8 put generation on the request path and recorded the cost as **G73**. M8.6's
first commit bounded the provider call and left the rest. Observed at HEAD, by reading the code:

- **Per-Brief wall time, over M7.3's capture**: median **32.32 s**, maximum **49.03 s**, n=29
  exercises that ran both calls. `GenerateSecurityBriefUseCase` calls `describe` then `explain`
  strictly in sequence, and ADR-0034 decision 3 makes that order a property.
- `ExplainableRiskPort.explainable_risk` **authorizes and selects in one call**, with the caller's
  `user_id`, and recomputes the project's whole scored set (**G61**).
- The Brief's id is minted inside the use case, **after both calls**. Nothing addressable exists
  before then.
- `security_briefs` has **eight** `NOT NULL` columns. Five of them — `decision`, `why_it_matters`,
  `model`, `prompt_version`, `generated_at` — are the ones a row created before generation could not
  fill; `id`, `project_id` and `finding_ids` it could. It carries **two** CHECKs,
  `ck_security_briefs_finding_ids_not_empty` and `ck_security_briefs_what_happened_all_or_none`, and
  an index on `(project_id, generated_at DESC)`. `tests/unit/test_security_brief.py` asserts `SecurityBrief`'s
  field set by **equality**.
- `brief` has **no status vocabulary**. Its domain holds no enum, and `SecurityBrief`'s eight fields
  carry no state.
- `on_startup` puts `scanners` and `repo_checkout` in `ctx`, and nothing else. arq injects
  `ctx["redis"]`.
- **`scans` enforces no correlation between `status` and `failure_reason`.** `ScanModel` has no
  `__table_args__` at all; the CheckConstraint is on `ScanResultModel`.
- `cross-module-brief` forbids `verion.modules.scanning.adapters`, so `AfterCommitJobQueue` cannot
  be imported from `brief`.

ADR-0033 decision 8 declined the queue on two grounds. The latency one was struck 2026-09-17. The
other — *"a pipeline stage this project has not designed"* — is **struck here as false**, and the
Context is why: `worker.py` runs two job functions and a cron, three queue adapters exist,
`platform/db.py` has `after_commit`, and M8.8 shipped a 202-plus-poll route over it. The claim has **four**
sites. Three are struck: that decision, ADR-0033's 2026-09-17 amendment's *"What stands"*, and
`ROADMAP.md`'s **G73** deferral rationale. The fourth, that amendment's *"What decision 8 said"*, is
a quotation inside a dated record and is annotated rather than struck — striking it would falsify
the record of what was said.

## Decision

### 1. Generation is a job; `POST` answers 202

Replaces ADR-0033 decision 8. Its second ground fails on the Context above; its first —
*"some write path must ship"* — was satisfied at M7.2 and does not bind a second time.

**202 rather than 201**, because the work is enqueued and not completed. The response carries the
generation's `id` and its `status`, always `pending` on this path, on `ScanAcceptedResponse`'s
shape. Nothing about `security_briefs`, `SecurityBrief` or ADR-0033 decision 3 changes.

### 2. A `brief_generations` table

The other two id forks are eliminated by measurement, not by preference.

- **A pending row in `security_briefs`.** It needs the five unfillable `NOT NULL` columns made
  nullable — a migration that weakens invariants every existing row satisfies — and it breaks the
  **equality** assertion over `SecurityBrief`'s field set. **A CHECK could re-express them**:
  `ck_security_briefs_what_happened_all_or_none` is that template, on this very table, so this fork
  is not rejected for lack of one. It is rejected because the CHECK would have to be conditioned on
  a status column that does not belong on a table whose every existing row is a completed Brief, and
  because the domain type would carry **three** of its existing fields turned optional — `decision`,
  `explanation`, `generated_at`; `what_happened` and `confidence` already are — plus **two** new state
  fields, all to describe a state no Brief reaches. Its
  `generated_at DESC` index and ADR-0033 decision 3's history semantics have no meaning for a row
  that has generated nothing.
- **Minting the id in the route with no row.** The poll's only evidence would be `security_briefs`,
  so *"no such Brief"* and *"still running"* are one query result — the distinction a poll exists
  for. It is also the only fork under which a lost message is undetectable.
- **A table of its own.** Chosen. `scans`' shape one module over, and it leaves `security_briefs`,
  `SecurityBrief`, ADR-0033 decision 3 and both pinned field-set tests **untouched**. That is what
  makes the fork that adds a table the cheap one.

`brief` therefore gains a second entity and a second repository port, and stops being one aggregate
behind one port. Stated because it is a real change to the module's shape.

### 3. Identity and ordering

The id is minted **in the route, before the work**, by `IdGeneratorPort` (rule 9). The row is
written, then the job is asked for — `TriggerScanUseCase`'s order — and the enqueue is deferred to
`platform/db.py`'s `after_commit` through `brief`'s own wrapper (decision 9).

ADR-0035 decision 5's ordering holds unchanged: **commit, then enqueue, then the response.** A 202
means the row exists and the job is queued.

### 4. Authorization: the route checks, and the job checks again

The route asks `ProjectAccessPort.may_read_project` before it writes anything. The job stores the
requesting `user_id` and calls `explainable_risk` with it.

- **This is not a verdict inherited across the queue.** `explainable_risk` authorizes and selects in
  one call and cannot be split, so the `user_id` crosses the boundary under every design. What this
  decision fixes is that a **second, independent check runs in the worker** — defence in depth, not
  the only gate.
- **What the late check buys that the scanning precedent has no answer for**: a membership revoked
  between enqueue and run. `StartScanUseCase` authorizes once and never again.
- **Rejected: no route check, the job authorizes alone.** It promises a Brief to a caller who may
  not read the project, spends a job on an unauthorized request — an amplification against the
  provider bill that **G73**'s repeats half already records as unbounded — and makes an
  authorization failure indistinguishable from a work failure.
- The read verdict, not an owner verdict: ADR-0033 decision 7 decided that and **G75** owns moving
  it. This ADR does not.

### 5. A status vocabulary, new to `brief`

`pending`, `running`, `succeeded`, `failed`. A plain `String` column, not a DB enum, on
`security_briefs.confidence`'s ground: adding a value must not need a type migration.

`pending` means enqueued; `running` means the job claimed it; both terminal states are written by
the job. The module had no such vocabulary and inherits none — `ScanStatus` belongs to `scanning`
and ADR-0016 decision 2 keeps it scanner-scoped.

### 6. The poll does not flatten: three outcome kinds, one per client action

The question is what a client does, and the client is M8.3, two issues out. Five terminal failures
map onto **three** actions:

| Failure | `failure_kind` | What the client does |
|---|---|---|
| `NoCurrentRisk` | `surface_changed` | re-read `/scored-risks`, ask again |
| `ExplanationUnavailable`, `WhatHappenedRejected` | `provider_unavailable` | retry |
| `ExplainableRiskInconsistent`, `BriefMemberMissing` | `internal_error` | do not retry |

**Not one free-text field**, which removes the client's ability to choose between those three and
is what `scans`' bare `failure_reason` would have given. **Not five**, which encodes distinctions no
client acts on. A fixed `detail` string accompanies the kind and carries no value (rule 12).

**`ExplainableRiskAccessDenied` is not a fourth kind**, and this is the seam where this decision and
decision 7 would otherwise contradict each other. The poll authorizes on its own (decision 8), so a
caller whose access was revoked between enqueue and run gets **404 from the poll's own verdict**,
never from anything stored. The job still terminates the row as `failed` under `surface_changed`, so
decision 7's CHECK holds and no row sits `running` forever. That kind is unobservable **while the
revocation stands**: the only caller who could read the row is the one the poll refuses. A re-granted
membership makes it readable again, reporting `surface_changed` for what was a denial — which is the
right action for that caller anyway, since the surface must be re-read either way.

### 7. `brief_generations` writes its own CHECK

`ck_brief_generations_outcome_shape`, on `ck_scan_results_outcome_shape`'s template:

```
(status IN ('pending','running') AND brief_id IS NULL AND failure_kind IS NULL)
OR (status = 'succeeded'        AND brief_id IS NOT NULL AND failure_kind IS NULL)
OR (status = 'failed'           AND brief_id IS NULL     AND failure_kind IS NOT NULL)
```

**`scans` is not the precedent here, and the Context says why**: it has no `__table_args__`, so its
`status`/`failure_reason` pairing is a convention nothing enforces. This ADR declines to copy the
convention and copies the constraint instead, from the table that has one.

### 8. The poll route

```
POST /projects/{project_id}/briefs                      → 202  {id, status}
GET  /projects/{project_id}/brief-generations/{id}      → 200  {id, status, failure_kind, detail, brief_id}
```

- **Authorized by `may_read_project` AND an actor match.** A generation is readable only by the
  caller who requested it; every other member gets 404, as does an absent id and a generation of
  another project. One 404 for every denial (**G17**).
- The actor match is what makes decision 6's unobservability real rather than asserted.
- `brief_id` is null until `succeeded`, and is how a client reaches the Brief on `GET …/briefs`.
- Both key sets are rule-10 schemas local to the adapter, pinned by equality assertions.
- No path ends in a slash (ADR-0031's trailing-slash limitation).

### 9. Worker wiring, and the OpenAI key's second process

The job builds, per job, from `session_factory()`: `PostgresFindingRepository`,
`PostgresSecurityBriefRepository`, the generation repository, `PostgresProjectAccessReader`,
`PostgresServingDeclarationVerdictReader`, `PostgresRouteMapReader`, then `ScoredExplainableRisks`
over `ComputeRiskUseCase` over `CorrelationCandidateRisks` over `CorrelateFindingsUseCase`, plus
`SystemClock` and `UuidIdGenerator`. `OpenAIExplanationProvider` is stateless and goes in `ctx` at
`on_startup`, beside `scanners`.

**The worker process now reads `OPENAI_API_KEY`.** No document said otherwise — checked, no change:
ADR-0032's *"every non-local deployment inherits `OPENAI_API_KEY`"* is process-agnostic and stays
true. Which rules this touches:

- **Rule 11** — satisfied unchanged **as to `openai_api_key`**, already `_DEV_ONLY_DEFAULTS`' fourth
  entry, with the guard running wherever `Settings` is constructed. Not a claim that rule 11 holds
  generally: **G98**, opened by M8.6's first commit, records it as unmet for `debug`.
- **Rule 12** — the one with new surface. A provider failure now renders in a worker log rather than
  an HTTP response. ADR-0032 decision 6's fixed messages, raised `from None`, are what hold it, and
  they are unchanged.
- **Rule 13** — untouched. No redirect exists on this path.

`brief` also needs its **own** after-commit queue wrapper: `cross-module-brief` forbids
`verion.modules.scanning.adapters`, so `AfterCommitJobQueue` is retyped rather than imported. That
is a contract forcing a copy, registered as **G99**.

### 10. `keep_result=0`, argued rather than copied

`normalize_scan` uses it because nobody reads its result and the `normalization_runs` row is the
record. Both clauses hold here **because of decision 2**: the `brief_generations` row is the record,
and the poll reads it rather than arq's result. So the flag is the same and the reason is this
ADR's, not an inheritance.

It also keeps arq's in-progress dedup while releasing the result key, which matters for the same
reason it did at M4.4: a result key reserves the job id for an hour after the job dies.

### 11. No sweep. The recovery is the user asking again

arq 0.28 retries only `Retry`, `RetryJob` and `CancelledError`, so a failed generation is never
retried, and a row whose enqueue was lost after the commit is never re-driven.

`normalization`'s sweep is **not** copied, on a distinction rather than on scope: **a normalization
run is owed work with no user attached** — a scan happened and findings must appear, so only a sweep
can notice — whereas **a generation is user-initiated and the user is already polling it**.
ADR-0033 decision 3 makes a repeat POST a regeneration rather than a no-op, so the recovery path
exists and is already designed, and the poll makes the stuck state visible exactly as M8.8's status
read does for a stuck scan.

**The cost is stated, not denied**: a lost enqueue leaves a row `pending` forever. That is
ADR-0035 decision 5's failure mode in a second table, and it **confirms G87** rather than citing it.

### 12. The call deadline is re-priced, and the ground is not the maximum

**`_CALL_DEADLINE_SECONDS` becomes 120.0**, from 30.0. The number is stated here rather than handed
to the code commit, because a decision to re-price that names no price is a third deferral wearing
another word.

**"Free" is bounded, and the bound is not this module's.** `WorkerSettings.job_timeout` is **600 s**,
global to the worker, and its own comment derives it from ZAP's 540 s plus a 30 s checkout, adding
that *"raising a scanner timeout is not a local decision"*. A generation is two calls plus the member
reads under that same 600 s, so 2 × 120 = 240 s leaves the reads and the write a wide margin while
not touching a figure `scanning` owns. That constraint, not the observed latency, is what picks the
value's order of magnitude.

**The ground is that it is free, NOT that it is derived from the observed maximum.** Every per-call
figure this project holds is **right-censored at 30 s**: the observed per-call maximum, 30.32 s,
*is* the call that hit the bound, and `describe`'s 28.14 s and `explain`'s 25.47 s are clean only
conditional on not having exceeded 30. The tail past it is unmeasured. Deriving a value from a
single exceedance is what ADR-0032's M7.3 amendment refused, and this ADR does not do it by the back
door. Any figure quoted in support is labelled right-censored.

`_TIMEOUT_SECONDS`, the per-operation value, does not move.

## Consequences

- **Rule 16.** The route, response-schema, migration and authorization clauses all fire. This ADR is
  the citation.
- **ADR-0033.** Decision 8 is replaced. Decision 1 **survives** — its identity, data-not-address,
  no-address and fails-closed clauses are untouched — with one clause struck: *"It is resolved in
  that same request against the projection"*, the resolution having moved to the worker. Its
  `NoCurrentRisk` refusal becomes decision 6's `surface_changed`, which is the same refusal reported
  later. Decision 3 is untouched and is what makes decision 11's recovery legitimate.
- **Register.** **G87** gains a confirmation, not a mention: M8.6 is a second occurrence of an
  enqueue that can be lost after the commit, in a second table, and declining the sweep is what
  makes it permanent. The count moves to two against an escalation threshold of three. **G99** is
  opened for the forced copy. **G73**'s session half resolves at M8.6's code commit, not here; its
  repeats half passes to a successor entry opened there, still M10.2's.
- **Owed by the implementation commit**, listed so they are not rediscovered: `di.py`'s comment
  above `get_compute_risk_use_case` (*"there is no worker path — the only caller is the read
  surface"*); `ARCHITECTURE.md`'s deployment diagram, whose Workers box reads `(scan/ normalize)`,
  and its note that *"briefs are not built"*; its Brief-routes bullet, *"`POST …/briefs` generates and
  stores a Brief"*, and its ADR-0033 summary's *"Generation is append-only and synchronous"* — the
  second of which sits four ADR bullets above this ADR's own block, where a reader meets the
  contradiction first; `GenerateSecurityBriefUseCase`'s and the POST route's *"synchronous"* docstrings; and — falsified by
  **decision 12**, not by the job — `openai_adapter.py`'s *"It is 30 s because that is what
  `_TIMEOUT_SECONDS` already declared"* and its whole equal-values paragraph, plus
  `test_a_read_timeout_is_unavailable`'s *"Since M8.6 commit 1 they are equal"* and the deadline
  test's *"a real one would take thirty seconds"*; and ADR-0033's route-table row *"201, the stored Brief"* with its
  *"pins a `Role.MEMBER` generation at 201"*.
- **Out of scope:** the frontend (M8.3), a list of generations, cancelling one, rate limiting
  (M10.2), and any change to `security_briefs`.

## Alternatives considered

- **A pending row in `security_briefs`; minting the id in the route with no row.** Both rejected in
  decision 2, each on a measurement rather than a preference.
- **The job authorizes alone, with no route check.** Rejected in decision 4.
- **One free-text `failure_reason`, on `scans`' shape.** Rejected in decision 6: it is the shape
  `scans` has, and `scans` does not enforce it either.
- **A fourth `failure_kind` for access denial.** Rejected in decision 6: it would name a denial in a
  response body and break **G17**'s one-404-for-every-denial.
- **A sweep like `normalization`'s.** Rejected in decision 11.
- **Deferring the call deadline again.** Rejected in decision 12. It would be the third deferral of
  one value.
