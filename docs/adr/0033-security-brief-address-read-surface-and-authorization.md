# ADR-0033 — How a Security Brief refers to its Risk, what it stores, how it is read, and who may generate one

## Status

Accepted — 2026-09-17 (M7.2). Written and accepted before any of M7.2's code is committed, on
ADR-0030's and ADR-0032's precedent.

## Context

M7.2's bullet asks for *"`GenerateSecurityBriefUseCase`, `SecurityBrief` entity, Postgres adapter"*
and an *"Endpoint returning the full Brief with evidence links (evidence traceability, FR-9)"*.

**Where persistence comes from.** `PRODUCT_SPEC.md` FR-8 does not require it; its text is *"system
generates a structured explanation"*. The requirement comes from that bullet's *"Postgres
adapter"*, from `ARCHITECTURE.md` §4.1's `SecurityBrief` design block, which carries an `id`, and
from §8's `Brief->>DB: persist SecurityBrief`. FR-9 adds *"Every Risk and every Brief must link back
to the raw findings and tool output that produced it."*

**G68 is the obstacle.** A stored Brief refers to a Risk, and ADR-0025 decision 1 says a candidate
Risk *"**has no identifier**"*. It rejects the match key, the lowest constituent `finding_id` and a
hash of the ordered ids as derived addresses. Decision 2 makes M8.1 the first issue forced to write
a Risk row.

**M7.1 left three things to this issue** (ADR-0032): the port that hands `ExplainableDecision` to
`brief`; the first production call to `ExplanationProviderPort.explain`; and FR-8's parts with no
producer.

**Observed at HEAD `1582c6c`** by running the code in memory against the real modules, with fake
ports where a database would be:

- `group_by_match_key` puts every finding id in exactly one group, and every group's `finding_ids`
  is sorted. Two findings with no key signal produce **two groups whose keys are equal**.
- `ComputeRiskUseCase` returns surfaces with sorted `finding_ids`.
- For one unchanged finding-id set, refreshing a member's severity from `HIGH` to `CRITICAL` moved
  `priority_score` from **6 to 7**.
- `explainable_decision` for the two single-finding surfaces with no key signal returned decisions
  that are unequal **only in `produced_by`**, which carries finding ids.
- `EvidenceResponse` carries no completeness envelope. `ScoredRiskResponse` carries `finding_ids`
  and no id.
- `count_unfinished_by_project_id` counts every status `!= completed`, so `failed` is included. The
  sweep's `get_stale` selects only `pending` and `running`, so a failed run is never re-enqueued
  (G15).
- No `domain/` package in `src/` imports anything from another module. There are 22
  `verion.modules` import lines across all `domain/` packages, and 0 of them are cross-module.

## Decision

### 1. A Brief has its own id and holds its Risk's ordered finding-id set as data, not as an address

**Four options were weighed.**

- **Generate without storing.** Rejected.
  - Every view would be a billed provider call.
  - Two views would differ, because nothing claims determinism (ADR-0032 decision 5 sends no
    `temperature`).
  - A Brief that exists nowhere after its response cannot *"link back"* (FR-9).
- **Persist a Risk.** ADR-0025 decision 2 permits it (*"whichever issue writes first"*). Rejected.
  - Forced by a narrative, it would make decision 1's *"Nothing before M8.1 is forced to write a
    row"* false, for a reason decision 2 never named.
  - A maintained Risk row needs what ADR-0025's Alternatives rejects: a conflict target that
    collides, replace-all that *"regenerates ids"*, and *"a WRITE trigger, which this project has
    never designed"*.
  - A Risk row minted per Brief is a snapshot, not an identity.
  - G37 refuses *"protecting a column that does not exist"*.
- **Key on the match key.** Rejected: two surfaces with no key signal have equal keys, as observed
  above.
- **The ordered finding-id set.** Chosen, in the following form.
  - **Identity.** A Brief's identity is a surrogate id from `IdGeneratorPort` (rule 9). It is not
    derived from the Risk.
  - **Storage.** `finding_ids` is stored as **data**: FR-9's link, and what a client joins on.
  - **No address.** No route, URL or held reference resolves a Risk by it.
  - **One selector.** The set acts as a selector exactly once, in the generation request's body.
    ~~It is resolved in that same request against the projection~~, by equality over sorted ids.
    *(Clause struck 2026-09-21, M8.6, ADR-0038 decision 1: generation is a job, so the set is
    resolved in the worker. The resolution itself is unchanged — same port, same exact equality —
    and the rest of this decision stands, including the fail-closed clause below, whose refusal
    becomes ADR-0038 decision 6's `surface_changed`.)*
  - **Fails closed.** A membership change produces ~~a 404~~ **a terminal `failed` /
    `surface_changed` generation** *(M8.6 commit 3, ADR-0038 decision 6: the refusal moved to the
    poll with the resolution itself. **Fails closed is the property and it is untouched** — the set
    still selects by exact equality, and still writes nothing. The strike note above this bullet,
    written at commit 2, says this clause "stands"; that was true of the property and wrong about
    the status code, and this is the correction.)* and writes nothing. That turns the defect
    ADR-0025 decision 1 names for *held* addresses (*"silently repoints a held URL"*) into a correct
    refusal at the only moment the set is read.

**What this does to ADR-0025.**

- **Decision 1 is untouched.** No derived address exists, the Risk still has no identifier, and
  there is still no per-Risk route.
- **Decision 2's clause is struck and replaced**, in that ADR's dated Amendments section rather
  than in line. The clause is *"Those are also the first values about a Risk that cannot be
  recomputed"*.
  - **Why a strike, not a qualification.** A stored narrative is a counterexample, and it arrives
    at M7.2. So the clause is false as written.
  - **Why the conclusion survives.** The conclusion rests on a property the counterexample lacks.
    A dismissal must stay attached to a Risk across membership change; a narrative describes one
    decision over one member set and must not.
- **This is not cost-forced persistence.** The amendment ADR-0025's Consequences names for cost
  stays with **G61** and M8.2.

### 2. What a `SecurityBrief` holds, and the edge that costs

**Fields.** `id`, `project_id`, `finding_ids: tuple[str, ...]`, `decision: ExplainableDecision`,
`explanation: Explanation`, `generated_at` (via `ClockPort`, rule 14).

- **`decision` is the narrator's input, whole.**
  - The live score can move for an unchanged set (6 → 7 above), so `/scored-risks` cannot stand in
    for what was narrated.
  - Rule 5: a stored score without its signals and thresholds is an unexplained number. ADR-0030
    decision 3: *"re-deriving the **bucket** needs the thresholds"*.
  - Rule 6: the narrative can be checked against the decision it was given.
- **`explanation` is *why it matters* plus its producer.** `Explanation`'s docstring: *"Both exist
  so a narrative M7.2 persists stays traceable to its producer"*.
- **FR-8 parts covered: two of six.** *Why it matters* (the narrative) and *evidence sources*
  (`finding_ids`; ADR-0022 decision 1: *"An addressable route is that link"*).

**Considered and rejected:**

- **`risk_id`**: decision 1.
- **`what_happened`, `recommended_action`**: scanned content with no producer. Their only
  justification is a later issue, the shape ADR-0021 refused: *"a column plus a domain field plus a
  migration to describe a state nothing has ever reached"*.
- **`estimated_effort`**: no producer, and ADR-0032's prompt forbids guessing *"how much effort a fix
  takes"*. Whether an LLM may ever supply one cannot be decided against an input that does not exist
  yet, so it is deferred (**G74**).
- **`confidence`**: **G63**. Its absence is asserted.
- **`package` and `url`**: scanned content (ADR-0032 decision 2), and already on `/scored-risks`.
- **Evidence URLs or tool names**: ids suffice, and the tool is `EvidenceResponse.source_tool`.
- **Separate `priority` / `priority_score` columns**: they would split the decision from its
  working.
- **An `is_current` flag**: it would recompute on every read (**G61**). A client's join answers it.
- **A per-Brief normalization snapshot**: decision 4.
- **`generated_by`, usage, tokens**: no consumer. ADR-0032: *"`Explanation` does not carry usage"*.

**`brief/domain` holds the published carrier, which makes it the first `domain/` package in the
tree to import another module.** It is legal:

- Rule 3 permits a published port.
- Rule 1 concerns frameworks, and the carrier is two frozen dataclasses with no imports.
- `cross-module-brief` forbids `risk_engine.domain` and `.adapters`, not `.ports`.

It is chosen on its own merits:

- **A Brief is the record that *this decision was narrated as this text*.** The decision is part of
  the fact being modelled, not a value in transit.
- **The alternative is a brief-owned copy type.** Its real advantage is decoupling stored rows from
  `risk_engine`'s evolution. Its defect is that when the carrier gains a field, the narrator is shown
  it and the copy stores without it, at a storage boundary where no test fails (**G33**'s narrowing).
- **Holding the published type makes what is stored equal what was shown, by construction.**
- **The cost:** `brief`'s domain changes whenever `risk_engine`'s published carrier does.

**No contract covers this edge.** `layers-brief` has `containers = ["verion.modules.brief"]`, so a
contract named *"brief: adapters -> application -> ports -> domain"* relates layers inside `brief`
only. It stays green whatever `brief/domain` imports from elsewhere. Registered as **G77**.

**The stored decision is versioned, and carrier evolution is made loud by mechanism.**

- **The version.** The `decision` JSONB value carries `"version": 1`, an in-value marker on ADR-0019
  decision 6's `v1:` precedent. ADR-0025 decision 3 names when such machinery is owed: *"it exists
  because stored values outlive the function that produced them"*. Here they outlive a type another
  module owns.
- **The serializer derives its keys.** `_decision_to_json` builds every key from
  `dataclasses.fields(ExplainableDecision)` and `dataclasses.fields(ExplainableSignal)`. A carrier
  field therefore cannot be silently left out of a stored row, even with no test.
- **A pinned v1 test** asserts that a literal v1 key enumeration **equals** that derivation, and that
  the serializer's output keys equal it too. A carrier change then fails in `brief`'s suite, and the
  same commit must bump the version and keep a v1 reader, or migrate the rows.
- **Unknown versions** are read as `StoredBriefUnreadable`.

### 3. Repeat generation is append-only

- **No uniqueness and no deduplication.**
  - A unique `(project_id, finding_ids)` would forbid regenerating after a rescore, which happens
    for an unchanged set.
  - Returning an existing row for an identical input would remove the only way to get a different
    narration of a non-deterministic narrative. It would also choose a regeneration policy that no
    consumer at HEAD has asked for.
- **What a client does.** The list is ordered by `generated_at` descending, then by `id`. The current
  Brief for a surface is the first item whose `finding_ids` equal the surface's. Later items for the
  same set are history, and `decision.priority_score` against `/scored-risks` shows whether the
  decision moved.
- **The cost is stated, not denied.** Every POST is a billed provider call, and nothing bounds how
  many a member sends. The bound belongs to request rate limiting at M10.2 (ADR-0022 decision 1:
  *"independently rate-limitable at M10.2"*), and it is registered with ~~**G73**~~ **G100**
  *(M8.6 commit 3: G73 resolved on its session half and the repeats half became its own entry, on
  G53 → G95's shape. A pointer at G73 now lands on a resolved entry.)*.

### 4. One list-shaped read, and no completeness envelope on either route

```
POST /projects/{project_id}/briefs          # body {finding_ids}; 201, the stored Brief
GET  /projects/{project_id}/briefs          # paged; each item carries its finding_ids
```

*(Amended 2026-09-21, M8.6 commit 3, ADR-0038 decisions 1 and 8. The POST's row above is
superseded: it answers **202** with `{id, status}`, and a third route,
`GET /projects/{project_id}/brief-generations/{id}`, reports the outcome. The `GET …/briefs` row
is unchanged, and this decision's own subject — one list-shaped read, no completeness envelope —
survives whole: the poll is not a second read of a Brief and carries no envelope either.)*

**Why a list rather than a GET by id.** A client listing `/scored-risks` holds `finding_ids` and no
id. A by-id route would serve only the caller that just generated a Brief. The list serves the client
that exists, by a local join, with no derived address in any URL.

**Why not a GET by set.** It is the address G68 rules an amendment, and its URL length is unmeasured.

**Why no envelope.** The question is not item versus list. It is whether a completeness envelope
answers a question about this response.

- **What the envelope is for.** ADR-0022 decision 3 defines it: *"`unfinished_runs` is what answers
  'may this list be incomplete?'"*. Every route carrying it is a live projection whose items are
  missing exactly while normalization is owed.
- **A Brief list is not owed by any pipeline.** Its rows exist only because a POST wrote them, so it
  is complete by construction.
- **The reader's real question is historical and per item**: was this narrated decision computed over
  complete findings at `generated_at`? A live envelope describes read time and cannot answer that.
- **A stored snapshot could answer it, but is refused.** No consumer exists; it would be a third copy
  of `NormalizationRun`'s fields (**G67**); and it would be a stored derivable summary (ADR-0019
  decision 1).
- **Consistent precedent.** `EvidenceResponse`, whose content is fixed at capture and carries its own
  provenance, carries none.
- **The live answer is already available.** The listing client has it from `/scored-risks`.

The cost is registered as **G76**.

### 5. Generation does not refuse while normalization is unfinished

Reading `count_unfinished_by_project_id` after authorizing would cost one `COUNT` per request, the
statement `/scored-risks` already runs. **Cost is not the reason to decline.**

- **Refusing would be permanent.** That count includes `failed`, and the sweep never re-enqueues a
  failed run (G15). A project with one historical failed normalization could never generate a Brief
  again, and nothing a client does would change that.
- **This differs from the stale-set 404.** A stale set is a property of the request, fixed by
  re-reading `/scored-risks`. A failed normalization is a property of the project.
- **A narrower refusal does not work either.** Refusing only while a run is pending or running needs
  a status breakdown that no `normalization` port publishes. It would still miss the worse case, an
  old failure, and it races any push.
- **The narration overstates nothing the listing did not already show.** The bucket narrated is the
  one `/scored-risks` showed alongside its own `unfinished_runs` when the client chose the set.
- **The residual cost joins G76.** A billed call can narrate a bucket understated by findings that
  were never produced, and nothing on the row records it.

### 6. The port

`risk_engine/ports/explainable_risk.py` declares:

- `ExplainableRisk`, frozen: `finding_ids` and `decision`.
- `ExplainableRiskPort.explainable_risk(*, project_id, user_id, finding_ids) -> ExplainableRisk`.
- Three denials subclassing `RiskEngineError`: `ExplainableRiskAccessDenied`, `NoCurrentRisk` and
  `ExplainableRiskInconsistent`. They are declared in the port module so that `brief` can name them,
  which is `CandidateRiskAccessDenied`'s shape.

It is implemented in `risk_engine/application/` over `ComputeRiskUseCase`, on
`CorrelationCandidateRisks`'s precedent:

- It does no ranking and no envelope reads.
- It fills `decision` through `explainable_decision`, and takes `finding_ids` from the matched
  surface rather than from the request.
- It translates `CandidateRiskAccessDenied` and `MemberFindingMissing`.

**Import edges.** The edge from `brief` to `risk_engine.ports` is governed by `cross-module-brief`.
`risk_engine`'s domain exceptions reach `brief` only indirectly, which `allow_indirect_imports = true`
permits. No contract changes, and G35 stays open.

### 7. Authorization

**Generation is member-level**, inherited through the port (ADR-0030 decision 1's shape).

- **G70 names this option.** Its Deferral rationale says a route needs *"either a second verdict on
  that port or a stated reason to accept the read verdict"*.
- **In production, member-level coincides with owner-gating.** The only place `src/` constructs a
  membership is `CreateProjectUseCase`, with `Role.OWNER`, and `scripts/seed_findings_benchmark.py`
  also writes owners. So ADR-0016 decision 3's owner-gating of costly writes is satisfied by
  coincidence, not by design.
- **In the test suite it does not coincide**: `Role.MEMBER` is seeded directly in 14 files. A route
  test pins a `Role.MEMBER` generation at ~~201~~ **202** *(M8.6 commit 3: the status moved with
  ADR-0038 decision 1, and the pin now also covers the worker's re-authorization, since the test
  runs the job and asserts the generation succeeded — so **both** of decision 4's gates are shown
  to admit a plain member, where before there was one)*. **G75** carries the day the two diverge.
- **This reason does not decide G70.** ADR-0016 decision 3 gated a write that *"costs real compute
  and can point an attack tool at a URL"*, with both conditions together. A Brief costs money and
  nothing else. A scan trigger also mutates `Scan` state under consent that is itself owner-gated
  (G49).

**The list consumes `ProjectAccessPort` directly** (ADR-0022 decision 2). It reads only `brief`'s own
table, so no inherited path exists for ADR-0030 decision 1's *"second copy of one authorization
rule"* to describe.

**Both routes answer 404 for both denials** (G17).

### 8. Generation is synchronous, on the request path

**REPLACED 2026-09-21 (M8.6) by ADR-0038 decision 1.** Generation is a job and `POST` answers 202.
This decision is left standing as written, per the rule against editing an accepted Decision in
line. **Both grounds are false and both are struck in line below.** The second was *declared* false
by the 2026-09-17 amendment, which struck nothing here; it is struck now, so this decision's text
no longer reads as live on a ground the record has called false for four days.

§8 left *"how it is triggered"* to this milestone. Generation runs inside `POST`, and **G73** records
what that costs.

**A queue trigger is not built.** It would be ~~a pipeline stage this project has not designed, for
a latency nobody has measured~~. *(Second ground declared false 2026-09-17 and struck in line here;
**first ground struck 2026-09-21, M8.6**, as false: `platform/worker.py` runs two job functions and a cron, three queue
adapters exist, `platform/db.py` has `after_commit`, and M8.8 shipped a 202-plus-poll route over
it. ADR-0038's Context.)*

**Some write path must ship.** ADR-016 decision 3 already names what the alternative would be:
*"dead-by-construction: code that cannot execute in a running system because nothing can write the
configuration that enables it"*.

### 9. Error mapping

**`POST`:**

| Condition | Status | Detail |
|---|---|---|
| Access denied | 404 | as the sibling routes |
| `NoCurrentRisk` | 404 | fixed, telling the client to re-read `/scored-risks` |
| `ExplainableRiskInconsistent` | 500 | fixed (ADR-0030 decision 5) |
| `ExplanationUnavailable` | 502 | fixed, never `str(exc)` |
| Empty or duplicate `finding_ids` | 422 | |

*(Amended 2026-09-21, M8.6 commit 3, ADR-0038 decision 6. **Rows 2–4 are superseded**: those three
failures no longer happen in the request, so the POST cannot report them. It answers 202, and the
job maps five terminal failures onto three `failure_kind` values the poll reports — `NoCurrentRisk`
to `surface_changed`, `ExplanationUnavailable` and `WhatHappenedRejected` to `provider_unavailable`,
`ExplainableRiskInconsistent` and `BriefMemberMissing` to `internal_error`. Rows 1 and 5 stand: the
access denial is still a 404 from the route's own `may_read_project`, and the 422 is still the
request schema's. **This decision's own subject survives** — fixed details, never `str(exc)` — and
is now held by a dict in the router keyed on `failure_kind`, with no stored `detail` column for a
provider's words to reach. This site was NOT on ADR-0038's owed list; it was found by the guardian
grepping `502` across the tree.)*

No maximum length is set: nothing bounds a surface's member count, and request limits are M10.2's.

**`GET`:**

| Condition | Status | Detail |
|---|---|---|
| Access denied | 404 | |
| `StoredBriefUnreadable` | 500 | fixed |

**Skipping an unreadable row is rejected**, because it would hide data loss behind a shorter list.
**So one unreadable row is a project-wide read failure** for `GET …/briefs`, until that row is
migrated or a reader for its version ships.

## Consequences

**Rule 16 fires on four clauses:** a migration (`security_briefs`); new frozen domain and carrier
types (`SecurityBrief`, `ExplainableRisk`); an authorization control (the list's `ProjectAccessPort`
consumption, and the member-level acceptance); and two routes with their request and response shapes.
This ADR is what the implementation commit cites.

**Carrier evolution is loud only because of a derivation.** A change to `ExplainableDecision` or
`ExplainableSignal` fails loudly because `_decision_to_json` derives its keys from `dataclasses.fields`
and the pinned v1 test compares a literal enumeration against that derivation. **Rewriting the
serializer field by field, or pinning the test against its own output, makes carrier evolution silent
again.** A field change to the carrier, which rule 16 routes through an ADR, must ship a v1 reader or
a data migration in `brief` in the same commit.

**Re-adding a scanned-content part re-fires rule 16's clauses.** If *what happened* or *recommended
action* is added later, the migration, frozen-type and response clauses fire again. That is accepted
rather than pre-declared as empty columns.

**The list's bulk shape carries no scanned content today.** Decisions, fixed definition strings, ids
and a narrative written from them are not the source-code export ADR-0022 decision 1 guards against.
This is re-read when M7.3 widens what the prompt sees.

**G61, per generation.** Generating a Brief runs `ComputeRiskUseCase` once, which is the whole doubled
findings read, plus one provider call. The list never recomputes. The provider term is unmeasured
until the capture that ends M7.1's departure.

**That capture is owed and not taken.** M7.2's `POST` is the first call to `explain` outside a test.
The capture is not taken because `OpenAIExplanationProvider._parse` reads only `choices` and `model`
and discards `usage`, so recording the response whole needs recording tooling that does not exist~~
and a transport or adapter change this issue does not make~~ *(clause struck 2026-09-17 as false;
ADR-0032's M7.3 amendment striking the adapter-change clause)*. The 30 s timeout stays unmeasured for the
same reason. Recorded in ADR-0032's Amendments and in `ROADMAP.md`'s M7.2 entry. The dated line
that re-dates M7.1's departure belongs to the implementation commit, because that commit is the one
that first calls `explain`.

**Register.**

- **Opened by the commit that lands this ADR:** **G73**, **G74**, **G75**, **G76**, **G77**.
- **Notes from that commit:** **G11**, **G37** and **G68**. In each, the decision discharges a *"M7.2
  may be forced to store a Risk"* qualification.
- **Notes from the implementation commit:** **G11** again (the table it ships), **G17**, **G33**,
  **G61**, **G63**, **G65**, **G67** and **G77**. **G68** resolves there.

**Owed by the implementation commit**, listed here so a reader of this ADR finds them:

- **Copies of the clause ADR-0025's amendment strikes:**
  - `ComputeRiskUseCase`'s docstring: *"a dismissal is the first value about one that cannot be
    recomputed"*.
  - `CorrelateFindingsUseCase`'s class docstring: *"M8.1, the first issue with a value that cannot be
    recomputed"*.
- **The comment above `_TIMEOUT_SECONDS` in `openai_adapter.py`**: *"M7.2's first real call path is
  where it is measured"*. It gets the reason from ADR-0032's amendment.
- **The *"Risk address"* wording** in `risk_engine/application/explainable_decision.py`'s docstring.
  It becomes the finding-id set held as data.
- **`ExplainableDecision`'s docstring**: one sentence naming `brief`'s stored rows as a pinned
  consumer.
- **`ARCHITECTURE.md`**: §4.1's `SecurityBrief` block, which still reads `id, risk_id`; §4.2's ERD;
  §5.1 and §5.2's rows, including the explanation-provider row saying M7.2's `SecurityBrief` *"is to
  carry"* the narrative; §6.1, §6.2, §7, and §8's `Brief->>` lines and trigger sentence.
- **`ROADMAP.md`'s M7.1 departure**: the dated line.

## Amendments

- **2026-09-17 (M7.3, ADR-0034): decision 2's rejection of `what_happened` is superseded, and its
  parts count moves from two of six to three.**
  - **What decision 2 said.** `what_happened` was rejected as *"scanned content with no producer"*.
  - **What changed.** ADR-0034 gives it a producer: a second narration, from typed member fields,
    through a separate provider call. `SecurityBrief` gains `what_happened: Explanation | None`, where
    `None` means a row written before M7.3. `recommended_action`, `estimated_effort` and `confidence`
    stay rejected on decision 2's grounds (**G74**, **G63**).
  - **What does not change.** `decision` and its version, the append-only write, and the list's shape.
- **2026-09-17 (M7.3, ADR-0034): the Consequences re-read is taken.** *"The list's bulk shape carries no
  scanned content today … This is re-read when M7.3 widens what the prompt sees."* From M7.3 each item
  carries *what happened*, prose written over typed member titles and locations. ADR-0034 decision 6
  keeps it on the list whole, because those inputs are fields the findings listing already returns in
  bulk, and ADR-0022 decision 1 drew the bulk line at `raw_payload`.
- **2026-09-17 (M7.3): the Consequences clause *"and a transport or adapter change this issue does not
  make"* is struck in place as false**, for the reason in ADR-0032's M7.3 amendment striking the adapter-change clause.
- **2026-09-17 (M7.3 capture commit, ADR-0034): decision 8's second ground is false, and decision 8
  stands until something replaces it.**
  - **What decision 8 said.** A queue trigger is not built: *"a pipeline stage this project has not
    designed, for a latency nobody has measured"*. *(Left unstruck 2026-09-21, M8.6 commit 2, and
    deliberately: this is a QUOTATION inside a dated record of what the decision said, so striking it
    would falsify the record. Both grounds are now false — see decision 8 and the bullet below. It is
    the fourth of the claim's four sites, and the guardian found it; the three struck ones are
    decision 8, the **What stands** bullet below, and `ROADMAP.md`'s G73 deferral rationale.)*
  - **What changed.** The latency is measured. Over 59 real calls the median is 16.46 s per call, a Brief
    is two calls, and one call hit the 30 s bound (ADR-0032's Consequences). The Consequences sentences
    calling the provider term and the timeout unmeasured describe M7.2 and are superseded.
  - **What stands.** ~~Decision 8's first ground: the queue is undesigned~~, and some write path must ship. *(Struck 2026-09-21, M8.6: the first ground is false too, and this sentence is the second of its four sites — found by grepping the claim rather than at decision 8 alone. ADR-0038 decision 1. The "some write path must ship" half was satisfied at M7.2 and does not bind twice.)*
  - **Where it goes.** ADR-0032's M7.3 capture amendment hands the timeout's value to the work that makes
    generation asynchronous, **G73**'s queued job. That work re-decides this decision, and ~~no issue
    schedules it~~. *(Struck 2026-09-21, M8.6 commit 2: **M8.6 schedules it**, and ADR-0038 replaces ADR-0033 decision 8. Assigned to M8.6 at the 2026-09-19 boundary review. Three sites, found by grepping the claim.)*

- **2026-09-20 (M8.5, documentation commit): decision 2's rejected `confidence` is DECIDED IN — a `SecurityBrief` is to gain the field and `security_briefs` a nullable column.** ADR-0037 decision 8. **This commit writes no `src/` and adds no migration**; both land in M8.5's second commit, and the discharge takes effect there.
  - **What decision 2 said**: *"**`confidence`**: **G63**. Its absence is asserted."* The ground it rested on — *"either scale reaches a third module"* — was true and is now paid: M8.5 reaches all three, `correlation` producing the value, `risk_engine` folding it and `brief` storing it.
  - **The field, as decided.** `SecurityBrief.confidence: Confidence | None`, with `None` meaning **a Brief written before M8.5** and nothing else, exactly as `what_happened` means a Brief written before M7.3. Generation never writes `None`. The column is nullable and is **not backfilled**: the surface a stored Brief describes may have moved, so there is nothing to compute it from.
  - **Its own column, NOT a field on the stored decision, and the ground is rule 6.** `ExplainableDecision` is *"everything a narrator may see"* and is frozen so rule 6 holds by the type; ADR-0037 decision 9 forbids the narrator this value, so putting it there would make that docstring false and degrade rule 6 to a convention. Confidence is also a property of the **grouping**, so it belongs beside `finding_ids`, which is the grouping held as data.
  - **What that placement preserves, and it is the reason for it.** `_DECISION_VERSION` does **not** move, no v1 reader is owed, and **every stored Brief keeps reading back**. A field on the carrier would have made `_decision_from_json` raise `StoredBriefUnreadable` on every existing row, since it derives its values from `dataclasses.fields` — the failure this ADR's Consequences anticipated for a carrier change. M8.5's code commit pins the version as unchanged with a test, so a later issue cannot undo that quietly.
  - **FR-8 is met in all four parts** once that commit lands — *what happened*, *why it matters*, *evidence sources* and *confidence*. Decision 2's *"FR-8 parts covered: two of six"* was accurate when written and is superseded by that count and by `PRODUCT_SPEC.md` FR-8's 2026-09-19 note, which cut *recommended action* and *estimated effort* to V2.
  - **Decision 1 is untouched.** A Brief still has its own id, still holds its member set as data, and still resolves no Risk by it. Decisions 3 to 9 are unaffected; in particular decision 2's rejected **`is_current` flag** stays rejected, and ADR-0037 decision 8 stores the confidence rather than recomputing it on read for that entry's own reason (**G61**).
  - **One residue, registered rather than absorbed.** A stored confidence can go stale when the route map is rebuilt, which **G55** prevents today and **M8.7** enables. **G93** carries it, and `SecurityBriefResponse`'s docstring is to gain the same `/scored-risks` comparison it already teaches for `priority_score`.

## Alternatives considered

**Generate without storing; persist a Risk; key on the match key.** Rejected in decision 1.

**A brief-owned copy of the carrier.** Rejected in decision 2.

**A literal-key serializer with a pinned test.** Rejected in decision 2. A field added to the carrier
would change neither side, so the test would pass while the row silently dropped the field.

**A unique constraint, or deduplication of identical input.** Rejected in decision 3.

**`GET` by id, or by finding-id set.** Rejected in decision 4.

**An envelope on the list; a per-Brief normalization snapshot.** Rejected in decision 4.

**Refusing generation while normalization is unfinished.** Rejected in decision 5.

**Owner-gated generation through a new `projects` verdict.** Not taken, because it would decide G70
(decision 7).

**A queued generation job.** Rejected in decision 8.

**Skipping an unreadable stored row.** Rejected in decision 9.
