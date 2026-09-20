# ADR-0030 — The scored Risk read surface: where ranking lives, what a response must carry to be re-derivable, and what the first measurement of a scored request does not show

## Status

Accepted — 2026-09-16 (M6.3).

Written and accepted **before any of M6.3's code existed**, on ADR-0025's precedent and for its
stated reason: a decision taken by the session that also writes its tests is taken by whatever
makes those tests pass.

## Context

M6.2 shipped `score_surface`, `ComputeRiskUseCase` and `correlation`'s first published port, and
**no route** — `platform/di.py` wired `ComputeRiskUseCaseDep` with a comment saying nothing consumed
it yet. *(That comment is gone as of this ADR's second commit, which replaced it with the consumer's
name; the sentence is past tense rather than struck, because it is the state this decision was taken
against.)* M6.3's roadmap bullet is titled *"Scoring persistence + API"*, and **as that bullet stood at
`2b38d3b`, immediately before this commit**, two of its three dated annotations had removed the
first half: ADR-0025 decision 1 makes a candidate Risk a projection, and ADR-0005 decision 3 scores
per request persisting nothing. The third added an obligation rather than removing one — ADR-0022
decision 2's authorization shape. *(This commit appends two more annotations, so that count is dated
rather than current.)*

Decided elsewhere and **not reopened**: the optional early write stays untaken, so **G37** and
**G11** remain latent and M8.1 remains the forced one; ADR-0005's function and thresholds.

One constraint orders the rest. `GET /projects/{project_id}/risks` already exists, served by
`correlation`, and `tests/integration/test_risks_routes.py` pins eight things it does not claim.

## Decision

### 1. A new route under `risk_engine`, coexisting with M5.2's

```
GET /projects/{project_id}/scored-risks
```

**Adding scores to M5.2's route was the cheaper option and is rejected on a mechanical ground before
a design one.** `cross-module-correlation` forbids `verion.modules.risk_engine.domain`, so a
response mapper in `correlation` cannot **annotate** `ScoredSurface` — and `mypy --strict` requires
an annotation on every parameter, the same constraint `ComputeRiskUseCase` already documents about
its own helpers. The mapping would have to survive on inference inline in correlation's handler:
legal, and it puts FR-7's output in FR-6's adapter, against `ARCHITECTURE.md` §3 and against
ADR-0005's own rejected *"score inside `correlation`"* alternative.

**Retiring M5.2's route here is also rejected** — not for lack of a case, but because the case
belongs to the issue with a consumer. Rehoming ADR-0025 decision 5's eight negative-claim tests is a
second deliverable. What that leaves open is registered as **G66** rather than decided here.

The path names the content on this project's own domain vocabulary — `ScoredSurface`,
`score_surface`, `priority_score`. **What it does not name is the ordering, which is the only thing
distinguishing the two routes; that residual is G66's**, stated there rather than softened here.
Two other spellings are rejected under *Alternatives*.

**404 for both denials**, inherited through `CandidateRiskPort` rather than through a second
`ProjectAccessPort` consumer: a direct dependency here would be the second copy of one authorization
rule that ADR-0022 decision 2 exists to prevent. How that inheritance flows, and what the roadmap
bullet gets wrong about it, is recorded under *Consequences*.

### 2. Ranking is a pure domain function, under a second use case

`ComputeRiskUseCase` is **unchanged**, so its *"Returns `correlation`'s group order, NOT a priority
order"* and the test pinning that both stay true. `ListScoredRisksUseCase` composes it and carries
ranking, paging and the envelope — ADR-0025 decision 4's shape one module over.

**Ranking is domain, not a sort in the adapter**, which would put the ordering contract where no
unit test reaches it. `rank_surfaces` orders by `priority_score` descending, then by the tuple shape
`_group_order` uses, so **within equal scores the two routes agree**. Copied rather than imported,
for the reason `_group_order` gives about copying `_representative_key`.

**That agreement is an invariant over two functions in two modules, one of them private, and a
claim in prose over exactly that is this project's recorded failure class.** So it ships with a test
importing **both** orderings — `tests/` is not bound by `lint-imports` — asserting they agree on a
tie. Without it the copy asserts nothing and a divergence is silent.

Paging reuses M4.5's bounds, **declared locally** rather than imported from another module's
`application/`, which would pass `lint-imports` and violate rule 3 (**G35**) — the choice
`ListProjectRisksUseCase` made, with the same entry named at the site. `total` is exact.

### 3. What the response carries, and why the thresholds sit on the envelope

Per item: `match{package, url}`, `finding_ids`, `finding_count`, `priority_score`, `priority`, and
`reasoning{severity, exposure, corroboration}`, each signal carrying `name`, `value`, `produced_by`
and `note`. Dedicated Pydantic schemas throughout, never the domain type (rule 10).
**Enumerated here rather than left to `ScoredSurface`, because that type does not have this shape**:
`match` is its `package`/`url` and `finding_count` is `len(finding_ids)`, both assembled by the
adapter. The first three fields are exactly `RiskResponse`'s, which is what makes this response a
superset of M5.2's and is the claim **G66** rests on — so that entry is true only if this list
ships.

Asserted absent, each with a test: `confidence` (**G63**), `id`, `raw_payload` anywhere in the
serialized body, `dedup_hash` as a field of an item, `resolved`/`is_open`/`status` on an item, and
any absolute worker filesystem path — counterparts to `test_risks_routes.py`'s eight, written to
their shape.

**The enumeration above is binding, and an absence list cannot bind it.** A test asserts the item's
key set **equals** that enumeration exactly — an extra field and a missing field both fail — because
those absences constrain what must not appear and say nothing about what must. Without it this
decision and **G66** go false together with every gate green: G66's superset claim holds only while
`match` and `finding_count` are actually shipped, and no absence test would notice their loss.

On the envelope: `total`, `limit`, `offset`, decision 4's completeness envelope, and
`ThresholdsResponse{fix_now_at, plan_at}` populated by name from **`FIX_NOW_AT` and `PLAN_AT` in
`risk_engine/domain/scoring.py`** — the module that already declares them so `bucket_for` and every
boundary assertion cannot drift apart. A test asserts the envelope values **are** those constants
rather than literals, so the field cannot drift from the function it describes.

**On the envelope and not the item** is rule 5 read precisely: `RiskReasoning` gives each signal's
value and the member that produced it, so a reader re-derives the **sum**; re-deriving the **bucket**
needs the thresholds, which ADR-0005 decision 1 claims is possible by hand. Per item they are a
constant repeated once per surface — the speculative shape ADR-0016 decision 3 and ADR-0021 both
refused.

### 4. The completeness envelope is carried; widening the port to supply it is rejected

Same two facts and six fields as ADR-0022 decision 3 and ADR-0025 decision 4. The argument transfers
with more force: a scored listing that looks clean while three normalizations failed presents a
**priority order** built on findings that were never produced. Returning fewer fields than the
sibling route is also two routes answering one question differently — **G17**'s shape one level
down, decision 4's own words.

**Widening `CandidateRiskPort` to supply the envelope is rejected on ADR-0005 decision 3's own
ground**: it would make `correlation` decide what `risk_engine` needs. That ADR refused the same
widening for per-finding scoring scalars, and the envelope is a weaker case for it, not a stronger
one. So `risk_engine` reads `NormalizationRunRepositoryPort` itself and fills a frozen carrier of
its own, field by field off the port's return value, never naming `NormalizationRun`.

The cost is named rather than absorbed: that carrier is the **second** of its kind —
`correlation`'s `LatestNormalizationRun` is the first, while `normalization` holds the entity
itself — and the obvious later repair puts a *transported* structure in `shared_kernel/`, against
the criterion ADR-0018 set and ADR-0025's Consequences already applied in declining exactly this.
Registered as **G67**.

### 5. `MemberFindingMissing` is a 500, chosen rather than inherited

Caught in the route and re-raised as a 500 with a fixed generic detail, `from exc`. Not a client
error and not retryable: its own docstring calls it a guard against the two reads disagreeing, and
nothing deletes a finding today (**G11**). **Caught rather than left to propagate**, because §9 has
inbound adapters translate domain errors to status codes — an uncaught domain exception reaching the
framework's default handler is the framework translating it, and the mapping would be a default
nobody can point at. Covered by an integration test overriding `get_candidate_risk_port` with a port
naming an id the findings read will not return; **that test does not exercise the real adapter**,
said here so it is not confused with decision 7's.

### 6. G64's closure is stated at the surface and pinned by an assertion

This route is the first place the scoring order is shown to anyone, which is **G64**'s own trigger,
so silence is not available. The route and `ScoredRiskResponse` docstrings carry the closure —
`fix_now` has one reachable decomposition, so a `CRITICAL` dependency CVE tops out at `plan` however
severe — in the terms G64 and `score_surface`'s docstring already state, cited rather than restated.

**A docstring alone is a comment; an assertion makes it a claim.** An integration test seeds a
`CRITICAL` package finding and asserts that item returns `plan` at 5 and that no item in the
response is `fix_now` — the endpoint-level twin of
`test_a_critical_package_surface_scores_five_and_buckets_plan`.

No response **field** asserts the closure: it is a property of the function and of no individual
Risk, and a field asserting it would fabricate rather than report (ADR-0025 decision 4). The closure
is already *locally* visible per item through `Signal.note`; what the docstrings add is the global
claim those notes cannot make.

### 7. The first measurement of a scored request, and what that phrase means

**The framing this issue was scoped against was wrong and is corrected here rather than quietly
dropped.** It held that measuring required extending `scripts/seed_findings_benchmark.py` to emit
production-shaped packages and URLs — conflating *measure a scored request* with *measure a
production-shaped grouping*. **G61 names the first.** Both `get_by_project_id` calls are the same
statement over the same rows whatever `package` and `url` contain; grouping happens between them, in
Python. So the doubled read is measurable on the generator as it stands.

Measured: one request at ADR-0025's volume, over **eight or more runs reporting plans rather than an
average**, on that ADR's precedent since it found the evidence join bimodal, with the two reads
timed separately. It stays a **dated manual run** recorded in this ADR's Consequences, per ADR-0022
and ADR-0025, not a CI test — a 100k-row seed is container-bound and the script's docstring records
why that was rejected.

The script gains **one `projects` row and one `project_memberships` row**, because
`ProjectAccessPort` refuses without them, plus their marker-scoped deletes. **No generated finding
value changes.** That still fires **G19**, whose trigger is anybody extending a generator, and the
answer is correspondingly short: no emitted finding value moved.

**The Python-side figure is reported as an UPPER BOUND with its shape beside it, never as a bare
"a scored request costs X ms".** Every generated finding carries `package: None` and `url: None`, so
2,000 findings become 2,000 singleton surfaces, each single-source with corroboration 0 — the worst
case for per-surface overhead and not a production grouping. Also recorded: the total is **not** 2×
the first read, because the second hits a warmer buffer cache; and the Python-side cost — the
`by_id` dict and the per-surface `score_surface` calls — has never been measured at any volume.
Populating `package`/`url` would widen the rows, so "same statement, same rows" bounds the grouping
and not the plan; each read's plan is therefore reported.

## Consequences

**ADR-0025 decision 5 items 1 and 5 stay true**, because M5.2's route is untouched. That second item
was re-derived while deciding this: its `zzz`/`CRITICAL` finding scores `5 + 0 + 0 = 5 → plan` and
its `aaa`/`LOW` finding `2 + 0 + 0 = 2 → monitor`, so the two orders genuinely disagree and a ranked
route would have failed `test_the_item_order_is_not_a_priority_order` loudly rather than passing
vacuously. An earlier reading claimed both bucket as `plan`; it was wrong, and the test
discriminates.

**The M6.3 bullet's *"authorize through `ProjectAccessPort`"* is wrong about the mechanism and right
about the obligation.** `risk_engine` does not consume that port. `CandidateRiskPort`'s
implementation wraps `CorrelateFindingsUseCase`, which reads `ProjectAccessPort` as its first
statement; `CorrelationCandidateRisks` translates the refusal into `CandidateRiskAccessDenied`, and
the route answers 404. That bullet carries a dated marker saying so. This is the **fourth** route
answering 404 for both denials while `projects`' own routes answer 403 — **G17**, as its own post-M4
note forecast. The count of those 403 routes is deliberately not restated here: **G18**'s dated note
of 2026-09-09 already moved it from six to eight, and G17's own post-M4 note still carries the
retired figure. *(An earlier draft of this sentence reintroduced "six"; the guardian round caught
it, which is the same figure-rot G18's note exists to have stopped.)*

**A scored Risk still carries no `confidence`** (**G63**), and the response asserts its absence, so
FR-7's second output stays unmet by shipped code at the surface a user sees. M7.1 chooses the scale.

**So M6 closes without one of the outputs its own Goal names.** `ROADMAP.md`'s Milestone 6 reads
*"correlated Risks get an explainable priority and confidence. FR-7"*, and the confidence is
deferred to M7.1. The commit that marks M6.3 done therefore carries a **dated qualification on that
Goal in the same commit** — a qualification and not a strike, since two of FR-7's three named
outputs ship — so that no window exists in which the roadmap asserts a goal it did not meet.

**This takes M6's second and last ADR slot**, per the budget G63's note records.

### The measurement decision 7 owed, and it does not support the decision that prompted it

Taken 2026-09-16 at ADR-0025's volume — 100,000 findings across 50 projects, 2,000 in the measured
project by its own guard counts — with one discarded warm-up per subject and eight readings each,
all printed:

| subject | min | median | max |
|---|---|---|---|
| `get_by_project_id`, end to end | 84.1 | **108.8** | 136.6 |
| `GET /risks` — ONE read | 94.8 | 144.1 | 150.9 |
| `GET /scored-risks` — TWO reads + scoring | 253.8 | 259.5 | 335.8 |

Query 5's plan reproduced ADR-0025's slower mode both times it was run: `Hash Right Join` with a
`Seq Scan` over all 100,000 evidence rows, `Execution Time` 25.943 then 26.661 ms.

**The doubled read is the larger term on every estimator** — it covers 94.4% of the route gap at
the medians, 52.9% at the minima and 73.9% at the maxima. Eight readings with this dispersion do
not pin it tighter than *between about half and nearly all*, and decision 7's upper-bound condition
applies to the residual rather than to this: the 6.5–74.9 ms left over is scoring over **2,000
singleton surfaces**, the worst case, which real grouping shrinks — while the read term is
shape-independent and does not.

**End to end is 4.08× `EXPLAIN`'s server-side figure** (108.8 against 26.661), the difference being
driver round-trip, transfer of 2,000 rows ~872 bytes wide, and hydration. An earlier reading
subtracted the `EXPLAIN` number from an end-to-end difference and concluded the second read was the
*minor* half — **16.6% at that run's medians, 18.1% at its minima**, re-derived from its own output
rather than restated. That is backwards, and it is recorded here rather than quietly corrected
because **G61** is the entry that would have inherited it. ADR-0025 had already warned against
exactly this — *"do not quote the milliseconds as production latency"*.

**What this does to ADR-0025 decision 1.** That ADR states a bad number is *"evidence AGAINST
decision 1, not a tuning task"*, and that cost-forced persistence would be *"an amendment to this
document and not a follow-up"*. Per-request purity buys the doubling, and the doubling is the
dominant term. **That is a claim about how the cost SPLITS, and it is not by itself the claim that
the premise failed** — the criterion is *cheap to recompute*, a read at 94% of a 5 ms gap would
falsify nothing, ADR-0025 sets no threshold deliberately, and the only scale it offers is the
**763 ms** it records for ADR-0022's pre-rewrite query against **259.5 ms** here at a worst-case
shape. What the measurement does establish is the **shape**: the dominant term is the one
production grouping cannot shrink, while the residual is the one it can. This ADR does not take the
amendment — M6.3's scope is a read surface and the write was declined at design time — and it does
not overstate the finding to compensate.
**G61** carries the escalation and ADR-0025 carries a dated note beside the paragraph that set the
criterion.

**Register**: **G66** and **G67** are opened by the commit that lands this ADR, which also carries
**G33**'s dated note — written before any of M6.3's code, since its subject is what M6.2 built.
**G17**, **G19**, **G38**, **G61**, **G64** and **G65** are owed dated notes by the **second**
commit, the one that ships the route, because each records what that commit did. *(An earlier draft
of this paragraph said all seven already carried notes, which its own commit falsified.)*
**G37** and **G11** get none, deliberately: a fired
*trigger* is recorded, an unfired *conditional* is not. G38 names M6.3 as a trigger and gets a note
saying its condition is unmet; G37 and G11 say *"if M6.3 takes the write"*, which stays true
afterwards and reports nothing.

## Amendments

- **2026-09-20 (M8.5, documentation commit): decision 3's enumeration is amended on BOTH halves — the item is to gain a field and the ENVELOPE one. The binding key-set assertion widens to match.** ADR-0037 decisions 8 and 10. **This commit writes no `src/`**; both land in M8.5's second commit.
  - **The item** gains `confidence`, a Risk's grouping provenance: `ungrouped`, `reported` or `inferred`. The per-item enumeration is therefore `match{package, url}`, `finding_ids`, `finding_count`, `priority_score`, `priority`, `reasoning{…}` **and `confidence`**.
  - **The envelope** gains `confidence_definition`, so it reads `total`, `limit`, `offset`, the completeness envelope, `ThresholdsResponse{fix_now_at, plan_at}` **and `confidence_definition`**.
  - **Why the definition is on the envelope and not on the item, which is this decision's own argument applied to a new constant.** It is one constant per response, and decision 3 already put the thresholds there because *"per item they are a constant repeated once per surface — the speculative shape ADR-0016 decision 3 and ADR-0021 both refused."* `SignalResponse` on this route carries no `definition` either. **A Brief carries the same text on its item**, as `{value, definition}`, because a Brief is a single narrated record with no envelope; that divergence is grounded in ADR-0037 decision 10 so it is not read as **G17**'s shape, and a test asserts the two placements are byte-identical from one owner.
  - **The absence list loses one entry.** *"Asserted absent, each with a test: `confidence` (**G63**)"* is discharged by that commit — `test_a_scored_risk_carries_no_confidence` is rewritten into a test that the field is present and what it is. `id`, `raw_payload`, `dedup_hash`, `resolved`/`is_open`/`status` and absolute worker paths all stay asserted absent.
  - **The binding assertion widens rather than loosens**, which is this decision's own point: *"The enumeration above is binding, and an absence list cannot bind it."* The item's key set still must **equal** its enumeration, and the envelope's now does too.
  - **`G66` is struck in part**, and the strike lives on that entry rather than here: its *"the only difference between them is the **ORDER**"* goes false when the field ships, while its superset clause holds and widens, `/risks` gaining neither.
  - **Decisions 1, 2, 4, 5, 6 and 7 are unaffected.** Decision 6's `fix_now` closure is untouched, and ADR-0037 decision 7 records that every surface reaching that bucket is `inferred`.

## Alternatives considered

**Scores added to `GET /projects/{id}/risks`.** Rejected in decision 1: the mapper cannot be
annotated, and inference inline puts FR-7's output in FR-6's adapter.

**Retiring the M5.2 route here.** Rejected in decision 1 as a second deliverable; registered as
**G66** so the question survives with a trigger instead of an opinion.

**`?scored=true` on the existing route.** Rejected on ADR-0022 decision 1's precedent, which refused
`?include_evidence=true` as the same exposure behind a parameter. A flag changing the *ordering
contract* is worse than one changing a field.

**`/{project_id}/risks/scored`.** Rejected: ADR-0025 decision 1 refuses a per-Risk route because a
candidate Risk has no id, and M8.1 may add one — a literal segment in what would become the
`{risk_id}` slot is a collision waiting for that issue.

**Ranking in the adapter.** Rejected in decision 2: the ordering contract lands where no unit test
reaches it, and the two-route tie agreement becomes unassertable.

**Thresholds per item, or omitted.** Per item is a constant repeated per surface; omitted leaves
ADR-0005 decision 1's re-derivability claim false for the bucket.

**Widening `CandidateRiskPort` to carry the envelope.** Rejected in decision 4 on ADR-0005
decision 3's ground.

**Extending the generator's finding shape before measuring.** Rejected in decision 7: it answers a
question G61 does not ask, and it is a benchmark-design project inside a route issue.
