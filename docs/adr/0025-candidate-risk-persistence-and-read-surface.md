# ADR-0025 — Whether a candidate Risk is stored, how it is addressed, and what a Risk read returns

## Status

Accepted — 2026-08-26 (M5.2).

Written and reviewed **before any of M5.2's code existed**, and accepted before it was written,
which is the ordering ADR-0023's 2026-08-26 amendment adopted and gave its reason for — a
decision taken by the session that also writes its tests is taken by whatever makes those tests
pass. Decision 1's premise was then measured before the code too; see *Consequences*.

## Context

M5.8 shipped `MatchGroup` and `CorrelateFindingsUseCase`; nothing persists or returns them.
`ARCHITECTURE.md` §9's idempotency bullet promises *"correlation adds upsert semantics on
Risks"* and is the only clause in that sentence naming no conflict target — this ADR gives it
one or corrects it. Three prior decisions bear directly and are **cited, not re-argued**:
ADR-0019 decision 1 (derived summaries stay derived), ADR-0020 decision 3 (the upsert
transcription's expiry condition, and where the fields that trip it belong), and ADR-0022
decisions 1 and 3 (evidence exposure, and the completeness envelope).

Two things are out of scope by prior decision and are not reopened: ADR-0022 decision 2
(`ProjectAccessPort`, both denials 404) and ADR-0023's 2026-08-26 amendment section 1
(per-project scope). Nothing here decides priority, confidence or reasoning — M5.2's Risk is a
candidate, unscored.

## Decision

### 1. A candidate Risk is a projection, not a stored entity. No `risks` table at M5.2

`correlation` persists nothing. The listing computes groups per request from
`CorrelateFindingsUseCase`. **Nothing before M8.1 is forced to write a row** — decision 2 says
why a score does not force one either.

Two properties decide it, both **STRUCTURAL**, read off `correlation/domain/matching.py` and
`correlation/application/correlate_findings.py`:

- **The match key is not unique across groups, so it cannot be an identity or a conflict
  target.** `group_by_match_key` appends a fresh `MatchGroup` for every no-signal entry *before*
  bucketing, so two no-signal findings in one project always produce two groups whose `key`
  values are equal. **The committed corpus cannot exhibit it, for the reason `G36` already
  gives**: that entry records the corpus *"contains exactly one no-signal finding: one group of
  one under either implementation"*. One no-signal key cannot collide with a second, so the
  collision is unobservable there — and G36's other clause, that on a real repository every
  Semgrep finding is no-signal, is what makes it observable the moment a project has two. This
  rules out identity-derived-from-the-key and any `UNIQUE` constraint over
  the key's fields, before any of the other arguments are reached — but **not** replace-all,
  which needs no conflict target; that is argued on its own merits under *Alternatives*.
  The property is downstream of M5.8's directed choice that a no-signal finding becomes a
  singleton rather than no group (ADR-0023's 2026-08-26 amendment section 2, and `G36` for the
  departure it produced), was not foreseen there, and became visible only when something tried
  to persist a group.
- **A candidate Risk is a pure function of the project's findings.** `execute` reads two ports
  and only one of them contributes to the value: `ProjectAccessPort` gates, and
  `FindingRepositoryPort.get_by_project_id` supplies everything the groups are built from. It
  then calls one total function; no clock, no id generator, no other input, and `_group_order` is
  total so the output does not depend on input order. Storing it is denormalizing a computable
  value, which is what ADR-0019 decision 1 refused for `last_seen_at`/`last_seen_scan_id` and
  what ADR-0022's Consequences re-read and declined again after measuring.

So a candidate Risk **is determined by** `(project_id, match key, ordered finding ids)` and
**has no identifier**.

**Addressability follows, and is decided here rather than left to the endpoint.** An address is
either stored — nothing is — or derived, and all three derivable candidates fail differently:

- **the match key** — collides, by the property above;
- **the group's lowest constituent `finding_id`**, which `_group_order` already uses as its
  total tiebreak — unique per group at an instant, but a lower-id finding joining the group
  silently repoints a held URL at a *different* group instead of failing, which is the
  fabricating direction ADR-0019 decision 3's principle ranks worst;
- **a hash of the ordered ids** — invalidated by every membership change, and it would rebuild
  ADR-0019 decision 6's version-prefix contract for something with no consumer.

**So there is no per-Risk route.** M5.2's bullet — *"endpoint to inspect a Risk's constituent
Findings"* — is satisfied by the listing carrying each group's `finding_ids`, and FR-9's link is
the existing per-finding evidence route, which ADR-0022 decision 1 already established **is**
the link. The cost, named: **M8.3 cannot deep-link to a Risk until a Risk has an id**, which is
M8.1 by decision 2.

**`ARCHITECTURE.md` §9's upsert promise is therefore CORRECTED rather than given a target.**
That correction is an obligation on the commit that lands this ADR; if it does not land there,
it is a register entry, because a falsified sentence in a document nobody re-reads at a
boundary is `G28`'s shape.

**This departs from M5.2's roadmap bullet** — *"`Risk` entity (candidate, unscored yet),
Postgres adapter"* — in its second half. The entity ships as a type; the Postgres adapter does
not. Recorded here rather than left to look like an omission.

### 2. What forces a write is user-settable state, not a score. So the trigger is M8.1

ADR-0020 decision 3 names the fields that break an upsert transcription — *"a dismissal, an
owner, a suppression"* — and assigns them to `Risk`. **Those are also the first values about a
Risk that cannot be recomputed**, which makes the landmine and the trigger the same event
rather than two.

**A score does not force a write, and saying otherwise would leave the trigger wider than the
argument supports.** M6.2 specifies `ComputeRiskUseCase` as pure domain logic over inputs that
are already stored, so a score is derived exactly as the grouping is, and ADR-0019 decision 1's
refusal covers it identically. M6.3 may still choose to persist one — if scoring measures
expensive, that is a projection cost to price, and the choice is open — but choosing it means
taking on this decision's obligation early, and G11's forecast with it.

**The obligation, whichever issue writes first:** decide and record which columns a
re-correlation may not overwrite, and make that a property of the statement rather than a
convention — the shape ADR-0020 decision 1 chose for `findings` by omitting the identity inputs
from `set_`.

Per `CLAUDE.md`'s rule that an ADR deferring with a trigger seeds a register entry in the same
commit, this seeds **G37**, whose trigger is *the first Risk row written* — forced at M8.1,
possible at M6.3. (**G37 and G38 were the next free numbers when they were opened**: the
register ran G1–G36 with no gaps at `d3ca532`, the commit this work started from —
`git show d3ca532:docs/ROADMAP.md | grep -c "^### G"` reports 36. Anchored to a fixed sha
rather than to `HEAD`, which moves: an earlier draft pinned it to `HEAD` believing that was the
safe end, and the M5.2 commit falsified it the moment it landed.)

### 3. A key change re-groups; nothing re-keys

`G31` records that M5.4's active plan splits ZAP's full-`url` key. Under decision 1 the
consequence is confined to the output: the next read returns different groups. **ADR-0019
decision 6's version-prefix machinery is not needed here and must not be copied** — it exists
because stored values outlive the function that produced them, and nothing is stored.

G31 is unchanged and remains M5.4's trigger. What this decision removes is the persistence half
of its blast radius; the grouping half — an over-split with nothing in the output saying so —
is untouched and is still G31's.

### 4. The response carries the same completeness envelope as the findings listing, in a type `correlation` owns

Same two facts, and the same six fields of the latest run, as ADR-0022 decision 3.
`failure_reason` is safe here for the reason that decision gives — it was enforced at the write
— and returning **fewer** fields than the findings route would be two routes answering one
question differently, which is `G17`'s shape one level down.

**`correlation` may not name `NormalizationRun`** (**STRUCTURAL**: `normalization.domain` is a
literal entry in `cross-module-correlation`'s `forbidden_modules`). So the envelope is a frozen
type of correlation's own in `correlation/application/`, its fields filled by attribute off
`NormalizationRunRepositoryPort`'s return value — the idiom `NormalizeScanUseCase` uses for
`ScanResult`, and the one ADR-0023's Decision rests on.

**No third field for the second-order exposure.** G15's post-M4 note is right that a Risk can
look fully evidenced while a constituent finding was never produced, but the number of missing
findings is unknowable by construction, and a field asserting it would fabricate an event —
the failure ADR-0019 decision 3's principle ranks worst. It is stated in the response schema's
docstring and pinned by no number.

The envelope belongs to a second use case, **`ListProjectRisksUseCase`**, rather than to
`CorrelateFindingsUseCase`: that one is the grouping, M6.3 calls it without wanting an
envelope, and its own docstring already declines this question.

### 5. The listing returns keys, finding ids and counts. It inlines no finding and no payload

```
GET /projects/{project_id}/risks
```

Per item: the match key's signal fields, the ordered constituent `finding_ids`, and a count.
**No `raw_payload`** — ADR-0022 decision 1 governs and is inherited, and a Risk correlating N
findings makes its bulk-shape measurement strictly worse. **No inlined finding metadata
either**, which extends that decision one level rather than re-deciding it: the findings
listing already returns that metadata at a route the client holds, and copying it per Risk
multiplies the same bytes by group membership. FR-9's link is the existing per-finding evidence
route. Cost, named: a client rendering this list needs the findings listing too.

Paged on `DEFAULT_PAGE_LIMIT`/`MAX_PAGE_LIMIT`, reusing M4.5's bounds. `total` is exact rather
than a second statement's answer, because the whole group set is computed in one pass — the
READ COMMITTED skew `ProjectFindingsResponse` documents does not arise here.

**The precise claim, because the loose one is false and an earlier draft of this section made
it — then used it to decide test coverage, which is the worse half.** That draft said the
response "carries no `Finding` field at all", and concluded that two of M4.5's four
negative-claim tests needed no counterpart here. Both halves are wrong, and M4.5 had already
worked out the right shape for exactly this: it named its own test *"never a **field** of a
finding"* rather than "never exposed", **because the unqualified version was false**, and
shipped a counter-test for the one path that does expose a hash. The same two corrections apply
here:

- **`match.package` and `match.url` ARE `Location` fields**, carried verbatim — the key the
  grouping is on — and `finding_ids` carries `Finding.id` verbatim too. **What this response is
  held to is the numbered list below: each item a single assertion with a test behind it.**
  Three drafts tried instead to summarise it as one sentence about which fields are absent, and
  two of the three were false — an enumeration asserts about every field it names and every
  field it leaves out, so it is checkable item by item until it is not. The summary is gone
  rather than narrowed a fourth time.
- **A `dedup_hash` CAN reach this response body**, through `normalization.latest_run.failure_reason`,
  which this route returns verbatim. `NormalizeScanUseCase` writes skipped groups' hashes into
  that field deliberately, and the sibling route already pins the same path. So the true claim
  is "never a field of a Risk", and it owes the same counter-test.

**Eight, then, not five, and all four of M4.5's have counterparts.** The absolute-worker-path
one does hold as stated — `rule_id` and `location.file_path` are genuinely not carried — but it
holds as a fact to assert, not as a reason to skip.

1. No `priority`, `confidence`, `reasoning` or score — M6.
2. No `resolved`, `is_open` or `status` — M9.1 owns resolution, M8.1 the lifecycle. The same
   assertion `test_nothing_in_the_response_claims_a_finding_is_resolved` makes, one level up.
3. No `raw_payload` anywhere in the serialized body.
4. **No `id` on a Risk item** — the new one. Decision 1 is what makes it necessary: without it,
   a later reader adds a surrogate and the response starts implying a stable referent.
5. **The item order is not a priority order.** It is `_group_order`'s, which is total and
   deterministic; a group holding a `critical` finding does not sort above one holding a `low`.
6. No `dedup_hash` as a **field** of a Risk item.
7. **And its counter-test**: a hash DOES reach the body via `failure_reason`, asserted rather
   than left implicit, so neither a future whole-body ban nor a future `dedup_hash` field can
   cite the other's test as precedent.
8. No response field carries an absolute worker filesystem path.

Every one of the eight is anchored on a non-empty body, so a regression that empties `items`
turns them red rather than green.

### 6. G11 does not grow here; G17 does

**`G17` grows as M5.2's block forecasts** — a third route answering 404 for both denials while
`projects`' six answer 403. Recorded, not fixed; the convergence direction is G18's at M10.2,
and G17's own post-M4 note already predicted this route.

**`G11` does NOT grow here, and both the forecast and M5.2's bullet are wrong about it.** That
entry's post-M4 note forecasts a fourth table depending on rows never being deleted, from a
`Risk`→`Finding` link. Decision 1 creates no such table, so the forecast moves to **M8.1** —
the same event decision 2's trigger names, and M6.3 only if it takes the optional write. G11 is
`open`, so the note is annotated in place — the distinction `G34` draws about a resolved
entry's frozen fields does not apply.

## Consequences

**The cost of computing on read is MEASURED, and the query is BIMODAL — two plans, both of
which reproduce.** `get_by_project_id` is unpaged and outer-joins `evidence`, so every read
hydrates every `raw_payload` in the project even though correlation reads none of them
(**STRUCTURAL**, from that method and its port docstring). Measured with
`scripts/seed_findings_benchmark.py --projects 50 --findings-per-project 2000`, query 5, at the
volume ADR-0022 used, over a project each run's own `_GUARD_COUNTS` confirm holds 2,000 findings
and 2,000 evidence rows, under `EXPLAIN (ANALYZE, BUFFERS)`. **Eight runs of that one command,
2026-08-26, before any of M5.2's code existed** — a dated record of what was observed, not a
present-tense claim, so re-running it produces new readings rather than falsifying these:

| plan | `Execution Time` | runs |
|---|---|---|
| `Gather Merge` over a parallel nested loop, `Index Scan using uq_evidence_finding_id` | 10.974, 11.426, 12.050 ms | 3 |
| `Hash Right Join`, `Seq Scan on evidence` over all 100,000 rows | 26.293, 27.335, 27.811, 27.948, 30.271 ms | 5 |

**Reported as two plans rather than as a range or an average, and neither is an outlier** — at
three of eight the faster plan is reproducible behaviour, not noise, and a mean would name a
latency no run produced. Every run returns 2,000 rows, and the **findings side is identical in
all eight**: a `Bitmap Index Scan on uq_findings_project_id_dedup_hash`, so **the project filter
already rides an existing constraint index and needs nothing added**. The divergence is entirely
the evidence join.

**What decides which plan is NOT cache state, and the plausible-sounding version of this was
wrong in an earlier draft.** Postgres's cost model takes no cache-state input beyond the static
`effective_cache_size`, so "warm versus cold" cannot select a plan. What did vary across these
runs is the per-`ANALYZE` row estimate on the project filter — **1873, 1980, 2033 and 2007
against an actual 2000** — and the lower estimates coincided with the hash plan. That is
recorded as an **observation, not a mechanism**: nothing here isolates it, and a false mechanism
is worse than none. For scale, ADR-0022 records **763 ms** to serve fifty findings before that
ADR's query was rewritten; the slower plan here serves a whole project for strictly more work.

**What this does NOT measure, named as a trigger rather than left to be found later.** It is
2,000 findings in one project — a volume ADR-0022 chose for a different question. **No project
an order of magnitude larger has been measured**, and ~~this cost scales with a project's finding
count rather than with the number of projects~~ *(**struck 2026-09-16, M6.3 — falsified, not
narrowed.** On the `Hash Right Join` plan — 5 of the 8 runs this ADR recorded — the evidence side
is a `Seq Scan` over the **whole table**, not the project's slice. Re-measured at M6.3 at this
same volume: `Seq Scan on evidence e … rows=100000 … actual time=0.042..11.312`, and of the 11.312 ms that scan
costs inside that run's **25.943 ms** read, all but the measured project's own 2,000 rows —
**roughly 11.1 ms** — is spent on other projects' evidence, so the cost grows with the corpus as
well as with the project. *(M6.3 ran this benchmark **twice**, and the two are kept distinguishable
rather than averaged or conflated: the figures here are the **first** run, which read 25.943 ms; the
second read **26.661 ms** on the same `Hash Right Join` plan and is the one every end-to-end ratio
in G61 and ADR-0030 is taken against — so a reader meeting 4.08× elsewhere is meeting 108.8 ÷ 26.661
and not a disagreement with this paragraph. ADR-0030's Consequences names both runs in one
sentence.)* The struck clause is the ground this paragraph's trigger was
written on, so the trigger is widened by the same note: a project an order of magnitude larger is
no longer the only way to reach a bad number — enough OTHER projects will do it. Recorded beside
the measurement that falsifies it, in ADR-0030's Consequences.)* Measuring one now would be scaling with no
consumer, which this repo refuses elsewhere (ADR-016 decision 3). **Trigger: the first project
an order of magnitude beyond the measured 2,000 findings, or any report of a slow Risk
listing.**

***(Note 2026-09-16, M6.3: **the number arrived and it meets this paragraph's own criterion.**
Measured end to end rather than by `EXPLAIN` — which this ADR's figures are, and which understate a
request's cost by **4.08×** at this volume — one `get_by_project_id` has a median of **108.8 ms**,
and the gap between the unscored and scored routes is 115.3 ms at the medians. **The doubled read
is therefore the larger term on every estimator** (94.4% of the gap at the medians, 52.9% at the
minima, 73.9% at the maxima), and per-request purity is precisely what buys that doubling. **What that settles is the SHAPE of
the cost, not the badness of the number:** the criterion below is *cheap to recompute*, this
document sets no threshold on purpose, and the only scale it offers — 763 ms for ADR-0022's
pre-rewrite query — sits above the 259.5 ms measured here at a worst-case grouping. The argument
for re-opening decision 1 is therefore that **the dominant term is the one production shape cannot
reduce**, and it is put in front of whoever takes the amendment rather than settled here. M6.3 does not take it: its scope is a read surface and it declined the optional
write at design time. The escalation, the full readings and the conditions are in **G61** and in
ADR-0030's Consequences. Recorded here rather than only there, because this is the paragraph a
later reader checks the criterion against.)***

**A bad number is evidence AGAINST decision 1, not a tuning task — this is the one thing about
this ADR that is easiest to get wrong at implementation time.** Decision 1 rests on a candidate
Risk being cheap to recompute; if it is not, the premise failed and persistence is forced by
cost rather than by state, which is an amendment to this document and not a follow-up. Three
responses would each improve the number while leaving the whole project recomputed per request,
and all three are refused in advance: **an index on `findings`**, **a cache of the groups** —
the lever ADR-0022 already re-read and declined — and **paging `get_by_project_id`**, which
would page the input to a function whose output depends on all of it, and so would return
wrong groups rather than slow ones.

No threshold is set here, deliberately: no product requirement fixes one, and inventing a
number would make an arbitrary figure look like a criterion. The paragraph above names when
this is re-measured; a bad number then reopens this ADR rather than starting a tuning task.

**M8.1 inherits two things together**: decision 2's protected-field set and G11's forecast.
Recorded in its roadmap entry rather than only here, on M9.1's precedent.

**`shared_kernel/` is not touched.** The envelope type is correlation's own, per ADR-0018's
criterion as ADR-0023 alternative 4 already applied it.

## Amendments

- **2026-09-17 (M7.2, ADR-0033): one clause of decision 2 is struck and replaced. Decision 1 is
  untouched. This is not cost-forced persistence.**
  - **Struck.** Decision 2's *"Those are also the first values about a Risk that cannot be
    recomputed"*.
    - **Why struck, not qualified.** The clause is a claim about which values come first. M7.2
      supplies a counterexample: a stored Security Brief narrative is a value about a Risk, and it
      cannot be recomputed from the findings, since the provider call claims no determinism
      (ADR-0032 decision 5). It arrives before M8.1, so the clause is false as written.
  - **Replacement.** *"Those are also the first values about a Risk that cannot be recomputed **and
    must stay attached to it when its membership changes**, which makes the landmine and the
    trigger the same event."*
  - **Why decision 2's conclusion survives.** The conclusion (M8.1 is the first issue forced to write
    a Risk row) rests on the property the counterexample lacks.
    - A dismissal, an owner or a suppression is about the Risk and must follow it when a finding
      joins.
    - A narrative describes one decision over one fixed member set and must not follow it. ADR-0033
      stores it against that set, and a changed set fails closed rather than inheriting it.
    - So M7.2 writes a Brief row and no Risk row, and nothing here moves **G37** or **G11**'s
      Risk-link forecast off M8.1.
  - **Why decision 1 is untouched.** No derived address is created.
    - A Brief's identity is a surrogate id.
    - Its `finding_ids` are stored as data that clients join on, and no route, URL or held reference
      resolves a Risk by them.
    - The set acts as a selector exactly once, inside the generation request, resolved against this
      projection in the same request. So the failure decision 1 names for an address, *"silently
      repoints a held URL"*, has no held URL to act on. A membership change produces a 404 at the
      only moment the set is read.
    - The Risk still has no identifier, and there is still no per-Risk route.
  - **Not cost-forced.** The amendment this document's Consequences names for cost (*"persistence is
    forced by cost rather than by state"*) is not taken. **G61**'s escalation and its owner, M8.2,
    are unaffected.

## Alternatives considered

**Identity derived from the match key**, the `dedup_hash` analogue. Rejected in decision 1 on
the no-signal collision, which is structural rather than a corpus property — and it would have
inherited ADR-0019 decision 6's whole version-prefix contract for a key that G31 already says
changes at M5.4.

**A surrogate id with `UNIQUE(project_id, package, url)`.** Same collision, same rejection: the
constraint is unsatisfiable for a project with two no-signal findings. Rescuing it with a
partial unique index over signal-bearing groups only is design invented to save a shape nothing
needs yet.

**Replace-all on re-correlate** — delete the project's Risks, insert the current groups. **The
collision above does not reach it**: it needs no conflict target, so it is rejected on its own
merits and at more length than the other two.

*What it would buy over the projection is one thing: a durable id, and with it the per-Risk
route decision 1 gives up.* It does not deliver that. **Delete-and-insert regenerates ids**, so
a URL held across a re-correlation is dead, and M8.1's `RiskEvent` log would reference rows
that no longer exist — `ARCHITECTURE.md` §9's idempotency promise satisfied in letter and
broken in the thing it exists for. On the axis that would justify it, replace-all is not better
than the projection; it is the same instability behind a handle that looks stable, which is
worse than not having one.

*The version that would fix that* — preserve ids by matching surviving rows to new groups —
needs something to match **on**, which is a key, which collides. So the collision does kill
replace-all, at one remove: not the option, but the only repair for its defect.

*And it needs a WRITE trigger, which this project has never designed.* Every stage that writes
has an issue that decided **when** it runs and a queue port to run it on — the scan job and the
normalization job, each with its own ADR. Correlation has neither, and M5.2's scope is a read
surface. So replace-all does not cost one table; it costs a third pipeline trigger, designed
inside an issue that was not scoped to design one. *(Two earlier drafts argued this by pasting a
command's output — first a `git grep` this very change falsified by adding a DI factory, then a
grep over enqueue functions. Neither was needed: the claim is about what the design contains,
which no command has to be re-run to check, and pasting one only gave the sentence an expiry
date.)* Stored groups are a snapshot of a function of `findings`, and `findings`
changes on every normalization — so replace-all obliges M5.2 to decide *when* correlation runs
as well, a second decision it has not been given, whose failure mode is a Risk listing quietly
describing an older set of findings. That is ADR-0019 decision 1's silently-stale summary made
real rather than hypothetical.

*Secondary, and not what carries this:* a table correct only while a Risk carries no user state
has a known expiry at M8.1, against ADR-0019's *"cheap now, expensive after persistence"*.

**Persisting and upserting per group.** Needs a conflict target, which decision 1's first
property denies it.
