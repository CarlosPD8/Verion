# ADR-0021 — Normalization job execution: scheduling, state machine, and failure semantics

## Status

Accepted — 2026-08-23 (M4.4)

## Context

ADR-0017 decision 2 shipped the durable half of the scan → normalize handoff and
deferred four things by name: the arq enqueue, the `normalize_scan` job, the
reconciliation sweep, and the partial index the sweep would want. With no
`Finding` entity they would have been dead by construction. M4.1 moved the
trigger from M4.1 to M4.4 because all four also need M4.3's persistence. Since
M4.0, therefore, every scan has written a `pending` progress row that nothing
advances — intended, and recorded in that ADR's Consequences.

M4.3 landed the persistence, so M4.4 discharges all four. Most of what it builds
implements decisions already made: the enqueue's placement is ADR-0017 decision
2, the `PARTIAL` and all-tools-failed behaviour is decision 3, and the two
contracts around `upsert` and `record_sighting` are ADR-0020 decision 5. This
document records only what those did **not** decide, and what M4.4 had no choice
but to choose:

1. **When the sweep runs, and what it selects.** ADR-0017 fixed one invariant —
   it must never read `Scan.status` — and explicitly left "a staleness threshold
   and an ordering" to this issue.
2. **The `started_at`/`finished_at` state machine.** Left unconstrained in both
   the domain guard and the `CHECK`, deliberately, because the transitions are
   this issue's to define.
3. **What happens when normalization itself fails.** ADR-0017 spent a whole
   decision on a failure writing the handoff row and nothing at all on a failure
   *consuming* it. ADR-0019 decision 2 additionally handed M4.4 one specific
   case as acceptance criteria: what the use case does when `collapse_by_identity`
   raises.

A fourth question was resolved in the same issue but belongs in **ADR-0019's
Amendments** rather than here, because it closes a caveat that document already
owns: the Semgrep invocation change that makes `file_path` and `rule_id` stable
(G9 and G10). It introduces no new principle and both of its rejected
alternatives are already recorded in G10.

## Decision

### 1. The sweep is an arq cron job that enqueues, and never normalizes inline

Registered as `WorkerSettings.cron_jobs`, every 5 minutes. Not a
self-rescheduling task and not a lock this project builds: `arq.cron`'s
`unique=True` default gives each tick a job id unique to its *intended execution
time*, so N workers running this cron produce one sweep per tick. The singleton
comes from arq.

It enqueues; it does not normalize. One code path produces findings, and it is
the job. A sweep that normalized inline would be a second writer with its own
transaction lifecycle, its own failure semantics and no `job_timeout` — three
things to keep in step for a path that runs only when something already went
wrong, which is the path least likely to be exercised.

**Nothing in the sweep guards against racing a live job, because three other
things already do**, and a fourth copy of that logic in a `WHERE` clause would be
a fourth place to keep right:

- `arq.cron`'s `unique=True`, above.
- `ArqNormalizationQueue` enqueues with `_job_id="normalize:<scan_id>"`, and arq
  refuses an id that is already queued or in flight — so re-enqueuing a live job
  is a no-op. (The prefix is load-bearing: `ArqJobQueue.enqueue_scan` already
  claims the bare `scan_id`, and an unprefixed id would collide with the scan's
  own job and silently drop normalization for every scan.)
- The job's own `claim` is a row-locked conditional transition, and the work it
  does is idempotent by construction (ADR-0020).

### 2. The sweep selects `pending` **and** `running`, staleness measured from `requested_at`

```sql
SELECT * FROM normalization_runs
WHERE status IN ('pending', 'running')
  AND requested_at < :threshold
ORDER BY requested_at
LIMIT :batch_size
```

No join, no subquery, no reference to `scans` in any form. ADR-0017 decision 2's
invariant is unchanged and is now **proved behaviourally rather than by reading
the query**: `test_normalization_sweep.py` sweeps a `pending` row whose `scan_id`
names a scan that does not exist. That row is legal by construction — `scan_id`
carries no foreign key (ADR-0017 decision 1; G11 records the consequence) — and
every implementation that reads `scans` by any route returns zero rows for it,
while the correct one returns it. Mutation-tested by adding exactly the
"harmless optimisation" the invariant forbids; two tests failed.

**Including `running` is a deliberate deviation from the `WHERE status =
'pending'` ADR-0017 anticipated**, and the argument is an asymmetry rather than a
preference. A job killed by `job_timeout`, or a worker killed after its claim
committed, leaves a `running` row that a pending-only sweep can never recover —
permanent, silent loss of exactly the work this record exists to guarantee.
Including it risks the opposite failure, re-enqueuing a job that is still alive,
and that one is *harmless*: the job-id dedup above makes it a no-op, and if it
somehow ran, the work is idempotent. **Prefer the harmless failure to the silent
one.**

**Threshold: 900s, and it is derived from `WorkerSettings.job_timeout` (600)
rather than picked.** This is the property that keeps the deviation in the
harmless direction, so it is a **constraint, not slack**: arq kills a job at
`job_timeout`, so a row that is `running` past the threshold cannot still have a
live job working it. Raise `job_timeout` past 900 without raising the threshold
and the sweep begins continuously re-enqueuing live work. Nothing in
`worker.py` would say so, so `test_sweep_settings.py` asserts the ordering.

**`requested_at` is the staleness column for both statuses**, not `started_at`.
It is `NOT NULL` on every row, it is the natural ordering key, and for a `running`
row it is strictly earlier than `started_at` — so the test is *more* eager there,
which lands on the harmless side. One column, one index, one predicate.

**The two deviations compound, and the interaction is bounded.** An in-flight
row's `requested_at` is older by construction than anything requested after it,
so `ORDER BY requested_at` puts live rows at the *head* of the list — under a
backlog deep enough that claims lag requests by more than the threshold, every
running row is over threshold and sorts first, consuming `LIMIT` slots stalled
rows wanted. The bound is `workers × arq's max_jobs` (10 by default), i.e.
independent of backlog depth: ~10 of 200 slots go to live work however deep the
queue is, and every displaced enqueue is a no-op. A small constant tax, not an
amplifying loop. Bounding it further would cost a second time column in the
predicate and a second partial index to buy back ~5% of one tick's batch.

**The partial index ships in the migration that carries this query** — ADR-0017's
"an index without its query is a guess at that query's shape", now that the query
exists. Partial on the two non-terminal statuses, so it stays proportional to the
backlog rather than to scan history.

### 3. `COMPLETED` is the only terminal state

| from | to | sets |
|---|---|---|
| `pending` | `running` | `started_at` (first claim only) |
| `running` | `running` | nothing — a re-claim after a crashed attempt |
| `failed` | `running` | nothing; `started_at` preserved, `failure_reason` cleared |
| `running` | `completed` | `finished_at` |
| `running` | `failed` | `finished_at`, `failure_reason` |

Deliberately symmetric with `RunScanUseCase`'s `if scan.status ==
ScanStatus.COMPLETED: return` — the same rule, one stage over.

**`FAILED` being re-claimable is the part that reads as sloppiness and is not.**
Decision 4 has the job write `failed` and re-raise for a transient failure; if
`failed` were terminal, arq's retry would reach `claim`, get `None`, and return —
a retry that silently does nothing. Re-claiming clears `failure_reason` because a
`running` row carrying one is rejected by both `__post_init__` and
`ck_normalization_runs_failure_reason_shape`; the consequence is that failure
history does not accumulate on this row, which a future caller wanting it would
have to model as a second table.

**Enforced in two places**, the idiom `ck_scan_results_outcome_shape` established:
`NormalizationRun.__post_init__` and `ck_normalization_runs_timestamp_shape`.
Both are exhaustive over the four statuses rather than a set of implications *in
the domain*, because a status left unconstrained by omission is how `running`
would keep accepting a `finished_at`.

**The SQL constraint is written as implications, and the difference matters.**
Both forms accept the same rows for the four statuses that exist; they differ only
on a status that is none of them. A disjunction would *also* reject an
unrecognised status — which sounds stricter and is worse, because
`ck_normalization_runs_status` already rejects it: the row would violate two
constraints, Postgres reports whichever it evaluates first, and
`test_the_database_rejects_an_unknown_status`'s assertion that the *status*
constraint fired would be depending on evaluation order. **It was passing for
that reason before this issue rewrote it**, along with the failure-reason
rejection test. One constraint, one concern, one test that cannot pass by luck.
What the disjunction would have bought — a fifth enum member rejected until
somebody gives it a timestamp rule — is bought instead by
`test_every_domain_status_is_accepted_by_the_check_constraint`, parametrised over
`list(NormalizationRunStatus)`: a new member gets a case automatically and that
case cannot be written without choosing a shape. The same mechanism ADR-0020
decision 4's partition test relies on.

**`claim` is a row-locked read-modify-write, not a conditional `UPDATE` with the
transition transcribed into a `SET` clause.** ADR-0020 decision 2 rejected
read-modify-write for the finding upsert because the row may not exist, so two
workers both `SELECT` nothing, both `INSERT`, and one takes an `IntegrityError`.
That objection does not transfer: this row **always already exists** by ADR-0017
decision 3's invariant, so there is no insert to collide, and `SELECT … FOR
UPDATE` closes the window. The payoff is that `NormalizationRun.start` — the
domain function — is on the production path, so unlike the finding upsert there
is no transcription to keep honest.

**The claim commits in its own transaction, before the work begins.** In one
transaction, `RUNNING` would be written and overwritten before anything could
observe it, which makes a job killed mid-flight indistinguishable from one that
never started — and that distinction is the whole reason decision 2's sweep can
recover a stalled run. The cost is that a crashed job leaves a committed `running`
row, which is precisely what decision 2's `running` inclusion pays for.

### 4. Failure splits on whether it is deterministic in the persisted `ScanResult` rows

Those rows do not change between attempts, so normalization is a pure function of
them plus the id generator and the clock. That makes the split decidable rather
than a judgement call:

- **Transient or unanticipated** — a DB error, an unexpected exception anywhere in
  mapping or persistence. Record `failed`, **re-raise**. arq retries (default
  `max_tries = 5`) with backoff; the retry re-claims and re-runs the identical
  pass.
- **Deterministic and isolated** — decision 5's `collapse_by_identity` raise.
  Handle in place, record `failed`, **do not re-raise**. A retry would fail
  identically and buy five wasted runs.

**A `ScanResult` naming a tool with no mapper is deterministic and re-raises
anyway**, which looks like an exception to the split and is not. The taxonomy asks
whether a *retry* helps; this case asks a prior question, whether the input is
something this system should be processing at all. `RunScanUseCase` persists
`str(scanner.tool)` from a `ScannerTool` member, so reaching it means a row was
written around the repository or a tool was removed from the enum with its rows
left behind — deployment configuration this project controls, which is exactly
where ADR-016 decision 2 draws its raise-versus-degrade line (an unrecognised
*severity* degrades to `UNKNOWN`, because that is upstream data a tool can change
in any release; an unrecognised *tool name* raises). The cost of arq retrying it
five times is five fast failures during mapping, before any work — not five full
re-runs. Pinned by `test_a_result_for_an_unknown_tool_raises_rather_than_being_skipped`.

**A retry cannot damage what an earlier attempt persisted, and that is a property
of ADR-0020 rather than of care taken here**: `upsert`'s refresh set is total
except the two surrogate ids, and `record_sighting` overwrites a per-scan total
rather than incrementing. Re-running the identical pass writes identical values.
This question would have been hard under any other upsert semantics; it is easy
because M4.3 already made the write path idempotent.

**One hole is left open deliberately.** If the work transaction aborts on a DB
error, the `failed` write aborts with it and the row stays `running`. Decision 2's
inclusion of `running` in the sweep is what recovers it — which is the concrete
reason that deviation is not cosmetic.

### 5. A conflicting finding group is skipped; the rest of the scan is persisted; the run is marked failed

ADR-0019 decision 2 handed M4.4 this as acceptance criteria, with three options:
skip the element, fail the run, or mark `NormalizationRun` failed. The chosen
shape takes the first and third together, and rejects the second.

`collapse_by_identity` raises when a group disagrees on a rule-level attribute —
normally a mapper bug, but reachable from data through the `"(unidentified)"`
`rule_id` fallback. **The use case therefore calls it once per identity group
rather than once over the whole scan**, catching `ValueError` per group and
dropping only that group. The domain function is unchanged and neither of its
guards is weakened: the project check and the rule-level check are both *within* a
group.

- **Letting it propagate** would abort a whole scan's normalization over one
  malformed element — the `PRODUCT_SPEC.md` §12 corruption the `Location` guard
  was removed to avoid, arriving through a second validation rule.
- **Failing the run and persisting nothing** has the same effect on the data and
  differs only in how loudly it is announced. Discarding 23 good findings because
  one element is malformed is the corruption regardless.
- **Skipping silently** is the option this project has no mechanism for: `src/`
  contains **zero** `logging.getLogger` calls, so "log a warning" means
  introducing logging inside an issue about a pipeline, and rule 12 makes a line
  carrying `title`/`severity` a surface needing its own review. A dropped security
  finding with no record of the drop is the invisible loss the register exists to
  prevent.

So the run is marked `failed`, using the field ADR-0017 decision 1 created for a
failure that is *neither a scanner outcome nor a pre-tool failure*. No new column,
no new domain field, no logging. **The reason names the count and the
`dedup_hash` values and never the disagreeing values**, which are
`title`/`severity` and can carry scanned content (rule 12).

A `failed` run with findings persisted is an unusual state and is the intended
one: the findings are correct, and something was dropped. Note the sweep does not
re-enqueue `failed` rows — a deterministic failure would fail identically every
five minutes — so recovery is a human reading `failure_reason`, which is what that
field is for.

**That justification covers this case and not the other one that lands in
`failed`.** Decision 4's transient branch also writes `failed`, after arq exhausts
`max_tries`; excluding `failed` from the sweep therefore drops a *transient*
failure permanently, which is exactly the "scan that is never normalized" outcome
decision 2's asymmetry argument is built to avoid. The two are indistinguishable
once written — nothing on the row records whether the cause was deterministic —
so the fix is a real design question (a distinguishing marker, a bounded retry
count, or a separate operator-facing requeue) rather than a predicate change.
Registered as **G15** with a `Blocks-if-unresolved:`, per `CLAUDE.md`'s rule that
a gap found and not fixed goes to the register rather than into a Consequences
section nobody re-reads.

Pinned by a test over a synthetic identifier-less pair, and **the load-bearing
assertion is that every other finding in the same scan is persisted**, since that
is what fails if a future refactor widens the catch back out. Mutation-tested by
moving the call back to one pass over the whole scan; three tests failed.

## Consequences

**The window ADR-0017 opened is closed.** No scan ends at a `pending` row that
nothing advances. `test_worker_run_scan.py`'s existing end-to-end case now
asserts the row reaches `completed` through a real arq round trip, a real clone
and a real Semgrep — and costs nothing extra, because it was already paying for
all three.

**M4.5 inherits a `NormalizationRun` worth surfacing.** `status`,
`failure_reason` and both timestamps now mean something, so "was this scan
normalized, and when" is answerable. The `failed`-with-findings state from
decision 5 is the one a response schema has to describe carefully.

**M9.1 inherits the state machine's guarantee**: "scan N was never normalized" is
a missing or non-`completed` row, and "not sighted in scan N" is a missing
sighting — ADR-0019 decision 1's two records compose with no third state, which
required `completed` to actually be written. It also inherits two new register
entries, **G13** and **G14**, both about a `run_scan` retry that changes
`ScanResult` rows *after* normalization already completed. Neither is reachable
without that retry landing on the non-DB path, and neither is this issue's to fix:
the fix is either a `DO UPDATE` ADR-0017 decision 2 forbids or a re-normalization
trigger nobody has scoped.

**`test_schema_matches_models.py` grew an index comparison.** `ix_normalization_runs_sweep`
is the project's first index that exists in its own right, and an `Index` is not
in `table.constraints` — so without it the sweep's index would have been asserted
by nothing in either direction. ADR-0020 already names the next one
(`ix_finding_sightings_scan_id`, M4.5).

**No logging was added, and the cost of that is now written down in one place**:
`worker.py`'s enqueue catch. While Redis is unreachable every scan degrades to
sweep latency — up to 900s — with no trace. Accepted, because findings arrive
late rather than wrong or lost. The comment there says explicitly that the fix,
if it is ever needed, is a metric or a log line and **not** a raise; a test pins
the three properties that claim rests on.

**CI runtime.** No container-bound test was added. The `PARTIAL` acceptance test
uses in-process fake scanners fed M4.1's committed fixtures, per `ROADMAP.md`'s
own instruction — reusing `test_multi_scanner_dispatch.py`'s three real adapters
would have added a fourth ZAP-class test, a third of the remaining headroom to
`CLAUDE.md`'s 120s split, for coverage that test already owns. The one addition
that costs real time is `test_semgrep_adapter.py`'s CWD-invariance case, which
runs the real adapter twice because that is the only way to observe the invariant
at all.

## Alternatives considered

**A pending-only sweep**, as ADR-0017 anticipated. Rejected in decision 2: it can
never recover a `running` row, and the failure it avoids is harmless while the one
it causes is silent and permanent.

**Measuring `running` staleness from `started_at`** with a second predicate. It is
strictly more precise — a freshly-claimed row under backlog would be excluded —
and is rejected on cost: a second time column in the predicate and a second
partial index, to buy back roughly 5% of one tick's batch in a case that is
already bounded by worker concurrency. Revisit if the sweep is ever observed
spending most of a batch on live rows.

**A conditional `UPDATE … WHERE status <> 'completed' RETURNING *` for the
claim.** One statement, no row lock. Rejected in decision 3: it transcribes
`NormalizationRun.start` into a `SET` clause, which is the second-copy-of-a-policy
cost ADR-0020 decision 1 pays only because it has no choice. Here the row always
exists, so a lock is available and the domain function stays on the path.

**Committing the claim inside the work transaction.** Simpler — one session, and a
crashed job rolls back to `pending` so the sweep needs no `running` clause at all.
Rejected because it makes `RUNNING` a state no observer can ever see: written and
overwritten inside one transaction. `normalization_runs` exists to make pipeline
progress *legible* (ADR-0017 decision 1), and a status that is structurally
unobservable is not progress anybody can read.

**Marking the run `completed` after a skipped group**, with the drop recorded
nowhere. Rejected in decision 5 — it is the silent option, and this project has no
logging to make it non-silent.

**Adding a `skipped_count` column** so a skipped group could be recorded without
overloading `failed`. Rejected as disproportionate: the case is latent (all 30
elements across the six committed fixtures carry their tool's identifier — 0
missing), and a column plus a domain field plus a migration to describe a state
nothing has ever reached is exactly the speculative shape ADR-016 decision 3
refuses. Revisit if a real capture ever reaches the fallback.
