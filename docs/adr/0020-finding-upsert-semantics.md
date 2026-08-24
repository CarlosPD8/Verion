# ADR-0020: How the `Finding` upsert stays equal to `merge_observation`

## Status

Accepted

## Context

ADR-0019 handed M4.3 four obligations, one of which is not a shape: *"upsert-by-hash with `merge_observation` as the executable spec for what refreshes and what is frozen"*. `ROADMAP.md` M4.3 restates it as a prohibition — *"so the policy is not re-invented in an `ON CONFLICT DO UPDATE` clause"* — and neither document says how a **pure domain function** and **one SQL statement** are supposed to be the same thing.

They cannot be the same code. `merge_observation(existing, observed)` needs `existing`, which means a `SELECT`; an upsert is one statement precisely so that it does not. So the choice is between two shapes with different failure modes, and whichever wins leaves a second question: what detects it if the domain rule and the SQL drift apart later, given that both would keep passing their own tests.

This ADR is narrow on purpose. Everything else in M4.3 — the three tables, `UNIQUE(project_id, dedup_hash)`, the sighting's composite key, the `dedup_hash` column, decision 7's `project_id` — implements a decision ADR-0019 already made, and re-deciding those here would dilute that record rather than add to it.

## Decision

### 1. `ON CONFLICT DO UPDATE`, and the `SET` clause is a transcription rather than a second policy

The prohibition in the roadmap reads as though `ON CONFLICT DO UPDATE` were the thing being ruled out. It is not; **re-inventing the policy** is. And the policy turns out to be almost nothing, which is what makes the transcription faithful:

```python
return replace(
    observed,
    id=existing.id,
    evidence=replace(observed.evidence, id=existing.evidence.id, finding_id=existing.id),
)
```

**The only values `merge_observation` takes from `existing` are the two surrogate ids.** Everything else comes from the observation. "Merge" here means *keep the ids, take the rest from the later observation* — so:

- `id` **absent** from `set_` is literally `id=existing.id`;
- every other mutable column reading `EXCLUDED` is literally "take it from `observed`";
- the identity inputs (`source`, `rule_id`, `file_path`, `package`, `url`, `http_method`, `parameter`) are **omitted rather than set from `EXCLUDED`**, though setting them would be a no-op — they are equal by construction, since the conflict target *is* the identity. Omitting them makes "identity is frozen" a property of the statement instead of a coincidence that holds only while the hash is faithful.
- the `evidence` statement's own `ON CONFLICT (finding_id) DO UPDATE`, which sets `scan_id`, `raw_payload`, `source_tool` and `captured_at` but not `id` or `finding_id`, is the inner `replace(...)` one for one.

The resulting `SET` clause is exactly `_RULE_LEVEL_ATTRIBUTES` **plus** the three `Location` fields `compute_dedup_hash` excludes for positional reasons — `start_line`, `end_line`, `installed_version`. Nine columns, both halves already declared by the domain.

### 2. Read-modify-write is rejected on a concurrency window that is real, not theoretical

The alternative is `SELECT`, call `merge_observation`, `UPDATE` or `INSERT`. It has the obvious virtue of *being* the domain function, and it is rejected anyway.

**The bound people reach for does not hold.** `UNIQUE(scan_id)` on `normalization_runs` makes the handoff idempotent, so at most one normalization is owed per scan — but that bounds *duplicate jobs for one scan*, not **two different scans of the same project being normalized at once**. Two pushes in quick succession produce two scans, two jobs, and arq runs jobs concurrently. Those two jobs will observe the same finding, because findings dedup within a *project*.

Both would then `SELECT` nothing, both would `INSERT`, and one would take an `IntegrityError` on `uq_findings_project_id_dedup_hash` — which ADR-014 rejected for `WebhookDeliveryRepository` and ADR-0017 rejected again for the handoff row, both times because it leaves the session in a failed-transaction state needing its own rollback. Here that is worse than in either: the worker commits in `finally`, and the failing statement would be in the middle of a loop over a whole scan's findings.

**Lost updates under `DO UPDATE` are not an anomaly**, and this is worth stating because it is the usual objection. `merge_observation` is order-dependent *by design* — the evidence refresh is unconditionally latest-wins (ADR-0019 decision 5) — so two concurrent observations produce one of the two valid serial orders, which is exactly what two sequential observations would have produced.

### 3. The equivalence has an expiry date, and it is a *total refresh set*

Decision 1 works **only because** `merge_observation`'s refresh set is total except the two surrogate ids. That is not a permanent property of the model; it is a property of the fields `Finding` carries today, every one of which derives from the rule or the advisory and is therefore correctly overwritten by the newest observation.

**The moment `Finding` gains a field that must NOT refresh, the transcription stops being one and this ADR must be revisited.** The named candidate is **`confidence`, deferred to M6.1** by ADR-0018 decision 5 — if it were ever to carry a value a human set, or a value the newest scan should not clobber, `EXCLUDED` would be the wrong source for it. The general case is any user-settable field: a dismissal, an owner, a suppression. Such a field belongs on `Risk` (M5/M6) rather than on `Finding`, which is one reason this is a trigger rather than a problem — but a trigger with nothing watching it is the failure `ROADMAP.md`'s register exists to prevent, so decision 4's tests are what actually hold the line.

### 4. Three test layers hold the agreement, and none needs editing when a field is added

A convention ("remember to update the `SET` clause") is the kind of rule this project has repeatedly found unenforceable. So:

1. **Partition** — `FindingModel.__table__.columns` partitions *exactly* into `{id, project_id, dedup_hash}`, the identity inputs, and the adapter's `_REFRESHED_COLUMNS`; disjoint and total. A column added without being classified fails.
2. **Derivation** — `_REFRESHED_COLUMNS == set(_RULE_LEVEL_ATTRIBUTES) | (Location's fields − compute_dedup_hash's parameters)`, computed with `dataclasses.fields` and `inspect.signature` rather than retyped. Changing either domain declaration without changing the adapter fails.
3. **Behaviour** — persist `existing`, upsert an `observed` that differs in *every* mutable field, and assert the result **equals `merge_observation(existing, observed)`**. One whole-object assertion on a frozen dataclass, so it covers every field at once and keeps doing so.

**Layer 3 is non-vacuous only because `upsert` returns a row read back through `RETURNING`** rather than the object it was handed. Returning a locally-reconstructed value would have made it assert that the adapter agrees with itself — the same shape as the redacted-fixture problem G9 records. Verified by mutation: removing one column from `_REFRESHED_COLUMNS` fails all three layers.

### 5. `upsert` returns the resolved `Finding`; `record_sighting` overwrites a total

**The return type is load-bearing and differs from ADR-0017's precedent deliberately.** `NormalizationRunRepositoryPort.request` returns `None` because both outcomes of its conflict mean the same thing and no caller branches. Here the caller's *next write* depends on the answer: identity is the hash and `id` is a surrogate, so only this upsert settles which id wins (ADR-0019 decision 1), and M4.4 cannot construct a `FindingSighting` without it. The idiom being followed is the conflict handling, not the return type — the same distinction ADR-0017 drew against ADR-014's `record_if_new`.

**`record_sighting` also uses `DO UPDATE`, and the reason is idempotency rather than recency.** That distinction matters because the recency argument is wrong for the field that needs one: `observed_at` genuinely is a later observation, but **`match_count` is a count of the same scan**, so "the later one is better" says nothing about it. What decides it is that `ARCHITECTURE.md` §9 requires re-normalizing a scan to refresh rows rather than add them, and an arq retry re-running every enabled scanner is guaranteed (ADR-016 decision 1). Of the three options, only one is idempotent:

- **summing** double-counts silently on every retry;
- **`DO NOTHING`** leaves a stale count and never refreshes `observed_at` — and ADR-0017's reason for choosing it does not transfer, because that row carries a state machine `DO UPDATE` would reset and a sighting carries none;
- **overwriting with a complete total** is correct.

**So `match_count` is a per-scan TOTAL, never an increment, and that is a precondition on the caller** rather than a property of the sighting — which `DO UPDATE` makes invisible, so it is stated in the port's docstring and pinned by a test. M4.4 satisfies it because `collapse_by_identity` produces the total in one pass. Per-tool batching would also be safe by construction, since `source` is a `dedup_hash` input and no `(finding_id, scan_id)` can span two tools; **chunking within one tool's output is the case that would break it**, and ZAP's per-instance split (ADR-0019 decision 4) makes large element counts more likely rather than less.

## Consequences

**M4.4 inherits two contracts from decision 5**, and both are compile-time invisible: `upsert` hands back the resolved `Finding` whose `id` the sighting must use, and `record_sighting` must be called once per `(finding, scan)` with the complete count.

**M6.1 inherits decision 3.** If `confidence` lands on `Finding` and is anything other than tool-derived, the `SET` clause stops transcribing `merge_observation` and this ADR is the thing to reopen. The partition test in decision 4 is what will make that visible — a new column fails it until somebody classifies it.

**No secondary index ships, and the one that is coming is named.** Every query M4.3 and M4.4 make is served by a constraint index that must exist regardless: the finding upsert by `uq_findings_project_id_dedup_hash` (whose leading column also serves M4.5's project-scoped listing, as an index prefix), the evidence upsert by `uq_evidence_finding_id`, the sighting upsert by the composite primary key. **The one query none of them serves is the scan-first one** — "which findings were sighted in scan N", and M9.1's absence check — and it wants `ix_finding_sightings_scan_id`, which ships **with M4.5/M9.1**, in the migration carrying its query. ADR-0017's "an index without its query is a guess" applies here without a counterweight, because ADR-0019's "cheap now, expensive after persistence" is an argument about *shape* — keys, columns and hash inputs, things that re-key stored rows — and an index rewrites no data, so it costs the same either side of persistence. What **is** shape, and is therefore settled now, is the sighting's primary-key column order.

**Measurement was not available and is not faked.** The three committed fixtures produce 24 findings for one scan; at that volume Postgres seq-scans whatever indexes exist, so a benchmark now would measure nothing while reading as evidence. **M4.5 should `EXPLAIN` the project listing and the sighting join at realistic volume** before deciding anything further — that is the first point at which the numbers mean something, and ADR-0019 decision 1's invitation to add a `last_seen` cache if the join proves to be the bottleneck should be re-read then, not before.

**One test-harness change rides along, and it is recorded here because it is what makes this issue's eight new constraints real.** The integration suite now builds its schema with `alembic upgrade head` instead of `Base.metadata.create_all`. Previously the two were compared by nothing: in CI they happened to agree because `alembic upgrade head` runs before `pytest` against the same service and `create_all` defaults to `checkfirst=True`, silently skipping every already-migrated table — an undocumented consequence of step ordering, invisible locally, and covering only constraints some test exercises. A `CHECK` declared on a model and missing from its migration would otherwise have passed the whole suite and failed in production. `test_schema_matches_models.py` covers the remainder by comparing table, column and named-constraint sets in **both** directions; the second direction is what stops it going vacuous, since `Base.metadata` holds only the tables whose modules have been imported. A side effect worth knowing: **rule 8 becomes partially mechanically enforced** — a model on a second declarative base gets no migration, so its table now does not exist and its tests fail loudly — for any model an integration test touches.

## Amendments

- **2026-08-24 (M4.5):** Both of this document's instructions to M4.5 are
  discharged, one of them with a result that contradicts what Consequences
  expected. No decision here changes; decisions 1–5 are untouched.
  - **`ix_finding_sightings_scan_id` did not ship in M4.5.** Consequences says it
    ships "with M4.5/M9.1, in the migration carrying its query", and the operative
    half is the second: M4.5's listing is **project-scoped and scan-independent**,
    so it has no scan-first query at all. Its per-finding sighting summary
    correlates on `finding_id`, the sightings primary key's leading column. The
    index goes to M9.1 with the absence check. What M4.5 shipped instead is
    `ix_normalization_runs_project_id`, on a table that had no index and grows one
    row per scan forever. See ADR-0022 decision 4.
  - **The `EXPLAIN` was run, and it reversed a query, which is the point of having
    asked for it.** At 100k findings / 300k sightings the first implementation took
    **763 ms**: the sighting summary was a whole-table `DISTINCT ON` merge-joined
    against the page, so Postgres seq-scanned all 300,000 sightings and sorted them
    on disk to return fifty rows. Rewritten as a LATERAL correlated to one finding
    it is **3.07 ms**. The listing's project filter does ride
    `uq_findings_project_id_dedup_hash` as an index prefix, exactly as Consequences
    predicted.
  - **The warning in Consequences was nearly not enough.** It says a benchmark at
    24 rows "would measure nothing while reading as evidence". The first run at
    *full* volume measured 8.8 ms and was also meaningless, because the synthetic
    finding ids were sequential — one project's findings clustered at the head of
    the id-ordered scan and the merge join terminated early. Real ids are UUIDs
    (rule 9). So volume alone does not make a benchmark honest; the synthetic data
    also has to lack no property production has. Recorded because it is the same
    disconnected-verification shape G8 and G9 already carry, arriving through a
    seed script.
  - **ADR-0019 decision 1's `last_seen` cache invitation was re-read here, as this
    document instructed, and declined.** It was the wrong lever: the cost was never
    that aggregating sightings is expensive, it was that the query aggregated every
    finding's sightings to serve one page. Correlating fixed it without
    denormalizing anything, so no silently-staleable summary enters M9.1's path.
  - The measurement is reproducible rather than asserted:
    `scripts/seed_findings_benchmark.py`, versioned for that reason.

## Alternatives considered

**Read-modify-write through `merge_observation` itself.** Rejected in decision 2. Worth restating what it would have bought: the domain function on the production path, so no transcription to keep honest. What kills it is not elegance but the `IntegrityError` this project has now rejected three times for the same reason.

**`ON CONFLICT DO UPDATE` with every column in the `SET` clause**, identity inputs included. Rejected: it is a no-op that reads as a decision. A reader would have to work out that the identity columns cannot differ before concluding the statement is safe, where omitting them says so.

**Generating the `SET` clause from `_RULE_LEVEL_ATTRIBUTES` at import time**, so the adapter cannot drift by construction. Tempting, and rejected on two grounds: it reaches into another module file's private name, and it makes the *adapter* silently follow a domain change that might warrant a migration — a new rule-level attribute needs a column before it can be refreshed. The derivation test asserts the same equality while still failing loudly rather than adapting silently.

**A database trigger, or a `GENERATED ALWAYS AS` column, to keep `dedup_hash` in step.** Rejected in ADR-0019 decision 3's terms: it would reimplement `compute_dedup_hash` in SQL — canonical JSON with its exact separators, `null` distinct from `""`, the `v1:` prefix — which is a second source of truth in a second language, and it would have to be mirrored identically into both `Base.metadata` and the migration. The column is written from the property, and a test recomputes the hash from each stored row's own identity columns, which is only possible because `Location` is flattened onto the table.

**Summing `match_count` on conflict.** Rejected in decision 5, and it is the one option that is definitely wrong rather than merely worse: retries are guaranteed, so it double-counts silently.

**Raising when a sighting is re-recorded with a different `match_count`.** Rejected: it would make the guaranteed retry path an error, which is the opposite of the requirement.

**`alembic.autogenerate.compare_metadata` as the schema check.** Rejected as the *primary* guard — it compares tables, columns, types, nullability, indexes and unique constraints, but **not `CHECK` constraints**, which is precisely the failure being guarded against and six of this issue's eight new constraints.
