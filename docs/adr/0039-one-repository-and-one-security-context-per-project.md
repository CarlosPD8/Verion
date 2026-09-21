# ADR-0039 — One repository and one Security Context per project: what a second write does, and what the constraint does not reach

## Status

Accepted — 2026-09-21 (M8.7). Written and accepted before M8.7's code is committed, on
ADR-0033's, ADR-0035's, ADR-0036's and ADR-0038's precedent. M8.7 ships in two commits:
this one, and the code and migration.

**Two commits, because the code commit deletes a committed test whose docstring argues
for its own existence** (decision 10). That deletion needs its ground on paper in front
of it, rather than composed in the same commit message that performs it.

## Context

`connected_repos` and `security_contexts` are the two one-per-project relations in
`projects/` that never got a constraint. Registered as **G51** and **G55**, assigned
together to M8.7 at the M7→M8 boundary review as one decision applied twice. Read at
HEAD:

- **No constraint.** `ConnectedRepoModel` and `SecurityContextModel` declare no
  `__table_args__`. `da15b49a2373` and `a1b2c3d4e5f6` carry a primary key on `id` and a
  foreign key on `project_id`, and nothing else.
- **Writers that do not read.** `ConnectRepositoryUseCase` (which calls
  `validate_connected_repo_url` on the way, as G51's 2026-09-15 note records) and
  `ConnectRepositoryViaGitHubUseCase` both construct a fresh entity and `add` it without
  looking for an existing row, so **either second connect duplicates**.
  `BuildSecurityContextUseCase` mints a new id and `add`s unconditionally. **On
  `security_contexts` alone, only that one can duplicate:** the other writer,
  `UpdateExposureTagsUseCase`, reads first and its `add` sits on the branch where that
  read returned `None`, which qualifies G55's *"two writers, neither checking first"*.
- **Reads that refuse the second row.** Both `get_by_project_id` implementations end in
  `scalar_one_or_none`, which raises `MultipleResultsFound`.
- **Five callers of the connected-repo read**, one of them
  `RunScanUseCase._checkout_repo` — so the failure lands on the pipeline, not on the
  route that caused it — and one of them `PostgresServingDeclarationVerdictReader`,
  which serves a member-level read.
- **Two callers of the Security Context read**: `GetSecurityContextUseCase` and
  `UpdateExposureTagsUseCase`.
- **Three tables already carry the shape.** `uq_scanner_configs_project_id`,
  `uq_serving_declarations_project_id` and `uq_route_maps_project_id`, each named so an
  upsert can target it, each with the repository upserting on that name.

**What makes this a gap rather than a bug in one artifact** is that the three disagree:
`ARCHITECTURE.md`'s data-model sketch renders `connected_repos` as a **list**, the
schema permits many, and the read forbids more than one.

## Decision

### 1. One fork, answered once, across two tables

A second write to a one-per-project relation either **replaces** the first, is
**rejected**, or is **legitimate and the read is what is wrong**. The mechanism is
identical at every layer for both tables, so the fork is answered once. Answering it
per-table would leave two relations in one module giving different answers to the same
question, which G51's and G55's reciprocal notes both refuse.

**Two clauses exist on one side only.** `ARCHITECTURE.md` renders `security_context` as
**singular** and `connected_repos` as a **list**, so the third branch is already closed
on one side and open on the other, and choosing on that side contradicts a document line
(decision 11). And `exposure_tags` has no counterpart on `connected_repos` (decision 3).

### 2. `security_contexts`: a second write replaces the first

**Reject does not resolve G55; it relocates the failure.** G55 records four harms, and
three of them are recoveries that run *through a second detect* — in its own words, the
retry for a stored `FETCH_FAILED` *"is a second detect"*, and for a project that predates
M5.6 commit 4 *"its next detect is a second detect"*. A 409 leaves all three where they
are and fixes only the fourth, that the read raises. **A fix answering one of four, and
that one the smallest, is not what the entry asks for.**

**Widen is closed independently of the migration**: `ARCHITECTURE.md` renders the
relation singular, and all **three** routes returning `SecurityContextResponse` — `POST
.../security-context/detect`, `GET` and `PATCH` — return one object, so widening means a
new response shape on three shipped routes.

### 3. `exposure_tags` survives a re-detect, and no `updated_at` is added

`BuildSecurityContextUseCase` writes `exposure_tags=[]`. **A replace that wrote every
column would erase the owner's confirmed tags on every re-detect** — and confirming the
Security Context is M8.4's first bullet, the step this issue exists to unblock. Decided
explicitly, because a `set_` listing every column takes that answer silently.

The idiom is **three parts**, all of them already in `ScannerConfig`:

1. `UpdateScannerConfigUseCase` **reads first and reuses the stored id** — *"one
   configuration per project being edited, not a new record each time it changes"*.
2. `PostgresScannerConfigRepository.upsert` targets the constraint **by name**.
3. Its `set_` lists only the fields that write owns, **omitting `id`**.

`exposure_tags` is omitted from the Security Context `set_` for the reason `id` is
omitted from ScannerConfig's: the write does not own it. A re-detect refreshes the
detected fields and leaves the tags, so **`PATCH` is their only writer on the `ON
CONFLICT` branch** — not outright, since a first detect still writes `exposure_tags=[]`
through the insert. **Four fields, not five**:
`DetectionResult` carries `language`, `framework`, `deployment_target` and
`ci_provider`, and `BuildSecurityContextUseCase` hard-codes `database=None`, so the
column exists and nothing detects it.

**No `updated_at` column.** `security_contexts` carries only `created_at`, and under a
replace that column keeps the first detect's time. Nothing needs a second: `route_maps`
already carries `derived_at`, written on the same request by
`BuildSecurityContextFromGitHubUseCase`, which composes the writer above.

### 4. `connected_repos`: a second connect replaces the first

Two grounds, in the order they weigh:

1. **Under reject, M8.4 has no way out.** Its flow is connect, confirm, first scan. An
   owner who connects the wrong repository has no update route, no delete, and a 409 on
   the second connect — the project keeps the wrong repository permanently. A typo makes
   the project disposable, inside the onboarding flow.
2. **Nothing in `src/` navigates by the id.** `ConnectedRepoRepositoryPort.get_by_id`
   has no caller — port declaration and adapter only — so no code path looks a
   repository up by it. **It is not unread**: both routes return it, as
   `ConnectedRepoResponse(id=connected_repo.id, …)`. So the one consumer is the HTTP
   client, and what changes for it is that a second connect returns the **stored** id
   rather than a fresh one — which is the correct answer under a replace, and the reason
   the use case must reuse that id rather than mint one the row will not carry.

**Widen is rejected on something harder than symmetry.**
`RunScanUseCase._checkout_repo` would have to choose *which* repository to clone. That
is not a choice code can make — it is the owner's, and nobody has asked them. It turns a
read defect into a product ambiguity inside the pipeline, and ADR-0028 and ADR-0029 both
built the serving declaration and the route map on *the project's repo*, singular.

### 5. Both connect routes become `PUT`, answering 200

Not a choice among 201, 200 and `PUT`. The rule is already written in the router this
change edits, in `declare_serving`'s docstring: *"PUT because there is one declaration
per project and re-declaring replaces it, which is `update_scanner_config`'s shape one
resource over."* That is `PUT /{project_id}/scanner-config` and `PUT
/{project_id}/serving-declaration` — **the two routes that already apply it**, on two of
the three relations already carrying the constraint being copied. (The third,
`route_maps`, has no write route of its own.) So `POST /{project_id}/repositories` and
`POST /{project_id}/repositories/github` become `PUT`, answering **200**, and
`connected_repos` becomes the **third** relation whose write route follows the rule.

**`security_contexts` does not join them, and that is not an oversight.** Its write
routes are `POST .../security-context/detect` and `PATCH .../security-context`, and
neither changes here: detect is not an idempotent replacement of a body the caller sent
— it derives its values from the repository — and `PATCH` is already the partial update
its verb describes. Decision 2 changes what detect *does* to the row, not how it is
addressed.

**The timing is a reason, not a detail: this change is free only now.** `frontend/` holds
two pages and never names `repositories`, so neither route has a consumer today, and
**M8.4 is the issue that writes them — three issues out** under the execution order this
commit installs, counted as ADR-0038 counts (M8.2, M8.3, M8.4; the ports step is not an
issue). It was one issue out under the order this commit strikes. Deferred, M8.4 builds
against
`POST` 201 and the method change then happens with a live consumer in front of it.

### 6. The constraints, and one migration over two tables

`uq_connected_repos_project_id` and `uq_security_contexts_project_id`, on
`c2d5e8f31b14`'s template: named explicitly so `ON CONFLICT` can target them by name,
declared in `__table_args__` and in one migration covering both tables. The repositories
upsert with `on_conflict_do_update(constraint=...)`, and each `set_` lists only what that
write owns (decision 3).

Model and migration are held together mechanically: `test_schema_matches_models.py`
compares reflected unique constraints by name in both directions, so one declared on a
model and missing from the migration fails CI.

### 7. Existing duplicate rows: the constraint goes on bare

**This answers the question rather than defers it**: *the upgrade fails, and whoever
holds duplicates decides then, with the data in front of them* — the right behaviour for
a state nobody can know in advance, and the **second** of the four things G55's deferral
rationale says this fix needs. The migration says so in as many words, or a later reader
takes the bare constraint for the question skipped.

**Not a dedupe.** `connected_repos` carries **no time column at all**, so a survivor
would be chosen by `id` or `ctid` — deleting a row that may hold the only URL the project
has, by physical insertion order. The fact outlives this decision: **if a dedupe is ever
needed there, no non-arbitrary way to do one exists.** The precedent inverts rather than
transfers — `c2d5e8f31b14` argued why it backfilled no **absent** rows; this argues why
it deletes no **excess** ones.

**Measured, not predicted**, 2026-09-21, against a scratch database migrated to
`e4b7c1d90a36` — the head *before* this issue's migration — with two rows per table for
one project, and both `ALTER TABLE ... ADD CONSTRAINT ... UNIQUE (project_id)` statements
issued by hand:

```
ERROR:  could not create unique index "uq_connected_repos_project_id"
DETAIL:  Key (project_id)=(p-1) is duplicated.

ERROR:  could not create unique index "uq_security_contexts_project_id"
DETAIL:  Key (project_id)=(p-1) is duplicated.
```

Each message names the **index** Postgres was building, which carries the constraint's
name. Afterwards `pg_constraint` held neither, so nothing applied partially. Deleting one
duplicate per table and re-running both statements succeeded — the control separating
*refused because of the data* from *refused because the statement was wrong*.

**What is measured and what is inferred.** The probe ran `ALTER TABLE`; the migration
runs `alembic upgrade`. Same mechanism, since on an existing table Alembic can only emit
that same `ALTER` — but not literally the same thing. **The `ALTER`'s refusal is
measured**, above; **that the upgrade fails is inferred from it.**

The harness is not committed: a dated record of one run against a scratch database, **not
a re-runnable claim**, which the code commit cites and does not re-run. At HEAD both
tables hold **0 rows**, no duplicate `project_id`, no duplicate `url`, no deployment.

### 8. What the constraint does not reach: `get_by_url`

Stated here so the migration is never later read as having covered it.

`HandleGitHubWebhookUseCase` resolves a push through
`ConnectedRepoRepositoryPort.get_by_url`, which also ends in `scalar_one_or_none`. **That
read takes a URL and no project, so `UNIQUE(project_id)` does not constrain it.** Two
*different* projects connecting the same GitHub repository — which nothing forbids,
before or after this ADR — make it raise for both. That needs no second connect to any
one project, so it is neither G51 nor closed by G51's fix.

Opened as **G102**. Whether one repository may be connected to two projects at all is a
second behaviour decision, and it is not the one M8.7 was assigned.

### 9. G60's trigger fires, and what decision 4 does to it

**G60**'s trigger is *"the first change to `ConnectedRepoRepositoryPort`"*, and its
deferral rationale says its data decision *"needs G51's re-connect question answered
first"*. M8.7 does both, so the trigger is recorded as fired rather than left to be
noticed later.

Decision 4 **gives that entry the way out its `Blocks-if-unresolved:` says it lacks** —
*"there is no update route and a second connect makes the read raise (G51), so the owner
has no way out."* After this change the owner re-connects and the row is replaced. The
rest of G60 is untouched: no migration inspects existing rows, and a plaintext credential
already written to `connected_repos.url` stays there until someone re-connects.

### 10. The committed test the constraint breaks, and the two that replace it

`test_an_undeclared_project_with_two_connected_repos_reads_false_without_raising` seeds
a second `connected_repos` row for one project. Under decision 6 it fails at the flush,
and the state it guards becomes unreachable at the storage layer. **Deleted**, and
replaced by **two tests, because they are two claims**:

- **A raw `INSERT`** raising `IntegrityError` naming the constraint, on
  `test_a_succeeded_generation_with_no_brief_id_is_refused_by_the_database`'s shape.
  Raw, and never through the use case: under decision 4 a second connect **absorbs**
  rather than errors, so a use-case version would pass while asserting the opposite of
  its own name.
- **A use-case test**: connect twice, then assert one row, the **stored id preserved**,
  and the new URL. This pins decision 4. The first pins only the schema.

Both are what makes the code commit's mutation killable. Removing the `UniqueConstraint`
must be caught by something that asserts a **refusal** — `test_schema_matches_models`
checks that the constraint's name exists and never that it does anything, which is the
shape M8.6 commit 3 met twice.

`PostgresServingDeclarationVerdictReader`'s short-circuit is **kept**, and its docstring's
G51 ground is rewritten to the ordering-and-cost ground, which is what remains true.

### 11. What is final on this commit

The two constraint names, the two response shapes and the method change are final here;
the code commit may not re-decide them. It carries the models, the migration, the two
upserts, the route change and decision 10's tests.

**`ARCHITECTURE.md` is marked here and corrected at the code commit**, and the
distinction is the point: this commit decides the cardinality, and until the constraint
exists a sketch asserting it would be false in the present tense — the failure this ADR's
own decision 7 refuses one layer down. So `connected_repos: [ConnectedRepo]` in §4.1,
**both** relation edges in §4.2's diagram — the `o{` on `CONNECTED_REPO` and the `||` on
`SECURITY_CONTEXT`, which reads as exactly-one and is enforced by nothing either — and
the two entity blocks each carry a marker naming ADR-0039 and the commit that makes them
true. The code commit removes the list, resolves both edges to `o|`, and deletes the
markers together with the migration that earns them.

## Consequences

- **G51 and G55 are decided here and resolved by the code commit**, not by this one.
- **`security_contexts.created_at` becomes the first detect's time and stays there**, for
  a project that re-detects. Nothing reads it today.
- **A replace is silent.** Neither route tells the owner whether they created or replaced,
  and 200 does not distinguish them. Accepted: the owner is looking at the value they
  just sent, and the alternative is a response key the frontend would have to render.
- **G102 is opened by decision 8**, and is not closed by this issue.
- **G60 gains a way out and keeps its data decision.**
- **The constraint idiom goes from three relations to five**, which is the strongest
  argument the next one-per-project relation will have for not inventing its own shape.
  The `PUT`-with-200 rule reaches **three** of those five — `scanner_configs`,
  `serving_declarations` and now `connected_repos`. `route_maps` has no write route;
  `security_contexts` keeps `POST .../detect` and `PATCH`, for decision 5's reason.
- **Rule 16 fires on two clauses** — the migration clause and the route clause — and this
  ADR is what they cite. Its frozen-type clause does not fire: no domain field changes
  and no response key set changes.

## Alternatives considered

- **Reject the second write (409) on both tables.** Rejected in decisions 2 and 4: it
  resolves one of G55's four harms, and it makes a mistyped repository permanent inside
  M8.4's onboarding flow.
- **Widen both reads to return many.** Rejected in decisions 2 and 4: it contradicts the
  singular rendering and two shipped response shapes on one side, and on the other it
  moves an unanswerable question into `_checkout_repo`.
- **Split the fork — replace one table, reject the other.** Rejected in decision 1: two
  relations in one module would answer the same question differently, which is what G51
  and G55 both say must not happen.
- **Dedupe inside the migration.** Rejected in decision 7: there is no non-arbitrary
  survivor on `connected_repos`, which has no time column.
- **A committed test that seeds duplicates and asserts the upgrade fails.** Rejected: it
  is permanent machinery re-verifying a Postgres guarantee on every CI run, and the
  constraint's own mutation is already killed by decision 10's raw `INSERT` test. The
  one run that was owed is decision 7's recorded probe.
- **Keep `POST` and answer 201 on a replace.** Rejected in decision 5: the router already
  states the rule for a one-per-project relation, twice, and the method is free to change
  only while neither route has a consumer.
