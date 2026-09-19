# ADR-0036 — Dismissing a Risk: what a dismissal attaches to, the event log, and who may write it

## Status

Accepted — 2026-09-19 (M8.1). Written and accepted before any of M8.1's code is committed, on
ADR-0033's and ADR-0035's precedent.

## Context

M8's exit condition ends *"and resolves or dismisses a Risk in the UI"* (`ROADMAP.md`, Rules for
M8). M8.1's bullet named a `RiskEvent` log and `ResolveRiskUseCase` / `DismissRiskUseCase` with a
required reason. The commit that lands this ADR strikes that line.

**This is the first issue forced to write a Risk row.** ADR-0025 decision 2, as amended on
2026-09-17, names a dismissal as *"the first value about a Risk that cannot be recomputed **and must
stay attached to it when its membership changes**"*. It inherits two register entries: **G37**
(which columns a re-correlation may not overwrite) and **G11** (tables that depend on rows never
being deleted).

**Observed at HEAD `586c425`**, by reading the code:

- A candidate Risk is `MatchGroup(key: MatchKey, finding_ids: tuple[str, ...])`
  (`correlation/domain/matching.py`). `MatchKey` is `project_id, package, url`. `ScoredSurface`
  (`risk_engine/domain/scoring.py`) carries `project_id, package, url, finding_ids, priority_score,
  priority, reasoning` and, per its docstring, no `id`.
- `group_by_match_key` turns every no-signal entry into a singleton, so two such groups have equal
  keys (ADR-0025 decision 1).
- The only stable identity is the finding id. The `findings` upsert leaves `id` out of `set_`
  (ADR-0020 decision 1).
- `/risks` and `/scored-risks` are both asserted to carry no `id` on an item (`assert "id" not in
  item` in `test_risks_routes.py` and `test_scored_risks_routes.py`). Both forbid `resolved`,
  `is_open` and `status` on an item, as does the findings listing.
- `risk_engine/ports/explainable_risk.py` publishes `ExplainableRiskPort.explainable_risk(*,
  project_id, user_id, finding_ids)`. It selects the current surface whose sorted ids equal the
  request's, raises `NoCurrentRisk` when none does, and authorizes through `may_read_project`
  beneath it.
- `history` is already named by `layers-history`, `cross-module-history` and
  `framework-isolation` in `pyproject.toml`. `cross-module-history` forbids other modules'
  `.domain` and `.adapters`. It does not forbid their `.application`, which is **G35**, so
  "`history` imports only other modules' `ports`" holds by rule 3 and by review, not by CI.
- No request schema in `projects` sets a `max_length`. `brief`'s request schema bounds no length
  either: `GenerateSecurityBriefRequest.finding_ids` carries `Field(min_length=1)` and a
  duplicate-rejecting validator, and no maximum (ADR-0033 decision 9).

## Decision

### 1. A dismissal is a record with a surrogate id and a snapshot of the surface's members

A `risks` row holds:

- `id`, `String(36)`, from `IdGeneratorPort` (rule 9);
- `project_id`, with no foreign key, as a cross-module reference (ADR-0017 decision 1);
- `finding_ids`, `ARRAY(String)`, with `CHECK (cardinality(finding_ids) >= 1)`: ADR-0033
  decision 1's shape.

**The snapshot is the surface's own sorted ids as `ExplainableRiskPort` returns them**, never the
request's echo, so a record stores what the engine scored rather than what a client sent.

**A row is written only by a dismissal and is never refreshed.** Its `id` addresses the *record*,
an immutable snapshot, and not the live surface. ADR-0025 decision 1's objection to a held address
is that it *"silently repoints a held URL at a different group"*. A snapshot cannot repoint,
because nothing rewrites it. The Risk listings stay id-less.

### 2. The same-Risk rule: a current surface is dismissed iff it is a subset of an active snapshot

A current surface is **dismissed** iff its finding-id set is a **subset** of some record's snapshot
whose latest event is `dismissed`.

| Membership change since the dismissal | Result |
|---|---|
| unchanged | dismissed |
| a member dropped | dismissed |
| the surface split | every half dismissed |
| a new member joined | **not dismissed**: the Risk reopens |
| merged with an undismissed group | not dismissed |

**The rule never hides a finding that was not in a snapshot.** That is the property it is chosen
for. The rejected rules (a superset, any overlap, the match key) each let a new finding, a
`CRITICAL` one included, join a dismissed Risk and stay hidden.

It is one pure function in `history/domain`, over primitives. It is live in `src/` from this issue,
because the write path uses it (decision 11).

### 3. A derived Risk splits under a map change, and both halves stay dismissed

A surface whose Semgrep members attach through a route map under a serving declaration (ADR-0029,
**G53**) changes shape when the map or the declaration changes. The Semgrep members fall back to
no-signal singletons and the ZAP members keep their path group. Every half is a subset of the
snapshot, so every half stays dismissed. That is intended. A half gaining a new member reopens.

### 4. A `DEDUP_HASH_VERSION` bump orphans every snapshot

ADR-0019 decision 6 migrates a hash bump by re-normalizing from `ScanResult.raw_output`. The
findings upsert conflicts on `(project_id, dedup_hash)`, so a re-derived finding under a new hash
is a new row with a new id. That decision does not say whether the old rows are removed, and
every dismissed Risk reopens either way:

- **if the old rows are removed**, a snapshot names ids that no current surface contains;
- **if they are kept**, every surface gains the re-minted twin of each member, so it is a superset
  of its snapshot.

Registered as **G90**. Its trigger is the next bump.

### 5. Dismiss only. Resolution stays M9.1's

ADR-0025 decision 5 item 2 says *"M9.1 owns resolution, M8.1 the lifecycle"*, and three tests pin
the absence of `resolved`/`is_open`/`status`. A manual "resolve" before M9.1 would be a dismissal
under another name, and it would conflict with the next scan that still sights the member.
`ResolveRiskUseCase` moves to M9.1. The exit condition's *"resolves or dismisses"* is met by
dismiss. Undo (decision 10) is not resolve.

### 6. `history` owns the tables and validates through `risk_engine`'s published port

- **Validation.** Dismiss calls `ExplainableRiskPort.explainable_risk` with the request's ids. The
  port selects by exact set, fails closed with `NoCurrentRisk`, and authorizes at member level.
  What it returns is the snapshot.
- **`history/domain` names no other module's type.** It holds primitives only, so no second
  **G77** arises. The port's return value is taken by inference in `application/`, the idiom
  `ComputeRiskUseCase` uses.
- **Direction.** `history` imports two other modules' ports: `risk_engine.ports` for validation,
  and `projects.ports.ProjectAccessPort` for undo and the list (decision 10). Neither module
  imports `history`. M8.2's dashboard overlay is `history`'s (M8.2 is `Module: history`), so no
  module cycle arises.
- **Cost.** Each dismissal runs the doubled findings read once (**G61**). Dismissals are rare next
  to reads.

`risk_engine` and `correlation` are not chosen as owners: each would amend a statement that it
persists nothing (ADR-0005 decision 3, ADR-0025 decision 1).

### 7. An append-only event log, ordered by an ordinal

```
risk_events
  id             String(36)  PK
  risk_id        String(36)  NOT NULL, FK risks.id       -- within the module
  ordinal        Integer     NOT NULL                    -- 1 for the first event
  kind           String      NOT NULL                    -- dismissed | undismissed
  actor_user_id  String(36)  NOT NULL                    -- identity's users; no FK
  reason         Text        NULL
  occurred_at    DateTime(timezone=True) NOT NULL        -- ClockPort (rule 14)
  UNIQUE (risk_id, ordinal)
```

- **`kind` is pinned by a `CHECK`.**
- **`reason` is required and non-blank for `dismissed`, optional for `undismissed`.** It is
  enforced twice, by a domain `__post_init__` and a `CHECK`, ADR-0017 decision 1's idiom.
- **`reason` is at most 2,000 characters for either kind**, enforced twice: the request schemas'
  `max_length` and `CHECK (char_length(reason) <= 2000)`. The figure is borrowed from ADR-0034,
  whose M6 check (ii) bounds a narration every member reads at 2,000 characters. That check
  bounds model *output*; this is the first bound on member-supplied *input*. The unbounded member
  input elsewhere is a hole, not a precedent, and is registered as **G91**.
- **The ordinal is the order.** `occurred_at` is a record of when, and it ties under one clock
  tick, while a UUID is no tiebreak. The latest event is the highest ordinal.
- **A record is dismissed once and undone at most once.** Decision 11 refuses an undo of a record
  that is already undone. A later dismissal of the same surface finds no active snapshot and writes
  a **new** record. So a record holds ordinal 1, `dismissed`, and at most ordinal 2, `undismissed`.
  Every act of dismissal is its own record.
- **Concurrent appends collide rather than interleave.** The writer computes `latest + 1` and inserts
  with `ON CONFLICT DO NOTHING RETURNING`. A lost race, such as two undos of one record, returns no
  row and becomes a 409. It is not an `IntegrityError`, for the failed-transaction reason ADR-0014
  and ADR-0017 give.
- **Append-only.** No statement updates or deletes a `risk_events` row, and none updates a `risks`
  row. PRODUCT_SPEC §7 asks for a permanent history.
- **Current state is derived** from the latest event and never stored (ADR-0019 decision 1).
- **No "opened" event.** A projection has no moment of creation, and nothing writes when a Risk
  first appears. PRODUCT_SPEC §11.5's *"opened"* is qualified by a dated line.
- **A reopen by drift is derived at read time and is not an event.** Recording detected changes is
  M9.1's.

### 8. G37 is resolved by structure: user state lives where no projection writer can name it

G37 asked that the columns a re-correlation may not overwrite be a property of the statement, the
way ADR-0020 decision 1 left the identity inputs out of `set_`.

- **User-set state lives only in `risk_events`.**
- **No projection writer exists.** Nothing writes a `risks` row from the projection. ADR-0025's
  Alternatives explains why none is built: it needs a write trigger this project has never
  designed.
- **`risks` holds identity columns only.** Its protected and refreshed sets are both empty. A
  partition test pins `RiskModel`'s columns as identity ∪ protected ∪ refreshed, disjoint and total,
  on ADR-0020 decision 4's layer 1, so an added column fails until it is classified.
- **A behaviour test** dismisses, changes the inputs through the real finding repository, runs every
  writer the system has, and reads the record and its events back unchanged through a second session.
- **Reopen trigger:** the first statement that writes or updates a `risks` row from the projection.

### 9. G11: no link table, and the count goes to six

The set is data on the row, as `security_briefs` holds it. Two more tables depend on rows never
being deleted: `risks` (`project_id`, and an ARRAY that cannot carry a foreign key) and
`risk_events` (`actor_user_id`). **G11** is a forecast about retention and stays open.

### 10. Member-level authorization, and undo as a new event

- **Every route asks `may_read_project`.** Dismiss inherits it through `ExplainableRiskPort`. Undo
  and the list consume `ProjectAccessPort` directly, before any read, because they read only
  `history`'s own tables (ADR-0033 decision 7's list precedent).
- **Why member level.** ADR-0035 decision 2 defines "manage" as owner-class actions that cost real
  compute **and** can point an attack tool at a URL, both conditions together. A dismissal does
  neither. (That decision's one sentence about M8.1 concerns a different name: it says a verdict
  called "write" would be misused by a member's dismissal, which is why the owner verdict was named
  "manage".)
- **The mitigation is visibility, while it matters.** A record is listed to every member, the owner
  included. While it is dismissed, its latest event is the dismissal, so `GET` shows who dismissed
  it, why and when. Once undone, the Risk is no longer dismissed and `GET` shows the undo's actor,
  reason and time. The original dismissal stays in `risk_events` and is not returned. **G75**
  records that member level coincides with owner at HEAD.
- **One 404 for every denial** (ADR-0022 decision 2).
- **Undo** appends an `undismissed` event under the same verdict. Its reason is optional. Nothing is
  mutated or deleted.

### 11. A state conflict is a 409 that writes nothing, and a refused dismissal names what to undo

- **Dismissing an already-dismissed surface is refused.** If an active snapshot covers the current
  surface, dismissal answers 409 with `{covering_dismissal_id}`: the covering record whose current
  `dismissed` event has the highest `occurred_at`, ties broken by record id. The client needs that
  id to find the record to undo. This is not event ordering, which decision 7 gives to the ordinal:
  it picks one id deterministically among records, which share no ordinal.
- **Undoing a record whose latest event is `undismissed` is refused**, as is a lost ordinal race.
- **Residual, registered as G92.** Two concurrent dismissals of one uncovered surface can both pass
  the check and write two records. The rule stays correct, but undoing one leaves the surface
  dismissed by the other.

### 12. Three routes, in `history`'s router, mounted under `/projects`

```
POST /projects/{project_id}/risk-dismissals                       → 201
POST /projects/{project_id}/risk-dismissals/{dismissal_id}/undo   → 201
GET  /projects/{project_id}/risk-dismissals                       → 200
```

No path ends in a slash (ADR-0031's trailing-slash limitation).

**`POST …/risk-dismissals`**, body `{finding_ids, reason}`:

| Condition | Status | Detail |
|---|---|---|
| Access denied | 404 | as the sibling routes |
| `NoCurrentRisk` | 404 | fixed, telling the client to re-read `/scored-risks` |
| `ExplainableRiskInconsistent` | 500 | fixed (ADR-0030 decision 5) |
| Already covered | 409 | body `{covering_dismissal_id}` |
| Empty or duplicate ids; a blank reason; a reason over 2,000 characters | 422 | |

**`POST …/undo`**, body `{reason?}`, at most 2,000 characters:

| Condition | Status |
|---|---|
| Access denied, an absent record, or a record of another project | 404 (ADR-0035 decision 4's shape) |
| Not currently dismissed, or a lost race | 409 |

**`GET …/risk-dismissals`** is paged on M4.5's `DEFAULT_PAGE_LIMIT`/`MAX_PAGE_LIMIT`, declared
locally (**G35**), newest record first: ordered by the `occurred_at` of the record's first event,
descending, then by record id. `risks` carries no timestamp of its own.

**Every item and both 201 bodies** are one rule-10 schema, `{id, finding_ids, state, reason,
actor_user_id, occurred_at}`. The last four come from the record's latest event. A user id is not a
credential under rule 12, and ADR-0035 decision 4 already returns one. **The 409 body** is its own
rule-10 schema, `{covering_dismissal_id}`. Every key set is pinned by an equality assertion.

### 13. The Brief is untouched

A Brief keeps its surrogate id and its `finding_ids` as data (ADR-0033 decision 1). It is not
re-keyed onto a dismissal. `POST /briefs` on a dismissed Risk is not refused here; whether to refuse
it is M8.2's and M8.3's policy. A dismissal's `reason` never enters a prompt (ADR-0034).

## Consequences

**Rule 16 fires on four clauses.** A migration (`risks`, `risk_events`). New frozen domain types
(the Risk record and its event). An authorization control (member-level dismissal and undo, and the
list's `ProjectAccessPort` consumption). Three routes with their request and response shapes. This
ADR is what the implementation commit cites.

**`MatchGroup` and `ScoredSurface` do not change.** Neither do `/risks` and `/scored-risks`, whose
items stay id-less and lifecycle-free. The overlay that shows a Risk as dismissed on a ranked list is
M8.2's. Until it lands, dismissed state is observable only on `GET …/risk-dismissals`.

**Amended the same day:** ADR-0025 (decision 1 stands, and a dismissal snapshot is not a Risk
address; decision 2's forced write lands here) and ADR-0020 decision 3 (the named fields live in
`history`'s event table, never on a Risk upsert). `PRODUCT_SPEC.md` §11.5 is qualified.

**Register.** **G37** resolves. **G11** gets a count note. Notes on **G52**, **G53**, **G61** and
**G75**. **G90**, **G91** and **G92** are opened.

## Amendments

- **2026-09-19 (M8.1 commit 2): two sentences made precise by the implementation.**
  - **Decision 7's "enforced twice" names one set of blank characters.** The first draft's CHECK,
    `btrim(reason) <> ''`, strips only spaces, while Python's `str.strip()` strips every Unicode
    whitespace character, so the database passed a tab-only reason the domain refused. "Blank" is
    now `REASON_BLANK_CHARS`, ASCII whitespace, in the domain, both request schemas and
    `ck_risk_events_reason_not_blank`, which reads `btrim(reason, E' \t\n\r\x0B\f')`. A reason of
    only U+00A0 is not blank, in all three places. Found by `architecture-guardian`.
  - **Decision 8's behaviour test is narrowed.** *"runs every writer the system has"* is replaced by
    *"runs every writer that touches a finding or a dismissal: the findings upsert, a scored read, a
    dismissal and an undo"*. Scanning, normalization and Brief writers are not run, and none of them
    names `risks` or `risk_events`.

## Alternatives considered

- **The match key as the attachment.** Rejected. It collides for every no-signal finding (ADR-0025
  decision 1), so dismissing one no-signal singleton would dismiss them all, and it hides a new member.
- **A snapshot with an exact-set, superset or any-overlap rule.** Exact set loses the dismissal on
  any drift. Superset and overlap hide a finding that was never dismissed. Rejected in decision 2.
- **Dismissal per member finding.** It behaves like the subset rule except where two dismissals cover
  one surface, needs a third "partly dismissed" state, and contradicts ADR-0020 decision 3's
  placement of such fields on the Risk. Rejected.
- **A link table `risk_findings`.** One more table for G11, for a "which Risks contain finding X"
  query nothing asks yet. Rejected in decision 9.
- **A stored `status` column on `risks`.** A stored derivable summary (ADR-0019 decision 1), and a
  protected column on the one table a future projection writer would touch. Rejected in decisions 7
  and 8.
- **Ordering events by `occurred_at`, id.** Ties resolve arbitrarily, so a dismiss and an undo at one
  timestamp can report the wrong state. Rejected in decision 7.
- **Owner-only dismissal through `may_manage_project`.** It would re-define ADR-0035's "manage".
  Rejected in decision 10.
- **Manual resolve beside dismiss.** Rejected in decision 5.
