# ADR-0022 — The findings read surface: evidence exposure, cross-module authorization, and what a response says about its own completeness

## Status

Accepted — 2026-08-23 (M4.5)

## Context

M4.5 is the milestone's proof point: the first issue that produces something a
human can look at. Everything before it — the handoff, the domain, identity,
persistence, the job — is only observable through `psql`.

Most of what it builds implements decisions already made. Pagination shape,
`Severity` coercion at the boundary (ADR-0018 decision 2), ordering derived from
one source of truth (ADR-0020 decision 4's idiom) and an index shipping with its
query (ADR-0017) are *applications* of existing rules, and belong in the roadmap
entry and in code comments rather than here. This document records only the three
questions M4.5 had to answer for itself:

1. **What the endpoint exposes of `Evidence.raw_payload`.** It is a verbatim copy
   of a scanned source element, so returning it is a rule-12 surface; FR-9
   requires evidence traceability, so refusing to return it needs an argument
   about how traceability is met instead. The two pull in opposite directions and
   neither yields.
2. **How a module that is not `projects` authorizes a project-scoped read.** FR-1
   puts RBAC at the project level and `PRODUCT_SPEC.md` §11.2 requires least
   privilege, but the only precedent — `projects`' own routes — is *same-module*,
   so it reaches `require_member` and `InsufficientPermissions` directly.
   `normalization` may not (rule 3). There is no cross-module precedent at all;
   this issue creates the one M5.2, M6.3, M7.2 and M8.2 will copy.
3. **What the response says about its own incompleteness.** G15: a transient
   normalization failure that exhausts arq's retries is never recovered, and
   nothing surfaces `NormalizationRun`. A project listing shortened by that is
   indistinguishable from a clean project.

Two pre-existing defects surface here because a response schema is the first
thing that has to decide what to do with them: `raw_payload[:MAX_RAW_PAYLOAD_CHARS]`
truncates into invalid JSON (M4.1, noted in ADR-0019's Consequences), and a
`Severity` crossing an HTTP boundary keeps equality but loses ordering.

**Written against measurement, like ADR-0018 and ADR-0019 before it.** Three
numbers below are load-bearing and one of them reversed a decision this ADR was
drafted to defend.

## Decision

### 1. The listing returns evidence metadata; a second route returns the payload

```
GET /projects/{project_id}/findings                        # metadata only
GET /projects/{project_id}/findings/{finding_id}/evidence  # the payload
```

FR-9 requires that every Risk and Brief *"link back to"* the raw findings and
tool output that produced it. **An addressable route is that link.** Reading FR-9
as "return the payload inline" is convenience rather than the requirement, and it
is the reading that would put scanned source into every listing.

**The rule-12 hazard is the bulk shape, not the payload.** A listing carrying
every finding's `raw_payload` is a source-code export with nothing in its
signature saying so. Measured: the three committed fixtures produce 34 findings
whose payloads total **93,792 characters** — for ZAP alone, 1.43× that scan's own
`raw_output`. *(Re-derived at M5.1 against the G23 common-target corpus; the
pre-G23 figures were 24 findings, 71,532 characters and 1.63×. Both the total and
the ZAP ratio moved, and the decision rests on neither's exact value.)* A single request would hand over all of it. Splitting also makes
each access its own request with its own URL, which is auditable and
independently rate-limitable at M10.2 where a query flag would hide it inside a
listing.

**A `?include_evidence=true` flag was the cheaper option and is rejected on that
same ground**: it is the same bulk exposure behind a parameter, and a client that
sets it by default turns every listing into an export while leaving no distinct
record of what was read.

**The evidence route is where the rule-12 surface is handled rather than
inherited.** Its docstring records, in code, that the body carries a verbatim copy
of a scanned element; that Semgrep's `extra.lines` is normally the matched source
line; and that secret-detection rules match secrets. It is inert today only
because anonymous Semgrep OSS redacts that field to the literal `"requires login"`
and this repo sets no `SEMGREP_APP_TOKEN` — an accident, not a design. **G7's
`Blocks-if-unresolved:` is updated to name this route** rather than "M4.5's
response surface" in the abstract, now that the thing that would leak has a path.

**What is omitted from the listing, and why, since a list of inclusions explains
nothing:** `dedup_hash` (internal identity with a version prefix — a client
keying on it would make a `v2:` bump, already a re-normalization by ADR-0019
decision 6, a breaking API change on top of one); `evidence.id` and
`evidence.finding_id` (surrogate keys of a 1:1 row nothing addresses by them);
`project_id` per item (it is the path parameter). `rule_id` and
`location.file_path` **are** returned, and they are the two fields G9 and G10 each
name as "M4.5 returns an absolute worker filesystem path in a response body" —
closed by M4.4's `cwd=target` plus `--no-rewrite-rule-ids`, and now asserted at
the surface that would have shown it.

#### `payload_truncated`, named for the fact rather than the test

The payload is returned as an **opaque string**, never parsed and re-serialized,
because re-serializing would mutate the verbatim copy ADR-0018 decision 6
requires. Truncating at an element boundary is rejected for the same reason: a
slice *is* a verbatim prefix, which is the principled form of a cut.

The flag asserts **"this payload is an incomplete prefix of its source element"**
— deliberately not "this is valid JSON". A reader given
`payload_parses_as_json` would take it as permission to parse; what a caller needs
is whether it has the whole element. The two facts coincide today because the only
lossy step is a character slice, and they **diverge under exactly one change**: a
mapper that truncated at an element boundary would produce something that parses
while still being incomplete. Registered as **G16** with that as its trigger.

**A stored `Evidence.truncated` column is refused, and the refusal rests on a
measurement rather than a preference for fewer columns.** Across the three
committed fixtures the largest payload ever produced is **9,888 characters
against a 20,000 cap — 49%**. The cap has never fired. A column, a domain field
and a migration to describe a state nothing has ever reached is the speculative
shape ADR-016 decision 3 refuses and ADR-0021 refused again for `skipped_count`.
The other alternative, `len(raw_payload) == MAX_RAW_PAYLOAD_CHARS`, is worse than
either: it *fabricates* truncation for a payload landing exactly on the cap, which
is the failure ADR-0019's principle ranks above under-counting.

#### Where `SightedFinding` lives, and the criterion

Two new types were needed and placing both in `domain/` by habit is how a
criterion stops being one, so it is stated and applied twice:

> `domain/` takes types whose fields are **facts about the system being
> modelled**. A type whose fields are **artifacts of how a caller asked the
> question** — a page size, an offset, a total assembled for an envelope — is not
> one, however convenient it would be to return.

`SightedFinding` is in: every field is `min()`/`max()`/`count()` over
`FindingSighting`, which ADR-0019 decision 1 already states in domain language
while forbidding the *stored* copy. A `FindingPage` is out, and rather than
relocating it the type is **dissolved** — the port returns `list[SightedFinding]`
plus a separate `count_for_project`. `limit`/`offset` as port *parameters* already
have precedent (`get_stale(*, older_than, limit)`, M4.4); it was only a dataclass
of paging fields that had no home. Cost, named: two statements under READ
COMMITTED, so a concurrent normalization can leave `total` disagreeing with the
page by a row — the same class of inconsistency offset paging already carries.

### 2. `projects` publishes a verdict-returning access port; both denials are 404

```python
class ProjectAccessPort(Protocol):
    async def may_read_project(self, *, project_id: str, user_id: str) -> bool: ...
```

The alternative was for `normalization` to depend on `ProjectRepositoryPort` and
`ProjectMembershipRepositoryPort` directly — contract-legal under rule 3 and
ADR-0010, needing no new port, and costing "two lines" of duplicated check.

**Rejected, because the two lines are an *authorization rule*, and a rule's value
is that there is one of it.** Today the rule is "a membership row exists". When
`projects` adds a VIEWER role, or makes reads role-sensitive, or introduces
org-level scoping, that rule changes in one place — and a reimplementation in
another module does not hear about it and does not fail loudly. It keeps
authorizing under the old rule. A revoked user, or one holding a role that should
not read findings, reads them.

**The structural objection is the same one this project has now drawn twice.**
`ProjectMembershipRepositoryPort` is a *persistence* port: it returns rows. A
consumer in another module reading it thereby learns that authorization means "a
membership row exists" — `projects`' domain knowledge crossing a boundary through
a repository. ADR-0017 made the handoff port take primitives so no domain type
crossed; ADR-0018 scoped `shared_kernel/` to vocabulary that is *compared* rather
than structures that are *transported*. A port returning a bool crosses the
**verdict**, not the data the verdict is made from.

The rule stays in `projects`, as `domain/authorization.may_read` beside
`require_member`, so one function changes and every consumer follows.

**And the precedent count is an argument for, not against.** M5.2, M6.3, M7.2 and
M8.2 each need this same decision. Under the reuse option that is five
reimplementations of one authorization rule across five modules with nothing
relating them. A precedent four issues copy is what establishing a pattern at the
first consumer means.

**One method, not `project_exists` + `is_member`, and that settles 404 versus
403.** Two methods would let a caller rebuild the existence leak on its own side
and would put the "what does a non-member see" policy in the *consuming* module.
With one there is no vocabulary for which reason applied, so both cases return
**404** — a non-member cannot distinguish an existing project from an absent one.
The policy is structural rather than conventional, and cannot drift back to a 403
without changing the port.

**This diverges from `projects`' own routes, which answer 403.** Deliberate:
findings are the sensitive read in this system, and project-id enumeration against
a findings endpoint is worse than two routers disagreeing on a status code. Two
register entries, not one, because the causes and the fixes point different ways:
**G17** is the divergence this commit introduces — and its real cost is that *the
404 conceals nothing while a sibling route still answers 403*, since a caller
recovers existence with a second request — while **G18** is the pre-existing leak
those six routes have carried since M1.4/M2. Closing G18 as "accepted" would
leave G17 open; the convergence needs a direction, and that direction is G18's to
choose. Both assigned to M10.2, whose scope is "verify enforcement at every
endpoint".

### 3. The envelope carries normalization state, and the count is the load-bearing half

```json
"normalization": {
  "latest_run": {"scan_id": "…", "status": "failed", "failure_reason": "…", …},
  "unfinished_runs": 3
}
```

**`unfinished_runs` is what answers "may this list be incomplete?", and
`latest_run` alone would not.** A project whose most recent scan normalized
cleanly while three earlier ones failed reports `completed` and looks healthy,
while three scans' findings were never produced. That is precisely G15's shape,
and a single latest-run field would report it as fine.

Two new methods on `NormalizationRunRepositoryPort`, both entirely within
`normalization` — answerable only because ADR-0019 decision 7 put `project_id` on
that table. Counts `pending`, `running` and `failed` alike: to a reader, "not
normalized yet" and "normalization failed" say the same thing about the list in
front of them, and the latest run's `status` is there for anyone needing the
difference.

**Returning `failure_reason` is safe by design rather than by luck**, and the
design was M4.4's. That issue made the transient branch persist the exception
**type only** — because SQLAlchemy's `StatementError.__str__` renders
`[parameters: …]`, which for the finding upsert means `title` and `raw_payload`,
i.e. scanned source — and the skip branch persist only a count and `dedup_hash`
values. Both comments name this endpoint as the reason. Rule 12 holds here because it
was enforced at the write — and the assertion that keeps it honest is
`test_normalize_scan.py`'s, shipped in **M4.4 alongside the branch it guards**,
not here. M4.5 adds no leakage test for it, and saying so matters: an ADR
claiming a test ships with the consumer would send a future reader looking in the
wrong file for the thing that actually holds the line.

**G15 is narrowed, not closed.** The visibility half now has a route. The recovery
half — a transient failure that exhausts arq's retries is never re-enqueued,
because the sweep excludes `failed` — is untouched. Its entry's claim that
`failure_reason` is "reachable only by querying Postgres by hand until M4.5 ships
an endpoint" stops being true in this commit and is corrected there.

### 4. `ix_finding_sightings_scan_id` does not ship; `ix_normalization_runs_project_id` does

ADR-0020 named M4.5 or M9.1 as the issue that would carry the first. **This
endpoint has no scan-first query**: it is project-scoped and scan-independent, and
the per-finding sighting summary is correlated on `finding_id`, the leading column
of the sightings primary key. ADR-0017's rule — *an index without its query is a
guess at that query's shape* — applies with nothing against it.

That follows from decision 5, not from convenience.

What does ship is `ix_normalization_runs_project_id` on
`(project_id, requested_at DESC)`, carrying decision 3's two queries, which had no
index at all on a table that grows one row per scan forever.

### 5. The listing is project-scoped and scan-independent

"The findings for this project" is not "the findings in the latest scan", and this
endpoint answers only the first. It exposes **when** a finding was last seen and
never **whether it is still present**.

A `?status=open` filter is the strongest product story available here, and that is
exactly why it is the trap. It needs "the latest scan for this project" —
`ScanRepositoryPort` has `add`/`get_by_id`/`update` and no such method — and it
needs the succeeded-tools scoping ADR-0019's Consequences requires. Shipping it
here means building resolution detection without the decision that makes it
correct, and the failure that produces is G4's shape: Trivy fails, the scan is
`PARTIAL`, `get_succeeded_by_scan_id` returns two tools, and a naive absence check
silently marks every dependency finding in the project resolved. Nothing raises.

M9.1 receives the scan-first query, the index in the migration carrying it, the
absence check and the succeeded-tools caveat **together, as acceptance criteria in
one place** rather than scattered across two ADRs' Consequences sections and a
roadmap bullet.

## Consequences

### The measurement ADR-0020 asked for, and the decision it reversed

ADR-0020 instructed M4.5 to `EXPLAIN` the project listing and the sighting join at
realistic volume, and warned that a benchmark over 24 fixture findings would
measure nothing while reading as evidence. `scripts/seed_findings_benchmark.py` is
versioned so these numbers can be re-derived rather than believed — a recorded
command with no script to run is what ADR-012's unvalidated 180s became.

```
uv run python scripts/seed_findings_benchmark.py --projects 50 --findings-per-project 2000
```

100,000 findings, 100,000 evidence rows, 300,000 sightings, 50 projects, Postgres
16:

| query | plan | time |
|---|---|---|
| filtered listing, `LIMIT 50` | page rides `uq_findings_project_id_dedup_hash` (bitmap index scan); LATERAL runs 50× on `finding_sightings_pkey` | **3.07 ms** |
| the `total` count | same index prefix | **0.50 ms** |

**The first implementation of that query took 763 ms, and this ADR was drafted
predicting it would be fine.** The sighting summary was a whole-table
`DISTINCT ON` merge-joined against the page. Postgres cannot push the page's fifty
ids into it, so it seq-scanned all 300,000 sightings and sorted them on disk
(`external merge`, 22 MB) to return fifty rows. Rewritten as a LATERAL correlated
to one finding — each an index scan of that finding's ~3 sightings — it is
**250× faster**.

**The way that was nearly missed is the more useful half.** The same query
measured **8.8 ms** on the first run, because the synthetic finding ids were
sequential: one project's findings clustered at the head of the id-ordered scan,
so the merge join terminated almost immediately. Real ids are UUIDs (rule 9) and
do not cluster. The fast number described the id scheme, not the query. The
generator now emits UUID-shaped ids and says why in a comment, because a
benchmark whose synthetic data has a property production lacks is G8's and G9's
failure — verification that is sound and disconnected from reality — arriving
through a seed script. Registered as **G19** — the third instance of that pattern, after a
tool (G8) and a fixture (G9), and the first whose trigger is "somebody writes a
seed script", which is a moment neither existing entry would have prompted anyone
to re-read. M5.3's curated correlation fixture set is the named next occurrence.

**ADR-0019 decision 1's `last_seen` cache invitation is re-read here, as ADR-0020
instructed, and declined.** It was the wrong lever: the problem was never that
aggregating sightings is expensive, it was that the query aggregated *every*
finding's sightings to serve one page. Correlating fixed it without denormalizing
anything, so no silently-staleable summary enters M9.1's path. Revisit if a
project's own page ever measures slow, which is a different observation from this
one.

**What these numbers do not show**, stated because a table invites over-reading:
real selectivity, real payload-size distribution, and any behaviour under
concurrency. The data is synthetic and uniform. Read the plans for access-path
shape; do not quote the milliseconds as production latency.

**The shipped index was also measured, and at first it was not used.** At three
runs per project (150 rows) Postgres seq-scans `normalization_runs` however good
the index is — which says nothing either way. `--runs-per-project 400` (20,000
runs) exercises the case the index actually exists for, since that table grows one
row per scan rather than per project: `get_latest_by_project_id` becomes an
`Index Scan using ix_normalization_runs_project_id` reading 2 rows (**0.059 ms**),
and the unfinished count a bitmap index scan (**0.071 ms**).

### The §10 noise-reduction number: half of it, and the honest half

`PRODUCT_SPEC.md` §10 measures noise reduction as the ratio of raw findings to
surfaced **Risks**, and `Risk` is M5/M6, so the ratio itself waits. What M4.5
makes observable is the denominator, and it is not flattering: the three committed
fixtures produce **34 source elements → 34 findings, a 1:1 collapse**, because no
two elements in that set share an identity. *(24 → 24 before the M5.1 re-capture.
The corpus grew; the collapse ratio did not change, which is the observation this
paragraph is making.)* That is a statement about the fixture
set being too small to exercise within-scan dedup, not about the product.

The number this endpoint *does* demonstrate is FR-5's actual criterion: scanning
the same repository twice leaves `total` unchanged and increments every
`sighting_count`. Those are different claims and only the second is dedup.

### Rule 13 is inert here

Rule 13 governs **HTTP redirects** — no credential, token or secret in a
`Location` header. Both routes return `200`/`404`/`422` with a JSON body and never
set `Location`. Rate limiting is M10.2 and security headers M10.4; no existing
route has either, so this one inherits nothing because there is nothing to
inherit. The evidence route is this project's first response whose body size is
bounded only by `MAX_RAW_PAYLOAD_CHARS` rather than by a fixed schema, which makes
it the natural first candidate for M10.2 — a pointer in its docstring, not a
register entry, since M10.2 already owns every endpoint.

### Inherited elsewhere

**M5.2, M6.3, M7.2 and M8.2 inherit decision 2** as the shape for every future
cross-module project-scoped read: consume `ProjectAccessPort`, never a persistence
port, and answer 404 for both denials.

**M9.1 inherits decision 5's four items together**, recorded in its roadmap entry
rather than only here.

**M10.2 inherits G17 and G18**, which have to be resolved in that order.

**`get_by_project_id` survives on `FindingRepositoryPort`** rather than being
replaced by the listing, and the reason is not inertia: `list_for_project`
enforces that every finding has a sighting and raises otherwise, so it cannot read
a finding the *write path* stored alone. Keeping a reader that does not share the
listing's invariants is what stops a defect in the sighting join from masking a
defect in the upsert — ADR-0020 decision 4's own argument for `upsert` returning a
`RETURNING` row rather than the object it was handed.

## Alternatives considered

**`?include_evidence=true` on one route.** Rejected in decision 1: the same bulk
exposure behind a flag, with no distinct record of what was read.

**Never returning the payload at all.** Rejected: M4 would close with no evidence
traceability, while FR-9 is an MVP requirement and M4 is the findings milestone.
It would also surface `payload_truncated` in metadata while offering no way to
look at the thing it describes.

**A stored `Evidence.truncated` column.** Rejected in decision 1 on the 49%-of-cap
measurement, not on principle. It is the correct fix if a mapper ever changes how
it truncates, which is what G16 exists to catch.

**`normalization` consuming `ProjectRepositoryPort` + `ProjectMembershipRepositoryPort`.**
Rejected in decision 2. It is the option that needs no new port, and it buys that
by putting a second copy of an authorization rule in a second module.

**`get_membership(...) -> Role | None` as the access port.** Rejected: it hands
over the ingredients rather than the verdict, so the consuming module decides what
membership means. The reuse option wearing a different name.

**`project_exists` alongside `is_member`, to keep `projects`' 403.** Rejected in
decision 2: it rebuilds the existence leak on the caller's side and relocates the
404/403 policy into whichever module happens to be reading.

**A keyset cursor on `dedup_hash`.** Genuinely better under concurrent writes —
`dedup_hash` is unique within a project and frozen by the upsert, so the cursor
would be stable. Rejected because a keyset cursor must order by its unique key,
which forces hash ordering: an unreadable order for a security findings list, in a
product whose thesis is turning findings into decisions. `total` also disappears,
and M8.3 needs it.

**`array_position(ARRAY[…], severity)` for the ordering** instead of a `CASE` over
`Severity.rank`. Both are generated from the enum rather than written out, so
neither is a second source of truth. The `CASE` wins narrowly because it reads
`.rank` itself, where `array_position` derives rank from a list *position* — one
indirection further from the source, and stale-able by a `_RANK` change that
reordered nothing.

**Always including `UNKNOWN` regardless of `min_severity`.** Considered because
filtering by rank means `?min_severity=low` drops findings whose severity no tool
could determine, which is surprising. Rejected: it makes the parameter's name a
lie, and `?min_severity=unknown` is already a no-op escape hatch. Honouring one
total order and documenting the edge beats two orders that disagree.
