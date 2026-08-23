# ADR-0019: `Finding` identity, deduplication, and what the hash is over

## Status

Accepted

## Context

`ROADMAP.md` M4.2 asks for a "dedup hash strategy" such that "re-running a scan doesn't duplicate identical findings". That criterion cannot be met by adding a hash field, because the entity it would sit on is scan-scoped. **G5** states the tension: `Finding` carried a single `scan_id` while `PRODUCT_SPEC.md` FR-5 requires deduplication *across repeated scans*. With one `scan_id` there are two outcomes and both are wrong — either the same underlying finding gets a fresh row per scan, so nothing dedupes, or the first row is kept and its `scan_id` points at a stale scan, so nothing records that the finding was seen again. M9.1 then cannot distinguish "still present in the latest scan" from "last seen three scans ago", and it fails *silently*, marking a live finding resolved.

So this ADR decides identity first and the hash second. Deciding either alone is not possible: a hash is an answer to "are these the same finding?", and that question is meaningless until the model says what a finding *is*.

**Written against captured output, like ADR-0018 before it**, and the ordering paid for itself again. Four measurements are load-bearing below, and three of them contradict what the shipped code or the roadmap assumed:

- **Semgrep emits absolute paths, and production's are unique per scan.** Verified by running the pinned ruleset twice: given an absolute target, `paths.scanned[]` is `['C:\…\src\verion\platform\__init__.py', …]`; run with `cwd` set to the target and `.` as the argument, it is `['__init__.py', 'app.py', …]`. `SemgrepAdapter.run()` passes an absolute target and `GitRepoCheckout` builds it with `tempfile.mkdtemp(prefix="verion-scan-")`. The committed fixture hides this — its `path` was redacted to `vulnerable.py` — so the mapper tests exercise the shape we want while production emits the shape we do not. Registered as **G9**.
- **ZAP's `instances[]` are not ordered deterministically.** One alert's three instances carry ids `6, 7, 5`: crawl order, not sorted. The shipped mapper took `instances[0]` as the location.
- **`alertRef` is finer than `pluginid`** (`10036-2` under plugin `10036`) and is present on every alert in both fixtures.
- **Trivy 0.74 emits a per-vulnerability `Fingerprint`**, which M4.1 did not record. It is opaque: 5,467 candidate concatenations of `VulnerabilityID`, `PURL`, `UID`, `PkgName`, `InstalledVersion`, `Target` and `ArtifactName` across five separators reproduce none of the captured values.

Two facts M4.1 already established are inputs here: Semgrep's `extra.fingerprint` is the literal `"requires login"` for anonymous OSS (**G7**), so it is not an identity candidate; and Trivy's twelve vulnerabilities are unique on `(VulnerabilityID, PkgName)` alone.

## Decision

### 1. A `Finding` is durable and project-scoped; each scan's observation is a `FindingSighting`

```
Finding            id, project_id, dedup_hash (derived), source, rule_id,
                   severity, native_severity, title, location, evidence,
                   cwe, owasp_category, cvss          # no scan_id

FindingSighting    finding_id, scan_id, observed_at, match_count
                   # composite natural key, no surrogate id (ProjectMembership's shape)

Evidence           id, finding_id, scan_id, raw_payload, source_tool, captured_at
```

The alternatives are in *Alternatives considered*; what makes this shape the right one is two properties it has and they do not.

**Absence is expressible.** "Not sighted in scan N" is the absence of a row, and "scan N was never normalized" is `normalization_runs`. ADR-0017 decision 3 guarantees a run row exists **iff** `ScanResult` rows were persisted, so the two records compose into exactly the distinction M9.1 needs, with no third state and nothing to keep in sync. That composition is not a happy accident — it is the reason the sighting model is worth its extra table.

**Derived summaries stay derived.** No `last_seen_at` and no `last_seen_scan_id` on `Finding`. Both are `max()` over the sightings, and denormalizing them would put a summary that can silently go stale into M9.1's path — the failure ADR-016 decision 2 legislated against for `Scan.status`, arriving one table over. If M4.3 or M8.2 measures the join as the bottleneck, adding the cache then is additive; adding it now is a guess.

**Sightings are written by the normalization use case (M4.4), never by a mapper.** A mapper cannot know a finding's resolved `id`: identity is the hash and `id` is a surrogate, so only the repository's upsert on `(project_id, dedup_hash)` settles which id wins. A mapper emitting a sighting would emit a foreign key to a row that may never exist. Mappers therefore produce **candidate** findings, and `Finding.id` is only used when the finding turns out to be new.

`match_count` is on the sighting because it is a per-scan quantity: see decision 3.

### 2. The identity inputs are normalized into the common schema, so one hash function serves three tools

Per-tool hash functions were the obvious route and are rejected. Rule 4 is the least of it: M5 would be correlating over keys with no shared definition, and adding a scanner would mean editing identity logic rather than adding an adapter.

The reason one function *looks* impossible is a real hole in the common schema: **there was no field for "which rule or vulnerability fired".** Semgrep's `check_id`, Trivy's `VulnerabilityID` and ZAP's `alertRef` were all melted into `title` next to prose — `"CVE-2019-11324: python-urllib3: Certification mishandle…"` — where the stable half and the advisory-mutable half are one string. Hashing `title` would re-key every Trivy finding the first time an advisory's wording changed.

So `Finding` gains **`rule_id: str`**, the tool's own stable identifier, normalized by the mapper. This is the pattern the module already applies twice — `Severity`/`native_severity` collapses three scales, `canonical_cwe` collapses three spellings — applied to identity: the per-tool difference is a *mapping* concern, and mapping is already the mappers' job. `compute_dedup_hash` never learns a tool name; it takes `source` as data.

`rule_id` earns its place beyond identity, which is why it is a real field rather than a hash input passed through: M5 groups by rule across scans, M6 explains by it, M8 filters on it, and none of them can get it out of `title`. It is `str`, not `str | None`, with a labelled fallback (`"(unidentified)"`) in the same idiom `native_severity` uses for `"(absent)"`. **What that fallback buys is visibility, not collision-freedom, and the distinction is worth stating because the obvious reading is wrong:** two findings whose tool named no rule, at the same location, hash identically — a shared constant merges exactly as `""` or `None` would. That merge is the under-count side of decision 3's principle and is acceptable on its own terms. What it exposes is a second-order question this ADR deliberately does not answer: two such findings will usually disagree on `title` or `severity`, and `collapse_by_identity` raises on that, which in M4.4's use case would abort a whole scan's normalization over one malformed element — the `PRODUCT_SPEC.md` §12 corruption the `Location` guard was removed to avoid, arriving through a different validation rule. **M4.4 owns it as acceptance criteria, not as a note** — its roadmap entry carries the decision *and* the requirement that whatever is chosen be pinned by a test over a synthetic identifier-less element — because choosing between skipping the element, failing the run and marking `NormalizationRun` failed needs a caller to choose against, and M4.2 has none. It stays out of the Deferred gaps register on ADR-0017 decision 2's own test: the register is for gaps that are *not yet anybody's issue*, and this one has a named issue with a live assignment. The contrast with G9, which is registered despite also being assigned to M4.4, is deliberate and worth stating: G9's trigger is a condition nobody would notice and it blocks M5 and M4.5 independently of M4.4, so `Blocks-if-unresolved:` does real work there; this raise cannot fire before M4.4 gives `collapse_by_identity` its first caller, so it is bounded entirely inside that issue's own code path.

**What bounds the deferral is a measurement, recorded here so it does not survive only in a commit message: all 30 elements across the six committed fixtures carry their tool's identifier — 0 missing.** So the fallback is unreached by anything ever captured, and the case is latent rather than live. If a re-capture ever brings an element without one, that is the signal to stop treating this as latent.

**One caveat, measured rather than assumed: Semgrep's `check_id` embeds the ruleset file's path** for a local `--config` (`src.verion.modules.scanning.adapters.outbound.scanners.rulesets.dangerous-eval`). Moving `rulesets/default.yml` re-keys every Semgrep finding. That is a real property of this identity input and is recorded here rather than discovered by a future file move.

### 3. What the hash is over, per field — and the principle behind the exclusions

```python
compute_dedup_hash(*, source, rule_id, file_path, package, url, http_method, parameter) -> str
```

The parameters *are* the input set, deliberately: taking a `Location` would have hidden which of its eight fields participate, and three of them do not.

| input | Semgrep | Trivy | ZAP |
|---|---|---|---|
| `source` | `semgrep` | `trivy` | `zap` |
| `rule_id` | `check_id` | `VulnerabilityID` | `alertRef`, else `pluginid` |
| `file_path` | repo-relative path | `Results[].Target` | — |
| `package` | — | `PkgName` | — |
| `url` | — | — | instance `uri`, else the site |
| `http_method` | — | — | instance `method` |
| `parameter` | — | — | instance `param` |

**The principle the exclusions rest on, stated once so the next occurrence is settled rather than re-argued:**

> Where identity is uncertain, prefer the failure that **under-counts** over the failure that **fabricates events**.

An under-count loses a number. A fabrication invents a security event — a resolution that never happened — in a product whose success metrics (`PRODUCT_SPEC.md` §10) are noise reduction and explainability. The two are not comparable costs, and this principle decides both this decision and decision 4.

**`start_line`/`end_line` are excluded.** An edit *above* a finding shifts it, so including them would make an untouched vulnerability look new after any refactor — failing M4.2's own criterion in the most ordinary case there is, and making M9.1 report a resolve-plus-reopen that never occurred. The cost is accepted rather than waved away: two matches of one rule in one file collapse into a single `Finding`. Two things bound it. The discriminator that would fix it — a hash of the matched source line — is *unavailable*, not merely unchosen: Semgrep's `extra.lines` is the literal `"requires login"` (G7), which is why that entry's `Blocks-if-unresolved:` now names this. And the loss is given a receipt rather than being paid silently: `FindingSighting.match_count` records how many source elements collapsed into the identity in that scan, which is a signal M5 and M6 will want anyway.

**`installed_version` is excluded.** Bumping a package from one vulnerable version to another vulnerable version fixes nothing, so re-keying would report a remediation that did not happen. When a bump *does* remediate, the tool stops reporting the CVE and the finding stops being sighted — the correct signal, needing no help from the hash. `package` and `file_path` *are* included: the same CVE against two packages, or one package pinned in two manifests, are genuinely different findings.

**`severity`, `native_severity`, `cvss`, `cwe`, `owasp_category` and `title` are excluded**, all for one reason: they are advisory- or ruleset-mutable. Trivy carries `LastModifiedDate` on every vulnerability precisely because advisories change. An NVD rescore must not re-key a finding, and a Semgrep ruleset gaining `metadata.cwe` (G6's fix) must not re-key every SAST finding as a side effect.

**`project_id` is excluded — it is the scope, not the identity.** Two projects with the same vulnerable dependency produce the same hash; uniqueness is `(project_id, dedup_hash)` at the persistence layer. Folding the project into the hash would gain one index column and cost the ability to ask the cross-project question at all.

`dedup_hash` is a **derived property** on `Finding`, not a constructor field, so it cannot drift from the fields it is over and cannot be forged by a caller. M4.3 persists it as a column because the unique index needs one; that column is a materialization of the property, not a second source of truth.

### 4. One `Finding` per (alert, instance) for ZAP

ADR-0018 deferred this here rather than rejecting it, and it is now decided in the affirmative. An alert with an empty `instances` list still yields exactly one `Finding`, located at the site it is nested under — that case is real output and the fallback is not a guess, since the nesting is ZAP's own statement of where the alert applies.

- **Alert-level identity cannot include the URL.** The location would come from `instances[0]`, which the ordering measurement shows is crawl order. Identity would have had to fall back to the site while `Location` displayed a URI that was not part of it — a finding whose location is not part of its identity, which is not a trade-off but a contradiction, and which would also make the displayed URL flip between scans.
- **Per-instance makes resolution granular.** Fixing the missing header on `/` but not on `/robots.txt` becomes one resolved and one still present. At alert level that transition is invisible: ZAP still alerts, the hash is unchanged, and nothing records that half of it was fixed. By decision 3's principle that is a fabrication — an under-report of a half-fixed alert as unchanged is a false claim about security state — not a lost count.
- **Instances are per-URL; sightings are per-scan.** They are orthogonal, so this neither pre-empts nor duplicates decision 1.
- **Alert-level is the more expensive option, not the cheaper one.** Splitting later re-keys every stored ZAP finding, which is G5's own Note: cheap now, expensive after M4.3 persists it.

Measured cost on the real fixture: 4 findings → 11, and evidence bytes 8,523 → 18,148 (**2.13×**). See decision 5 for what that does to ADR-0018's storage estimate and why the character cap does not need revisiting.

### 5. `Evidence` stays 1:1 with the `Finding`, holds the latest payload, and gains `scan_id`

The alternative — evidence per sighting — is the faithful-history option and would store the payload N times, which is the ~2× ADR-0018 flagged and the collapse to ~1× amortized that M4.1 wanted. It is rejected on that cost, with three supports:

- **FR-9 asks for the tool output that produced *this* assessment**, not the best output ever seen. Risks are computed from the current state of the findings, so a Brief citing text the current scan did not produce would be a traceability defect wearing generosity as a disguise.
- **`ScanResult.raw_output` is the floor.** Those rows are keyed `(scan_id, tool)` and are never deleted, so every past scan's full output remains on disk, addressable by scan. The honest caveat: recovering a specific past finding from it means re-parsing with per-tool knowledge — archaeology, not a product feature.
- `Evidence.scan_id` records which scan the retained payload came from, which is what makes the claim above checkable rather than implied. It is also what keeps a scan reference in the model at all after decision 1 removed `Finding.scan_id`.

**Latest-wins is unconditional, and the cost is named rather than implied.** A later scan can observe the same finding with a *poorer* payload — a Trivy entry caught mid-advisory-update with a shorter description — and the richer earlier one is replaced. Preferring the older payload would require deciding which is "richer", which means a size heuristic or field-by-field per-tool comparison: the leak the common schema exists to prevent, deciding by an unexplainable rule what evidence a human sees. The window is also narrow and self-healing, since every re-sighting refreshes again. **Trigger for revisiting: M9.2's before/after evidence view on a resolved Risk**, the first consumer that needs a payload other than the current one; the resolution then is per-sighting retention, which is additive.

One degradation case *shrinks* under decision 4: "a shorter crawl returned fewer instances" no longer produces a poorer payload, because each finding's payload holds exactly one instance — a shorter crawl means the finding is simply not sighted, which is a signal rather than a silent loss.

**For a per-instance finding, `raw_payload` is the alert with `instances` narrowed to that one instance.** ADR-0018 decision 6 is **clarified, not amended**: the principle — a verbatim copy of the source element, never a reference into a replaceable blob — is unchanged, and what changes is what counts as the source element, which for a per-instance finding is the alert-plus-instance pair. Nothing is invented, only projected; the instances are partitioned across the findings, so none is dropped; and the whole alert stays verbatim in `ScanResult.raw_output` regardless. What repeats across siblings is the alert-level metadata (`desc`, `solution`, `reference`, `cweid`) — 1,051–1,738 bytes per finding in the fixture. That is storage duplication, not fidelity loss.

**What this does to ADR-0018's estimate, and why `MAX_RAW_PAYLOAD_CHARS` needs no revisiting.** ZAP's `raw_output` as emitted is 11,155 bytes, so evidence goes from 0.76× to 1.63× of the scan's raw output — ADR-0018's "roughly 2× per scan" becomes roughly 2.6× for ZAP. The amortization argument is untouched and is the part that matters: `raw_output` is stored per *scan* while evidence is stored once per *finding*, so the split raises a one-time constant and leaves the recurring term alone. As for the cap, it is alert-level that had the pathological case: a 1,000-instance alert truncates at 20 KB, silently discarding ~990 instances *and* leaving `raw_payload` as a mid-JSON string that no longer parses. Per-instance, the same alert produces 1,000 findings of ~1.5 KB each and none truncates. The aggregate grows linearly with instance count, which is how Semgrep and Trivy already grow with finding count — the split makes ZAP behave like the other two rather than being the special case.

### 6. `dedup_hash` is a `str` owned by `normalization`; SHA-256, hex, version-prefixed

**ADR-0018's `shared_kernel/` criterion applied, and answered in the negative** — the third time it has been, after `Confidence` and `Location`, which matters because a criterion applied only in the affirmative is not yet a criterion. The criterion takes *closed vocabularies* two or more modules must *compare or order*. A dedup hash is an open-valued string, and the only module that compares one is `normalization`, in the upsert. M5 correlates findings from *different* tools and `source` is a hash input, so two tools can never produce the same hash — correlation has no reason to compare them. M9.1 compares sightings, not hashes. It is a plain `str` rather than a `NewType`, consistent with rule 9's plain-string IDs.

**SHA-256 over a canonical JSON array of the ordered inputs, UTF-8, hex-encoded.** Not a security boundary: the requirement is collision resistance over short structured strings plus reproducibility across processes and releases. JSON rather than a separator-joined string because the values are paths, URLs and parameter names, so no separator is safe by inspection; JSON is unambiguous by construction and encodes `None` as `null`, keeping it distinct from `""` — the same "a field with no source is not an empty value" rule the rest of the schema keeps.

**The stored value is `"v1:<hex>"`, and the version prefix is what makes this a contract rather than an implementation detail.** Changing the algorithm or the input set invalidates every stored value. With the prefix, a v1 value can never silently compare equal to a v2 one; the comparison fails loudly instead of matching the wrong finding. The migration for a bump is **re-normalization from `ScanResult.raw_output`**, which re-derives every finding and every sighting from the original tool output with no lossy back-fill — and which works *only* because those rows are retained per scan. A future retention policy on `ScanResult` would quietly remove that property, which is why it is written down here rather than assumed.

### 7. The dedup scope reaches `normalization` on the handoff row

Findings dedupe **within a project**, so `Finding` carries `project_id` — and normalization cannot currently see one. `get_succeeded_by_scan_id` returns `ScanResult` rows and `normalization_runs` has no `project_id` either.

**`normalization_runs` gains `project_id`, and the port becomes `request(*, id, scan_id, project_id, requested_at)`.** `RunScanUseCase` already holds `scan.project_id`; the method stays primitives-only, so ADR-0017 decision 1's boundary is untouched. The column carries no foreign key, following `scan_id`'s own precedent in that table and ADR-0017's rule that FKs are used within a module while cross-module references go unconstrained.

A `normalization → scanning` read port was the alternative, and the decisive objection is not that it opens a cross-module read one method away from the `Scan.status` invariant — it is that **the sweep cannot use it**: ADR-0017 decision 2 fixes the reconciliation sweep as selecting on `normalization_runs` alone, and a read port cannot serve a `WHERE` clause. It fails for the consumer the whole outbox design exists to serve, and its "no migration" advantage is only deferred.

**This ADR decides that and M4.3 implements it**, which leaves M4.2 shipping three mapper entry points that take a `project_id` — and a `Finding.project_id` field — that no production path yet supplies. (Not the hash function: `compute_dedup_hash` does not take one, by decision 3.) Named rather than passed over, because this milestone has spent three issues rejecting its lookalike: it is acceptable because the mappers are **pure and their tests pass `project_id` directly, so they are executable and verified** — the deferred-*consumer* case ADR-0017 decision 2 permits, not the "code unable to execute" case ADR-016 decision 3 refused. M4.3 carries the column, the add-nullable → backfill → `NOT NULL` migration, the port signature, the `RunScanUseCase` call site and an ADR-0017 amendment as acceptance criteria. `NormalizationRun.__post_init__` and both `CHECK` constraints are unaffected: their invariants are about `status`/`failure_reason` and are orthogonal to scope.

## Consequences

**M9.1 inherits one constraint, and it is the sharpest thing this ADR produces. "Not sighted in the latest scan" only means resolved for the tools that *succeeded* in that scan.** A Trivy failure makes a scan `PARTIAL` and contributes no SCA findings at all; a naive absence check would then mark every dependency finding in the project resolved — silently, with nothing raising, which is the G4 failure shape arriving one milestone later through a different door. The line is already drawn by `get_succeeded_by_scan_id`, which ADR-016 decision 2 makes the pipeline's entry point, and M9.1 must scope its absence check by it rather than by scan membership alone. This is recorded here rather than only as a roadmap bullet because it is a direct consequence of decision 1, and because a bullet gets closed and stops being read. The sighting model makes absence cheap to query, and that is exactly what makes this easy to get wrong.

**M4.3 receives a settled shape and four obligations**: `UNIQUE(project_id, dedup_hash)`; upsert-by-hash with `merge_observation` as the executable spec for what refreshes and what is frozen; the `finding_sightings` table keyed `(finding_id, scan_id)`; and decision 7's column and migration. Hydration must still reconstruct `Severity(...)` (ADR-0018 decision 2).

**M4.4 receives `collapse_by_identity`** — the within-a-scan counterpart to `merge_observation`. The two divide the work over **disjoint field sets** rather than competing, and the reason is structural: every attribute the merge refreshes derives from the rule or the advisory rather than the individual match (Semgrep's severity is per-rule, Trivy's per-advisory, ZAP's per-alert), and a shared `dedup_hash` already pins `source` and `rule_id`. So the fields that can differ inside a collapsing group are exactly the ones the hash excludes for positional reasons, and the representative choice never competes with the merge's precedence. That is *asserted* rather than assumed — a disagreement raises, because it would mean a mapper derived a rule-level attribute from a match-level field. The representative is picked by a total sort key ending in `raw_payload`, so it never depends on the order a tool happened to emit its elements in; "lowest `start_line`" alone would have left Trivy and ZAP groups, where every line field is `None`, falling back to list order — the mistake `instances[0]` is the record of. Both functions also guard the project boundary, not just the merge: grouping on `dedup_hash` alone would span projects if a caller ever mixed them, and a matched pair where only one half checks the scope is a pair that will be relied on for both.

**M5 gets `rule_id`**, which is a correlation signal it did not have: "the same rule fired here and there" was previously only reachable by parsing `title`. Whether it becomes one is M5.1's decision, not this ADR's.

**G9 is opened.** Semgrep's `path` is an absolute per-scan temp path in production, so every Semgrep finding re-keys on every scan and nothing dedupes for one tool of three. It also breaks M5's file-path correlation and would put worker paths in M4.5's responses. It is invisible in CI because the committed fixture's path was redacted to a relative one — the tests exercise the fixed behaviour while production does not have it. The fix is one change in `SemgrepAdapter.run()` and belongs to `scanning`, so it is assigned to M4.4.

**G7's `Blocks-if-unresolved:` is sharpened.** Its M4.2 half said a token would make Semgrep's `fingerprint` usable as an identity input; this ADR declines tool-supplied fingerprints on other grounds, and what the entry should name instead is the discriminator decision 3 actually lacks — a hash of the matched source line, the only thing that would let two matches of one rule in one file stay distinct without putting line numbers into the identity. Same trigger, and the two-sided direction is preserved: the token that would improve identity also arms the rule-12 exposure.

**`ARCHITECTURE.md` §4 and §4.2 change shape.** `Finding` loses `scan_id` and gains `project_id`, `rule_id` and `dedup_hash`; `FindingSighting` is added; `Evidence` gains `scan_id`. The ERD's `SCAN_RESULT ||--o{ FINDING` becomes wrong the moment a `Finding` outlives one scan result, and is replaced by `PROJECT ||--o{ FINDING` plus `FINDING ||--o{ FINDING_SIGHTING` and `SCAN ||--o{ FINDING_SIGHTING`.

**One pre-existing defect is noted and deliberately not fixed here**: `raw_payload[:MAX_RAW_PAYLOAD_CHARS]` truncates into invalid JSON in all three mappers. Decision 4 makes it *less* likely to fire for ZAP rather than more. M4.5 is where a response schema first has to decide what to do with a payload that no longer parses.

## Alternatives considered

**A fresh `Finding` row per scan, deduplicated at query time.** Rejected: it meets no requirement. FR-5 asks for dedup across repeated scans, and M9.1 would have to reconstruct identity in a query from fields nobody declared as identity — which is the same hash, applied later, with no constraint enforcing it.

**One row mutated in place, keeping `scan_id`.** Rejected — it is what G5 rules out. The field would mean "first scan" or "latest scan" depending on which writer touched it last, and neither answers "was this in the latest scan?".

**Full per-scan snapshots: identity on the finding, every attribute on the sighting.** The purest option, and the honest reason for rejecting it is cost, not principle: it stores the payload and every attribute N times, which is the multiplier ADR-0018 already flagged and M4.1 wanted collapsed. Decision 5's per-sighting retention is this option arriving later, additively, when M9.2 gives it a consumer.

**No project scoping: findings keyed by hash alone, the project reached through sightings → scans.** Rejected as a **multi-tenancy defect**, not a cost trade-off. Two projects with the same vulnerable dependency would share a row, so a finding's state — resolved, dismissed — becomes shared across tenants: someone accepting a `urllib3` CVE in their project would accept it in yours. `PRODUCT_SPEC.md` §11.5 requires every risk state change to be logged with an actor, which a shared row cannot express, and §11.2 with FR-1 puts RBAC at the project level. The shared row's `Evidence.raw_payload` would also come from whichever scan wrote it first, carrying another project's file paths and matched code.

**Per-tool hash functions.** Rejected in decision 2. Worth restating why the objection is not merely rule 4: M5's whole purpose is comparing findings across tools, and it cannot do that over keys whose definitions have nothing in common.

**Trivy's own `Fingerprint` as the identity input.** Rejected twice over. It is per-tool by construction — Semgrep's equivalent is the constant `"requires login"` and ZAP has none — so it could never be the single function; and its input set is opaque, so adopting it would mean depending on an unknown, including whether it survives a DB refresh. A tool-supplied fingerprint only becomes interesting if all three tools have one.

**Hashing `title`.** Rejected: it melts a stable identifier together with advisory-mutable prose, so an advisory rewording would re-key the finding. That is what motivated `rule_id`.

**A separate opaque `identity_scope` string filled per tool**, instead of hashing the `Location` fields directly. Rejected: an extra field that duplicates `Location`, invites downstream misuse as a location, and hides the per-field stability judgements that decision 3 exists to make explicit.

**Including `start_line`/`end_line`** so that two matches of one rule in one file stay distinct. Rejected by decision 3's principle: it buys a count and pays with fabricated resolution events on every refactor. `match_count` recovers most of what it buys.

**One `Finding` per ZAP alert**, as M4.1 shipped. Rejected in decision 4.

**Python's built-in `hash()`.** Rejected, and recorded because it is the naive choice: `PYTHONHASHSEED` randomization means the same finding hashes differently after a worker restart, so the table's keys would stop matching for no visible reason. **MD5** — no functional objection at this size, but Verion scans its own repository (`PRODUCT_SPEC.md` §11.6, M10.4) and a weak-hash finding against our own code would cost more to explain than SHA-256 costs to use. **BLAKE2** — no advantage here and less familiar.

**A `dedup_hash` constructor field with a `__post_init__` guard checking it.** Rejected in favour of the property: a guard that verifies a value against the function that should have produced it is a more elaborate way of not letting the caller supply it at all.
