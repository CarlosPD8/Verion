# ADR-0029 — Where the route extractor lives, what its route map is re-derived against, and how a derived location enters the match key

## Status

Accepted — M5.6, commit 1 of 3. Written before the extractor and before the port, so that the
placement, the key-entry shape and the accepted residue are chosen by somebody who is not also
writing the tests that would make them pass. That is ADR-0023's amendment section 3 applied a
third time, after ADR-0028 applied it a second.

**Size:** a ceiling of **24,000 bytes** was declared before writing, on ADR-0027's and ADR-0028's
precedent of declaring one. No `## Amendments` section exists yet, so the decision text is the whole
file. **Which measurement, stated exactly, because the two precedents do not agree and an earlier
draft of this sentence claimed a convention neither of them sets:** `wc -c` on disk, **23,993
bytes**, inside the ceiling — and the LF blob is smaller still, so the conclusion holds either way.
ADR-0027's file carries no CRLF at all, so its stated 19,163 is convention-free; ADR-0028's stated
20,979 is its LF blob at the accepting commit.

## Context

ADR-0023 Decision C defers the SAST↔DAST derivation behind two triggers. **G24** was resolved at
M5.9, and **G27**'s declaration half was decided by ADR-0028 and shipped at M5.5, leaving its
conditioning half here. So what is missing is the derivation itself: mapping a crawled URL path to
the source location that serves it.

M5.6's roadmap block leaves the module OPEN and names what should decide it. Under placement (b) it
says the widening "is a volume and rate-limit question, not a boundary one, and it is the thing to
measure before choosing."

**The measurement was taken and it does not choose.** `verion-demo-target` at
`c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850` holds **one** `.py` file in a six-blob tree, so fetching
every source file through `VcsProviderPort` costs **two** GitHub API calls — one `list_repo_files`,
one `get_file_content` — and no documented rate limit is reachable at any auth mode. The answer,
against the only target this project owns, is identical under either placement and any design. This
ADR says so rather than presenting a two-call measurement as though it discriminated.

Two further facts from the same reconnaissance bound everything below.

**There is no committed FLASK tree in this repository**, and the qualifier is load-bearing — an
earlier draft said "no committed source tree", which is false.
`tests/integration/fixtures/semgrep_target/vulnerable.py` is a committed Python source file
`ast.parse` accepts; it declares no routes, making it a ready-made **miss case** rather than a
counterexample. What is absent is a tree with routes: the two GitHub
fixtures list `src/main.py` and `pages/index.js` in their `tree` and carry neither in their
`contents`, because `relevant_file_paths` filters source out before `get_file_content` is ever
called. So the only real Flask tree is the two-route demo target, reachable by live clone. That
bounds decision 5.

**The re-derivability constraint M5.6's block calls binding is not satisfiable under either
placement.** `Scan` has no commit column; `RepoCheckoutPort.checkout` takes a URL and a token and
no revision; `GitHubAdapter.list_repo_files` requests `/git/trees/HEAD` and `get_file_content`
sends no `ref`. Decision 3 is what this ADR does about that, and it is the decision most easily
deferred by accident.

## Decision

### 1. Placement: `projects/`, and the deciding ground is the boundary

**Decided: the route extractor lives in `projects/`.** The ground is the module boundary
`ARCHITECTURE.md` §3 and `PRODUCT_SPEC.md` §5 already set, and it is stated as a boundary argument
rather than dressed as a cost comparison, because the cost comparison the block asked for came back
undiscriminating.

§3's module table assigns *"Projects, connected repositories, Security Context"* to **Projects**,
and §5 defines Security Context as *"framework, language, DB, **APIs**, auth mechanism, deployment
target, dependencies"*. A route table is the API surface of a tree, derived from that tree, keyed on
its framework. It is the same kind of fact as `language` and `framework`, which `detect_stack`
already derives in `projects/domain/`, from the same fetch, keyed on the same value —
`_PYTHON_FRAMEWORK_SIGNATURES` already carries `flask`. Placement in `correlation/` would need an
ADR arguing a deliberate deviation from §3; this one declines.

**Two supporting grounds, neither of which is a fetch cost.**

**(a) `correlation/` would have to acquire a port to a source tree, and that is the shape the
contracts exist to prevent.** It has no such port, and `cross-module-correlation` forbids
`verion.modules.scanning.adapters` and `verion.modules.projects.adapters`, so it would be a port
`correlation` owns, with its own adapter and factory — the module responsible for *"Grouping related
Findings into candidate Risks"* reading repositories over the network. Nothing mechanical rejects
that, which is exactly why it needs deciding rather than discovering.

**(b) Placement (a) would erode ADR-0023 section (b)'s conformance guarantee.** That section makes
`build_match_key` *"the single place `mypy` compares correlation's description of `Finding` against
the real one"*. A route map fetched and parsed inside `correlation` reaches that site from a second
provenance no port annotation covers, so it stops being the single comparison point while still
compiling. Placement (b) leaves the fetch and the parse behind an annotated port return type.

**What (b) actually costs, since the block's stated cost is known not to be it.** The widening: a
route-map value on `SecurityContext` or a new entity, an ORM column and a migration (rule 8), a
response-schema field if it is ever exposed (rule 10), and a published port for `correlation` —
`security_context_repository.py` exists, so that may extend an existing one. **This ADR does not
decide persistence**; decision 2 says why.

### 2. The extractor is a pure function over source text, and persistence is not decided here

**Decided: the extractor is a pure function in `projects/domain/`**, taking file contents and
returning a route map, with no I/O of its own — `detect_stack`'s shape, which already takes
`dict[str, str]` and returns a frozen result. It is keyed on the framework `detect_stack` reports,
so a non-Flask tree returns an empty map rather than a guess.

Two properties are established rather than assumed. **The parse needs no execution:** `ast.parse`
over the demo target's `app.py` yields `app.route('/')` → `index`, lines 10–11, and
`app.route('/calculate')` → `calculate`, lines 15–31, from decorators at lines 9 and 14; Semgrep's
committed `dangerous-eval` finding reports line 28, inside `calculate`'s span. *(Line numbers into
`verion-demo-target` at `c68caa7` only, on ADR-0027 decision 5's frozen-SHA exemption.)* **And the
file-path side works only because G9 was resolved:** matching a span needs
`Finding.location.file_path` repo-relative, which it is since M4.4 made `SemgrepAdapter` run with
`cwd=target` and pass `.`. Before that, every Semgrep path carried a per-scan `mkdtemp` prefix and
nothing here would have matched.

**Persistence is deferred to commit 3, with a trigger and a reason.** Whether the map is stored or
derived on demand turns on *when* the derived value is computed, which decision 4 settles. The cost
of deferring is named: commit 2 may build the pure function and its tests, and may not add a
migration. Trigger: **commit 3**, which is also where the port lands.

### 3. The third tree: the residue is ACCEPTED, and what a green derived group therefore means

**Decided: option (i) — accept it as a documented residue.** Not (ii), waiting on G25, and not
(iii), taking part of G25 inside this issue.

**The residue, stated exactly.** Nothing can supply a revision. `Scan` carries
`id, project_id, status, triggered_by, started_at, finished_at, failure_reason` and no commit;
`RepoCheckoutPort.checkout` accepts no revision and `GitRepoCheckout` runs `git clone --depth 1`
with no branch and no revision into a `mkdtemp` that does not survive the scan;
`GitHubAdapter.list_repo_files` requests `/git/trees/HEAD` and `get_file_content` sends no `ref`.
So a route map is derived from **the default-branch tip at derivation time** — a third tree,
distinct in principle from the tree Semgrep read and from whatever the URL was serving.

**What a derived group therefore means, in ADR-0028 decision 2's own formulation one axis over.**
That decision says the declaration **voids on reconfiguration and never on drift**. The same shape
holds on the tree axis: **the route map is re-derived at the tip and never at the observed
revision.** A green derived group means *this route path exists in the tip now and a finding's line
falls inside its span there*, never *the tree Semgrep scanned defined this route*. A route renamed
after the scan yields no group where one belongs; a route added after it yields a group for a
finding that was never there. Both are silent and nothing measures the distance — G47's closing
sentence on a second axis, which is why this seeds its own entry rather than folding into G47.

**Why not (ii), waiting on G25.** G25 is genuinely the fix, so this is a real option and it is
refused for reasons of scope rather than of correctness. Waiting means M5.6 does not close the
conditioning half of **G27** inside M5, which puts `PRODUCT_SPEC.md` §10's demonstration behind an
entry whose own trigger is **M9.1** — a milestone away. And the wait would not be total: G25 gives
the *tree* side a revision, while `VcsProviderPort` would still need a `ref` parameter on two
methods, which G25's four-item scope does not include. So (ii) trades a documented residue for a
milestone's delay and still leaves work here.

**Why not (iii), taking part of G25.** This needs an argument, and the argument goes the other way.
G25's `Deferral rationale:` prices the change at four things — `Scan` gains a field, the migration,
`RepoCheckoutPort.checkout` returns or accepts a resolved revision, `TriggerScanUseCase` decides
whether a caller may pin — and its trigger is M9.1 precisely because M9.1 is the first consumer that
would define the diffing semantics. Settling those inside the issue that wants a route map would
answer M9.1's question for an unrelated reason. ADR-0028's Consequences already records that **M5.6
grows**; a schema change on top of an ADR, an extractor, a port, a factory and a gate is that growth.

**What this residue does NOT do, stated because it is the natural misreading.** It does **not**
prevent M5.6 closing G27's conditioning half. That criterion asks whether a derived group is
withheld when the declaration is absent or out of force — a question about the declaration, not the
revision, which commit 3's gate answers whatever tree the map came from. **Three unversioned things,
and folding any two loses one:** **G25** is *which tree the scanner read*; **G47** is *what the URL
is actually serving*; **this** is *which tree the route map was derived from*. → **G52**.

### 4. The key-entry shape: the stated preference does not work, and what replaces it

ADR-0023's amendment section 4 states a preference while excluding `source`: *"Without it, M5.6 adds
a derived location field and the key admits it — additive, the direction section (b) prefers."*
M5.6's block never cites it, so the shape is **under-owned rather than unowned**, and this ADR
engages the preference instead of deciding around it.

**The preference does not work as stated, and this is a measurement rather than a reading.**
`matches` is `left == right` over the whole frozen dataclass, after a `has_signal` guard. Run
against a four-field key with the same guard, a Semgrep key and a ZAP key carrying an **equal**
derived location:

```
semgrep key: Key4(project_id='p1', package=None, url=None,  source_location='app.py:calculate')
zap key    : Key4(project_id='p1', package=None, url='http://…/calculate?expr=2*3', source_location='app.py:calculate')
has_signal : True True
matches()  : False
differing fields: ['url']
```

**The field is admitted by the type and produces no match.** Equality is on *every* field, so the
keys differ on `url` — populated for ZAP by construction, `None` for Semgrep by construction — and
the derived field never gets to matter. Section 4's "the key admits it" is true, and is not the
claim "the pair correlates".

**Three shapes, priced.**

**(1) A fourth field — the stated preference. Inert without a companion amendment.** To make it
match, one of two things must also change: section 2's equality rule weakens from *equality on every
field*, which that section rejected as non-transitive; or the mappers stop populating `url` for ZAP
findings with a derived route, destroying ZAP's intra-tool grouping and changing what `Location.url`
means. It also cannot satisfy `test_match_key.py`'s conformance test at all — `_FIELD_SOURCES`
requires a declaring *type* per field and no `Finding` or `Location` field a derived route comes off
exists — the partition test fails too, and `_group_order`'s hand-enumerated tuple would ignore it.
Not merely insufficient: the most expensive of the three.

**(2) A second matching path beside `group_by_match_key`.** It breaks the property every shipped
assertion rests on — each finding in exactly one group — and `MatchGroup.key` is a `MatchKey`, so
the second path must synthesize one anyway. Rejected.

**(3) DECIDED — the derived route path goes into the EXISTING `url` signal, and ZAP is keyed on
path.** Both sides become `(project_id, None, "/calculate")` and plain equality works. Verified
against the real `matches` and the real `group_by_match_key`, unmodified:

```
semgrep key: MatchKey(project_id='p1', package=None, url='/calculate')
zap key    : MatchKey(project_id='p1', package=None, url='/calculate')
matches()  : True
group url='/'          members=('zap-2',)
group url='/calculate' members=('semgrep-1', 'zap-1')
```

No field-list change, so **no amendment to ADR-0023's frozen field list is owed**: three fields,
partition, `has_signal`, `_group_order` and the conformance test all unchanged. That is the whole of
its advantage.

**But ADR-0023 is not silent on keying `url` by path, and "no amendment is owed" without engaging
that would overstate this.** Its 2026-08-26 amendment **section 6** decided the same question the
other way — *"**The key is not changed to a path here.** No measurement of a path-keyed *grouping*
exists … and nothing in this repo normalizes URLs"* — and deferred it with a named exit:
*"Re-entry trigger: **M5.4**, seeded as **G31**."* So decision 4 is **that trigger firing as
designed, not a reversal**, which is why the frozen list survives untouched. Section 6's stated
ground is now **false in both clauses** — M5.9's capture is the missing measurement, and this
decision is what makes the repository normalize a URL — and that ground lives in **two** places:
G31's `Deferral rationale:`, annotated here, and section 6 itself, inside an accepted ADR and **not**
corrected here. The second lands on **G46**, whose subject is exactly that.

**Run over the committed corpora through the real mappers**, with the derivation applied at the
`build_match_key` call site:

| corpus | findings | signal groups | no-signal singletons | cross-tool group |
|---|---|---|---|---|
| passive, all three tools | 34 | 7 | 0 (was 1) | `/calculate`, n=5, `{semgrep, zap}` |
| Semgrep + M5.9's active capture | 17 | 4 (was 5) | 0 | `/calculate`, n=7, `{semgrep, zap}` |

The passive group **count** is unchanged at 7; what changes is Semgrep's singleton joining
`/calculate`. That is the first cross-tool group this project has measured rather than predicted.

**Its price, stated at full strength because it is this project's own tracked failure class.**
`build_match_key` keeps type-checking exactly as before — `str | None` into `str | None` — while the
*provenance* changes: a Semgrep finding's `url` would carry a route path that did not come off
`Location.url`. Section (b)'s guarantee survives in letter and narrows in substance, and **ADR-0023
already names this class and declares it undetectable** — section (c)'s *"Semantic changes behind an
unchanged signature … is invisible to every check here."* A known hole entered deliberately, at the
one site built to prevent the other kind. → **G53**.

**Three constraints, decided here.**

- **The derivation happens at the `build_match_key` call site in `correlation/application/`, never
  in a mapper.** `Location.url` keeps its meaning, `dedup_hash` is untouched (ADR-0019 decision 3),
  and the narrowing is confined to the one site that already carries section (c)'s caveat. A mapper
  doing it would change a persisted field's meaning for every consumer.
- **Dropping the host is safe only while a project has one target.** `ScannerConfig` carries a
  single `zap_target_url`, so every ZAP URL in a project shares a host; keying on path alone is
  therefore lossless *today* and would silently collide if a second target were ever added.
- **The builder gains `file_path` and `start_line` as scalars** rather than the use case computing
  the value first, so all five source values still meet their annotations at the one site. Residue:
  the conformance test derives from the **key's** fields, so the two new parameters get `mypy` and no
  conformance assertion. In G53 rather than left to be found.

**What shape 3 does not buy.** A Semgrep finding outside any route span stays a no-signal singleton.
And two Semgrep findings inside one span co-group with each other and with every ZAP alert at that
path — the over-grouping ADR-0023 amendment section 5 raised against `file_path`, one granularity
finer. **This corpus cannot exhibit it**, Semgrep contributing one finding, which is the same bound
that amendment drew for its own structural half.

### 5. What a green M5.6 does not prove

ADR-0027 decision 5's pattern, so this arrives as a decision rather than as a discovery, and bounded
by the fact that the only real Flask tree available is a two-route app.

- **It proves the mechanism on one shape and no more:** that a literal path in an `@app.route`
  decorator maps to a function span, that a reported line inside that span resolves to that route,
  and that the parse needs no execution.
- **Untested by construction, because the tree cannot express them:** blueprints, `add_url_rule`,
  variable path converters, methods, multiple decorators on one view, class-based views, routes
  spread across modules, and any path that is not a decorator literal.
- **No miss case from the real tree.** It has one source finding and it hits, so a green run does not
  show that a finding outside every span stays a singleton. `semgrep_target/vulnerable.py` is a
  committed route-free Python file and covers exactly that shape, so the miss case is a fixture
  obligation that is already half-supplied rather than one needing a new tree.
- **The span boundary is undetermined.** `ast` reports `calculate` at `lineno=15`, excluding its
  decorator at 14, and line 28 is inside either reading. Decorator-inclusive and -exclusive spans are
  indistinguishable here, so whichever the extractor picks is a choice no test checks.
- **It says nothing about the residue in decision 3.** The demo target's tip *is* its scanned tree,
  so the one configuration where the residue is invisible is the only one CI exercises — the same
  accident ADR-0023's 2026-08-25 amendment records for the probe and G27, *"the one configuration in
  which the coupling holds by construction"*.

## Consequences

**M5.6's module is `projects`, and the block's `Module: OPEN` is answered.** Its placement bullets
are annotated rather than struck: both stay accurate, and what changed is that the cost the block
nominated as deciding turned out not to. ADR-0027 decision 4's *"not left OPEN the way M5.6's is"*
becomes dated by that, and takes a dated amendment in this commit.

**No amendment to ADR-0023's frozen field list is owed, and that is narrower than "no amendment".**
Decision 4 chose the one shape of three leaving the field list, the matching rule, the partition and
the conformance test untouched — deliberate, since M5.8's criterion (b) makes a departure a dated
`## Amendments` entry and the cheapest way to honour that is not to depart. Section 4's preference
is **engaged and not followed**; section 6's deferral is **re-entered by its own named trigger**,
not reversed. What *is* owed, and is not paid here, is a dated amendment for section 6's now-false
ground — added to **G46**'s enumeration, whose subject that already is.

**G31's first out becomes available and is not taken here.** Shape 3 re-keys ZAP on path, that
entry's *"re-keys on path with a measurement behind it"*, and M5.9's capture is the measurement — 16
ZAP findings, 5 groups on full URL, 4 on path, `6-5` and `90036` split. **This commit re-keys
nothing, so G31 stays open**, discharged by commit 3. M5.6's block now cites it, closing a citation
that ran one way.

**Two register entries are seeded here**, per `CLAUDE.md`'s rule that an ADR deferring something
with a trigger seeds the entry carrying the escalation check: **G52** (the map is re-derived at the
tip, a third tree, and nothing observes the distance) and **G53** (a Semgrep finding's `url` carries
a value that did not come off `Location.url`, so section (b)'s provenance guarantee narrows while
`mypy` stays green). **G46** gains a third site rather than a fourth entry.

**G48 is not discharged and is not fired.** Its trigger is *"M5.6 landing … or M5.6 being descoped,
deferred or split"*, and one issue in three commits is none of those; the port ships at commit 3. A
note says so at the entry, so a reader arriving between commits need not infer it.

**Commit 2 is bounded by this ADR and can start:** the pure extractor in `projects/domain/`, keyed
on framework, with fixture tests for the miss case the demo target cannot supply, no migration.

## Alternatives considered

**Placement in `correlation/`, argued on the fetch.** This is what M5.6's block set up, and it
collapses once the fetch is measured at two calls. Its deciding cost is the one the block already
identified without the fetch: `correlation` has no port to a source tree, so the extractor would
re-fetch at correlation time and parse a tree nobody recorded. Decision 3 shows that hazard is not
removed by placement (b) either — but under (a) it would sit inside the module whose output is the
thing being trusted, with nothing nearby to make it visible.

**`shared_kernel` promotion.** Not re-litigated, on M5.6's block's own instruction: ADR-0023
alternative 4 rejected it on ADR-0018's criterion, and alternative 6 records that it returns at M6.

**Raw path-prefix join instead of an extractor.** M5.6's block already prices this and measures it
empty, and nothing here changes that: Flask's decorator routing does not map URL paths onto file
paths, so it reaches the same empty relation M5.1 measured for field equality, by another route.

**Deferring decision 4 to commit 3.** Rejected, and not free. The key-entry shape constrains the
extractor's **output type**: shape 1 wants an opaque location token, shape 3 a route path string a
URL parse can equal. Deferring would have commit 2 build a return type commit 3 then changes, or
stall commit 2 outright. Deciding it here costs one section and unblocks the next commit.
