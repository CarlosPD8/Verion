# ADR-0023 — How `correlation` names the type it correlates: a match key it owns

## Status

Accepted — 2026-08-24 (M5.1)

## Context

M5.1's roadmap entry said `CorrelateFindingsUseCase` would be "implemented as pure domain
logic, unit tested with constructed Finding fixtures". As written that is not buildable, and
the M4→M5 boundary review escalated it to acceptance criteria for this ADR rather than
leaving it as prose.

Three constraints combine, and **all three were measured this session rather than reasoned
about.** That distinction is the reason this section exists: `correlation/` has been nine
empty `__init__.py` files since **M0.1** scaffolded the module tree, and its two contracts
have existed since M0.2 without ever rejecting anything, because there has never been any
code in that module for them to reject. A constraint nobody has exercised is a belief, not a fact — and
this repo has already had one such belief falsified, when "`domain/` may not import a port"
turned out to be false for the **three** `domain/` modules that import `shared_kernel.ports`
(`normalization`'s three mappers). Seven `domain/` modules import `shared_kernel` at all, but
four of those take only enums, and the claim being falsified was about *ports*. Each probe
below injected a real violation, recorded the tool's verbatim output, and was reverted,
following the M0.2 / ADR-010 precedent.

1. **`layers-correlation` rejects `correlation/domain/` → `correlation/ports/`.** Measured
   twice, because a symbol import and a package import are different graph edges and might
   have been treated differently. They are not:

   ```
   verion.modules.correlation.domain is not allowed to import
   verion.modules.correlation.ports:

   - verion.modules.correlation.domain._probe ->
   verion.modules.correlation.ports._probe_port (l.1)
   ```

   and, for `from verion.modules.correlation import ports`, the same failure naming the
   package rather than the submodule. In both runs **only that one contract broke** — 16
   kept, 1 broken — so the rejection is attributable to the layers contract alone.

2. **`cross-module-correlation` rejects a plain import of `normalization.domain.finding`:**

   ```
   verion.modules.correlation is not allowed to import
   verion.modules.normalization.domain:

   -   verion.modules.correlation.domain._probe ->
   verion.modules.normalization.domain.finding (l.1)
   ```

   `Finding` lives in `normalization/domain/finding.py`, so this is the constraint that
   actually binds.

3. **`mypy --strict` requires every parameter annotated**, which is what makes the two above
   binding rather than avoidable. Without it a `correlation/domain/` function could take an
   unannotated `findings` and the question would not arise.

Both probes were the **first-ever exercise** of their contract. That is worth recording for a
reason beyond bookkeeping: `lint-imports` reports `17 kept, 0 broken` on a tree where **8 of
the 17 contracts have a *source* module containing zero non-`__init__` Python files** — the
four `layers-*` and four `cross-module-*` contracts for `correlation`, `risk_engine`, `brief`
and `history`. (Their `forbidden_modules` lists do name modules that have code; it is the
source side that is empty, and the source side is what a contract can catch a violation *in*.)
The green number is real for the four modules that have code and vacuous for the four that do
not, and nothing in the output distinguishes them.

## Decision

**`correlation` matches on a match key it owns.** Three placements, and the third is the
point:

- **The key type is a frozen dataclass in `correlation/domain/`.** It is correlation's own
  domain type, so naming it is legal — no contract is involved.
- **It is built in `correlation/application/`**, from `Finding` values arriving through
  `normalization`'s `FindingRepositoryPort`. Importing another module's *ports* is legal
  (`cross-module-correlation` forbids only `.domain` and `.adapters`), and
  `application` → `domain` is the direction `layers-correlation` permits.
- **Matching logic stays in `correlation/domain/` and takes the key, never `Finding`.**

That third placement is what makes this worth choosing over the alternatives: it **restores
the pure-domain matching function** M5.1 asked for and the roadmap concluded was impossible.
The impossibility was never about matching logic living in `domain/`; it was about `domain/`
naming *another module's* type. A key correlation owns has neither problem.

The key carries only the fields correlation matches on — not a mirror of `Finding`.

### (a) Why this was not among the five options the roadmap listed

It is **option 3 — the anti-corruption type — narrowed.** The roadmap described option 3 as
"an anti-corruption type `correlation` owns, with a mapping at its boundary", and every
reading of it assumed a mirror of `Finding`. Narrowing it from a mirror to a match key is a
materially different cost, not a rewording: **the drift surface is three or four fields
rather than the whole entity**, and `Finding` has twelve fields, two of which (`location`,
`evidence`) are themselves structures with their own.
An anti-corruption mirror has to be re-synchronised whenever any of them changes; a match key
has to be re-synchronised only when a field it actually matches on changes.

### (b) Where the conformance check lives, and the constraint it imposes

The construction site in `application/` is the **single place `mypy` compares correlation's
description of `Finding` against the real one**. A renamed or removed field fails the build
there, at that one site, with no test needed.

**That guarantee is bounded, and the bound is ADR-015's.** That ADR records that conformance
"is only verified where an adapter meets a port-annotated site … An adapter constructed into
an `Any` is still unchecked". The same applies here one size down: the check holds only while
the construction site's `Finding` value has a real type rather than `Any` — which it does,
because it comes back from `FindingRepositoryPort`'s return annotation.

**And it imposes a constraint on whoever writes the key: its field annotations must replicate
`Finding`'s field-for-field, without narrowing.** If the key declares `cwe: str` where
`Finding` has `str | None`, or `str` where a future `Finding` has `list[str]`, the
construction site silently stops being a total check and becomes a partial one, with nothing
saying so. This is ADR-015's `Any` caveat one size down again — conformance is verified only
where the two descriptions actually meet, and a narrowed annotation moves the meeting point
without moving the green build.

So the equivalence is **pinned by a test in ADR-0020's shape**, not left to convention. That
ADR faced the same problem — a pure domain function and one SQL statement that had to stay
equal — and answered it with three layers, of which the load-bearing one derives the expected
set from the domain's own declarations rather than from a hand-written list. The same applies:
**derive the key's expected annotations from `Finding`'s own declarations** (`dataclasses.fields`,
as ADR-0020 decision 4 already does for the refresh set). A hand-written list would be a third
copy, free to drift from both sides, and would assert that correlation agrees with itself.

### (c) What this does not detect

Said plainly, because a check described as total and then found partial is worse than one
described accurately:

- **Added fields.** A new `Finding` field the key does not carry changes nothing at the
  construction site. That is usually correct — the key is deliberately a subset — but it means
  a new field that *should* be a matching signal arrives silently.
- **Semantic changes behind an unchanged signature.** `cwe` changing from "the CWE of the
  vulnerability" to "the CWE of the rule that found it" is invisible to every check here.
- **The no-narrowing rule in (b) is a constraint on whoever writes the key, not a property
  this placement confers for free.** The placement creates the meeting point; it does not
  guarantee the annotations meeting there are faithful. That is what the test is for.

## Consequences

**Every module that reads another module's entity inherits this decision.** `risk_engine`
reads `Finding` and correlation's `Risk`; `brief` reads both plus scoring output; `history`
reads across all of them. **M6, M7 and M8 each hit exactly the wall M5.1 hit**, and each has
the same seven alternatives this ADR weighed. The roadmap's M5.1 entry already says "whichever is
chosen binds M6, M7 and M8 too, since every one of them reads another module's entity"; this
is that instruction discharged.

**What is deliberately not decided here: which fields the match key carries.** No captured
data exists on which that choice could be validated — the three committed scanner fixtures
were captured against three unrelated targets (a `.py` file, a `requirements.txt`, and a
local HTTP server), so no measurement over them can distinguish "these tools do not correlate"
from "these captures describe different systems". Choosing fields against that corpus would be
choosing against the generator rather than against reality, which is the failure G19 exists to
name.

That deferral **seeds `G23` in this same commit**, per CLAUDE.md's rule that an ADR deferring
something with a trigger condition seeds a register entry rather than leaving the trigger in a
Consequences section nobody re-reads at a boundary. The trigger is concrete: **a captured
corpus of all three tools against one artifact.**

What *is* settled about the signals, and survives any corpus, is recorded in **G6**'s note:
`rule_id` is each tool's own namespaced identifier, so it can never match cross-tool; and ZAP
shares no populated `Location` field with either other tool, so no location signal can reach
DAST. What is **not** settled — and the ADR is explicit that it is not — is Semgrep↔Trivy,
which do share `file_path`, and CWE. Both need the corpus G23 names.

*(**Superseded by the Amendments below, 2026-08-25.** G23's corpus exists, both open questions are
measured empty, and this section's deferral — "No captured data exists on which that choice could
be validated" — is discharged as to what is out.)*

## Amendments

- **2026-08-25 (M5.1): the Consequences deferral — "which fields the match key carries" — is
  discharged as to what is *out*. What the key *carries* is still not fixed, and that is
  deliberate.** G23's trigger fired: the three committed fixtures now come from one `Scan` over
  one target, so a measurement across them measures a *signal* rather than a coincidence of three
  captures. This amendment records what that measurement settled. **It settles three negatives and
  no positive, and the absence of a positive is the result rather than an omission.**

  **The finding, stated in the form the corpus admits.**

  **The signal set is the one this project already nominated**, which is what makes it citable
  rather than invented here:

  - **`cwe` and each of `Location`'s eight fields** — ADR-0018's Consequences names exactly these:
    "M5 gets a canonical CWE it can compare across tools, and a `Location` whose fields it can
    compare without knowing which tool produced either side." Decision 2 adds the *fields, not the
    type* qualification: "`Location` out — M5 will compare locations, but it compares fields."
  - **`owasp_category` and `cvss`** — ADR-0018's Context puts them in the same sentence as `cwe`:
    "The same question arrives again for `cwe`, `owasp_category` and `cvss`."
  - **`rule_id`** — nominated by `ROADMAP.md` M5.1, which then corrected itself: it is each tool's
    own namespaced identifier and can only group *within* a tool. Measured here anyway, because a
    nominee withdrawn on reasoning is worth confirming on data.

  **Twelve signals across three tool pairs, thirty-six cells, and no cell is non-zero.**

  ***(Scoped 2026-08-25: read "no cell is non-zero" as a measurement over **the committed corpus**,
  which is a passive-only ZAP capture. It is accurate about that corpus and this amendment names it
  throughout. Under an **active** scan plan one cell becomes non-zero — `cwe` on Trivy↔ZAP, via
  `CWE-22` — which Decision B below now rests on rather than contradicting, because the one pair it
  produces is spurious. Flagged here rather than left for a reader to hit as an apparent
  self-contradiction two screens down. The tier breakdown that follows is unaffected: the
  twenty-nine construction-tier cells are properties of the mappers, which no scan plan changes,
  and the three vocabulary-tier cells are properties of the identifier namespaces.)***

  **`severity` is deliberately not in that set, and it must be named because it is measured
  NON-EMPTY** — Semgrep↔Trivy intersect on `high`, Trivy↔ZAP on `low` and `medium` (Semgrep↔ZAP is
  empty). A reader who tries it will find that, so the reason has to be on the record: **ADR-0018
  decision 2 states `Severity`'s M5 role as "M5 ranks correlated findings"** — it orders what
  correlation has already grouped. Using it to *decide* the grouping inverts that. `native_severity`,
  `title` and `source` are likewise unnominated; all three happen to measure empty on all three
  pairs, and `source` is empty by definition, equality on it meaning "same tool". `id` is a
  surrogate, `project_id` is the correlation scope, `evidence` is provenance ADR-0018 decision 6
  keeps outside the common schema, and `location` is measured through its eight fields.

  **Why the set is cited rather than derived**, since the obvious derivation does not work: a rule
  of the form *"a signal is a field a tool may leave unsupplied"* cannot be read off `Finding`'s
  annotations, because **partiality lives in the mappers, not in the dataclass.**
  `native_severity or "(absent)"` and `title or "(unnamed semgrep rule)"` are the same
  construction as `rule_id or "(unidentified)"` — ADR-0019 decision 2 says so outright, calling
  that fallback "in the same idiom `native_severity` uses for `"(absent)"`". Any rule keyed on
  `X | None` therefore separates fields that the code treats identically.

  **The sweep was previously reported over ten signals and thirty cells**, omitting
  `owasp_category` and `cvss`. Both were then measured: neither is populated by more than one
  tool, so both are construction-tier on all three pairs and the conclusion did not move — but the
  counts did, and the earlier figure should not be quoted.

  The thirty-six cells do not have the same standing, and collapsing them into one claim would
  repeat the sample-to-general step this project has caught repeatedly.

  - **Twenty-nine are empty by mapper construction**, which is a property of the code and holds
    for any target. Each mapper's `Location(...)` construction names its own subset:
    `mappers/semgrep.py` names `file_path`, `start_line` and `end_line`; `mappers/trivy.py` names
    `file_path`, `package` and `installed_version`; `mappers/zap.py` names `url`, `http_method`
    and `parameter`. **Those subsets are not disjoint — Semgrep's and Trivy's both contain
    `file_path`, which is exactly why that cell is corpus-dependent rather than structural** and is
    the one location signal that had a real question attached to it. Outside the fields each mapper
    names, everything defaults to `None` and no code path can change it; `owasp_category` reaches
    only Semgrep and `cvss` only Trivy, so both are construction-tier on every pair. Two tools that
    never populate one field cannot be equal on it, whatever they scanned.
  - **Two are empty by ruleset configuration, not by construction — `cwe` on Semgrep↔Trivy and on
    Semgrep↔ZAP — and separating them from the twenty-nine above is not pedantry.** Semgrep
    populates no CWE today, so those two cells read as structural from the data alone. They are
    not: `mappers/semgrep.py` reads `canonical_cwe(_first(metadata.get("cwe")))` unconditionally,
    and the committed `semgrep_synthetic_edges.json` exercises exactly that path, yielding
    `CWE-95` and `CWE-16`. The cells are empty because the pinned ruleset declares no `metadata:`
    (**G6**) — a production configuration edit away from being non-empty. Folding them into the
    "holds for any target" tier would contradict Decision B below, which counts G6's resolution as
    removing one of its grounds; a cell cannot be both structural-for-any-target and removable by
    editing `rulesets/default.yml`.
  - **Three are empty by disjoint identifier vocabularies** — `rule_id`, on all three pairs. Both
    sides populate it, so this is not structural by *population*; it is structural by *namespace*:
    `dangerous-eval` against `CVE-2019-11324` against `10038-1`. Already recorded in **G6**'s note
    as surviving any corpus. Confirmed here on thirty-four findings rather than the pre-G23
    corpus's twenty-four, and adding nothing that note did not already carry.
  - **Two were corpus-dependent, and are the only cells this measurement actually settles.** `cwe`
    on Trivy↔ZAP: fourteen distinct values against four, disjoint, with Semgrep contributing none
    at all (**G6**). `file_path` on Semgrep↔Trivy: `app.py` against `requirements.txt`. The second
    is sharper than the semantic argument G6 offered for it — Semgrep's `paths.scanned` is
    `['app.py']`, so it never read the manifest, and Trivy's `Target` is the manifest and never a
    source file. The two vocabularies do not overlap on this repository even though the field is
    shared.

  **No replacement field was chosen, because none exists.** This amendment must not be read as
  "correlation matches on X instead". The measured result is that field equality **over the twelve
  signals above** produces an **empty relation** cross-tool — not over every field on `Finding`,
  which `severity` would falsify — and that thirty-two of the thirty-six cells
  — twenty-nine by construction and three by vocabulary — are empty for reasons no corpus can
  change. Of the remaining four, two turn on a ruleset this project controls and two were the
  genuinely open questions.

  - **Decision A — the ZAP `Server` banner does not populate `Location.package` or
    `Location.installed_version`.** All thirty-six cells are empty, so **the only cross-tool
    correspondence this corpus yields that is about a shared subject rather than a shared
    magnitude comes from outside the signal set entirely** — not from a field read, but from a
    string inside `Evidence.raw_payload`. *(Scoped 2026-08-25 on the same terms as the note above:
    "all thirty-six cells are empty" is a
    measurement over the **committed passive-only corpus**. Under an active plan the `cwe` cell on
    Trivy↔ZAP is non-empty. **Decision A is unaffected either way** — its subject is the `Server`
    banner and `Location.package`, which no scan plan populates — and the "only correspondence this
    corpus yields" clause survives for the corpus it names.)* ZAP's `10036-2` alert carries `evidence` of `"Werkzeug/2.3.8
    Python/3.11.5"` on each of its instances; parsed as `(name, version)` and compared against
    Trivy's `(package, installed_version)`, `Werkzeug/2.3.8` matches **six** of Trivy's twenty
    findings and `Python/3.11.5` matches none. Lifting that into `Location` inside
    `mappers/zap.py` would convert two of the twenty-nine construction-tier zeros — `package` and
    `installed_version` on Trivy↔ZAP — into live signals. It is refused on **two independent
    arguments, both of which are required**:
    - **ADR-0018 decision 4** — *"A field with no source is `None`, never `""` and never a
      guess"* — governs which tool is a source for which field, and works that out as a
      per-field-per-tool table. Adding ZAP as a source for `package` is precisely that operation,
      so this is that decision's to take and not a local mapper convenience. Note the objection is
      *not* that the banner is invented: it is verbatim tool output, and passes that decision's
      "never a guess" clause as literally written. **Nor is it that an existing row forbids it** —
      that table has three rows, `cwe`, `owasp_category` and `cvss`, and no `Location` field has
      ever appeared in it. What the proposal requires is *adding a row*, which is a decision at
      ADR-0018's level rather than a mapper's, and this amendment is where it is declined.
    - **`Location`'s own docstring**, which says the flat shape exists so that a downstream reader
      can ask *"do these two findings share a `file_path`?"* — verbatim — *"without knowing, or
      caring, which tools they came from. That question is the whole point of correlation."* If
      `package` means "pinned in this manifest" from Trivy and "the server said so" from ZAP, then
      comparing the two **requires** knowing which tool produced each side, which destroys the
      property the flat shape exists to provide. The design would defeat itself at the level of
      its own stated rationale.

    **The asymmetry that decides it, since `file_path` already carries two meanings and that
    objection has to be answered rather than ignored.** Trivy's `file_path` is a manifest path and
    Semgrep's a source path — two meanings, measured above. But both refer to **the scanned
    tree**, so the ambiguity produces an *empty intersection*: an **under-match**. The banner's
    two referents are **the running process** and **the scanned tree** — different systems — so
    its ambiguity produces a **false match** whenever a version number coincides. ADR-0019
    decision 3 draws exactly this line: *"Where identity is uncertain, prefer the failure that
    **under-counts** over the failure that **fabricates events**."* The ambiguity `Location`
    already carries falls on the safe side of that principle; the proposed one falls on the other.

    **And a perverse property worth recording, because it is what closes the case rather than
    merely supporting it.** Alert `10036-2` **is** "Server Leaks Version Information via `Server`
    HTTP Response Header Field", and removing or blanking that header is its remediation. So the
    correlation signal exists **only while the target still carries the vulnerability the signal
    is derived from**, and evaporates the moment the team acts on the scanner's own advice. A
    signal anti-correlated with the target's security posture gives least coverage exactly where a
    deployment is well configured.

    **Nothing is lost by refusing it.** The banner is already in `Evidence.raw_payload` verbatim,
    which is where per-tool structure the common schema does not model is supposed to live. If it
    ever needs structure, its home is **Security Context** — FR-3 asks for "deployment signals",
    and a live server's self-reported stack is a fact about the deployment rather than the
    location of a finding — not `Location`, where it would be compared field-to-field against a
    manifest.

  - **Decision B — `cwe` is out of the match key. G6 is the re-entry trigger.**

    ***(Grounds REWRITTEN 2026-08-25 by the active-scan probe, not annotated. Two of the four
    original grounds are falsified, and they are struck rather than left listed with a marker
    beside them — a falsified ground that stays on the page is a ground somebody will cite. What
    they said, once, for the record: **(1)** "the intersection is empty on all three pairs" and
    **(3)** "**G24** bounds ZAP's reachable CWE vocabulary to passive response-configuration
    weaknesses permanently and independently of any corpus". Both were measured against a
    passive-only scan plan and both fail when the plan changes. The decision does not: it is
    re-founded below on a stronger ground the original list did not contain. This is the treatment
    this project gives a claim that turns out **wrong** rather than incomplete.)***

    **Three grounds — two measured and one the absence of a measurement**, which is a real
    distinction and not a hedge:

    **(1) The only cross-tool CWE pair ever measured is one side hallucinating** *(measured)*.
    Under an active scan the Trivy↔ZAP intersection is **not** empty: `CWE-22` appears on both
    sides. It buys nothing, and what it buys is the point. The pair is **ZAP `6-5` "Path
    Traversal", riskcode 3 but confidence 1**, at `/calculate?expr=calculate` — the attack payload
    is the literal string `calculate`, the URL's own last path segment — against an application
    that performs **no file access on user-controlled input**: the only sink reached from the query
    string is `eval`. It is a false positive with nothing behind it. The other side is **Trivy `CVE-2024-49766`**, whose fixture `Title` reads in full
    `werkzeug: python-werkzeug: Werkzeug safe_join not safe on Windows`, MEDIUM — a real CVE about
    a path-joining helper inside the framework. So the two
    findings share a CWE and describe unrelated things, one of which does not exist. **This is a
    stronger ground than the empty intersection it replaces**: an empty cell says the signal
    produced nothing here and might produce something elsewhere, while a populated cell whose only
    occupant is spurious says what the signal produces when it *does* fire. It is ADR-0019
    decision 3's *"prefer the failure that under-counts over the failure that fabricates events"*
    arriving as data rather than as argument, and it is the same distinction Decision A draws
    against the banner — an under-match versus a false match.

    **(2) Semgrep contributes zero values at all, G6** *(measured)*. Unchanged.

    **(3) G26 leaves it unverified whether the surviving value is even stable across
    vulnerability-database updates** — *unmeasured by construction*, since it is the absence of a
    reading rather than a reading. G26's own `Deferral rationale:` calls that measurement
    "measurable and cheap" and states its exit condition, so this is the ground that can be retired
    by somebody doing an afternoon's work.

    **What resolving G6 would and would not remove, restated against the new list.** Ground (2) is
    G6 itself, so resolving it removes that ground outright. **It no longer reopens anything in
    ground (1)**, because ground (1) is now a Trivy↔ZAP finding and Semgrep is not a party to it —
    which is a change worth naming: under the old list, resolving G6 both removed a ground *and*
    reopened two thirds of another, and that entanglement was the subject of a whole paragraph.
    The new ground (1) and ground (3) are independent of G6 and remain whole.

    So the honest statement is unchanged in shape and stronger in content: **resolving G6 leaves
    two independent grounds standing, one of them a measured false match, which is a trigger to
    re-read this decision rather than to reverse it** — and anybody who resolves G6 and concludes
    CWE is thereby back in the key has skipped that re-read. Conversely this decision remains
    **conditional on G6 remaining unresolved**, which is why that entry stays open rather than
    being marked discharged when M5.1 closes.

    Read this together with the corpus's own limit, recorded in the fixtures README: over one small
    Flask app with three vulnerable packages, neither the disjointness the old ground (1) rested on
    nor the single collision the new one rests on is proof of a structural property. **The
    asymmetry is that they fail differently.** A thin corpus measuring an empty intersection cannot
    separate *"these families never overlap"* from *"this one happened not to"* — it might be
    hiding a real signal. A thin corpus measuring a **false match** has already produced the
    failure mode; a larger corpus could add true matches beside it, but cannot retract this one.
    That is why the replacement is an upgrade rather than a substitution of equals.

  - **Decision C — the SAST↔DAST derivation is deferred, and the reason is not its cost.** The
    derivation — normalising ZAP's crawled URL path against a Flask route table to reach the
    source line Semgrep flagged — is bounded work for this target's shape.

    ***(Basis REWRITTEN 2026-08-25 by the active-scan probe, not annotated — on the same rule
    Decision B's rewrite states one bullet above: a falsified measurement that stays on the page is
    a measurement somebody will cite. What it said, once, for the record: that the per-URL alert
    sets were `/` → five alerts and `/calculate?expr=2*3` → four, that **"no alert fires only on
    `/calculate`, and its alert set is a strict subset of `/`'s"**, and that the derived group would
    therefore be **"a co-location with zero discriminating power"**. All three were measured against
    a passive-only scan plan and all three fail when the plan changes. **The deferral does not** —
    see the Amendments entry, which carries the full treatment and the reason the decision now rests
    on.)***

    It is deferred because the group it would produce cannot yet be trusted. Measured under an
    active scan plan, keyed on **path** rather than full URL — `6-5` fires at `?expr=calculate` and
    `90036` at `?expr=2*3`, so a full-URL key splits the vulnerable endpoint across two rows and
    hides the result:

    | URL path | alerts |
    |---|---|
    | `/` | `10020-1`, `10021`, `10027`, `10036-2`, `10038-1`, `10106` |
    | `/calculate` | `10020-1`, `10021`, `10036-2`, `10038-1`, **`6-5`**, **`90036`** |
    | `/robots.txt` | `10036-2`, `10038-1` |
    | `/sitemap.xml` | `10036-2`, `10038-1` |

    **Two alerts fire only on `/calculate`** — `6-5` and `90036`, the latter at confidence 3 — **and
    the subset relation is false in both directions**, since `/` carries `10027` and `10106` the
    endpoint does not. So discriminating power exists, and the objection this decision was
    originally founded on is gone. **What replaces it is worse and is why the deferral stands:** the
    group would be well-formed and possibly about two different systems, because nothing asserts the
    crawled URL serves the tree Semgrep read. See the Amendments entry.

    **Two triggers, required for different reasons, and neither substitutes for the other.**
    Recorded as a distinction rather than a list, because a reader handed an undifferentiated pair
    will resolve the more visible one and conclude the path is open:

    | | condition on | what its absence means |
    |---|---|---|
    | **G24** | **existence** — that a shared finding exists at all | the shipped scan plan is passive-only **while it is**, so DAST reports nothing about the `eval()` sink. The SAST half exists; the DAST half does not. Measured satisfiable by the probe above and still open — no `activeScan` job has shipped. |
    | **G27** | **validity** — that comparing them is well-founded | nothing asserts the crawled URL serves the tree Semgrep read, and the derivation's route-path-to-view-function stage assumes exactly that. |

    Resolving **G24 alone** yields a real SAST↔DAST pair whose correlation is still unfounded,
    because the URL may serve a different tree; the correlation is produced, is wrong, and nothing
    records that it happened. Resolving **G27 alone** yields a valid path with nothing to put
    through it. **G27 is the less visible of the two**, and deliberately named so: the banner case
    at least presents as a version comparison somebody might question, while the derivation's
    dependence on the same coupling is betrayed by nothing at all.

- **2026-08-25 (active-scan probe): Decision C's measured basis is FALSIFIED. The decision stands,
  and it stands behind BOTH triggers exactly as before — what changed is that G24 is now measured
  *satisfiable*, which is not the same as satisfied.** A hand-run of `ZapAdapter`'s plan shape with an `activeScan` job added, against
  the same target at the same commit. **Which half died and which survived**, stated as a split
  because a decision whose basis is retracted wholesale is one nobody can rely on:

  **Died — the discriminating-power measurement.** *"No alert fires only on `/calculate`, and its
  alert set is a strict subset of `/`'s"* is false under an active scan, and so is everything drawn
  from it. **The corrected per-path sets are in Decision C's own body**, which was rewritten in place
  rather than left pointing here — one table, not two, because a measurement copied into two
  documents is the drift G20 exists to track. In summary: **two alerts fire only on `/calculate`** —
  `6-5` "Path Traversal" and **`90036` "Server Side Template Injection (Blind)", riskcode 3,
  confidence 3, param `expr`** — and the subset relation is **false in both directions**, since `/`
  carries `10027` and `10106` the endpoint does not. So the
  derived group is not `{dangerous-eval}` plus four alerts the root also carries; it is
  `dangerous-eval` plus a confidence-3 finding that the endpoint executes shell commands, which the
  root does not have and structurally cannot. **The "co-location with zero discriminating power"
  conclusion is retracted** — such a group clears `PRODUCT_SPEC.md` §10's bar rather than reading
  as though it did.

  The table above is keyed on **path** where the original was keyed on URL, and that is not
  presentational: `6-5` fires at `?expr=calculate` and `90036` at `?expr=2*3`, so a full-URL key
  splits the vulnerable endpoint across two rows and hides the result. The derivation this decision
  defers therefore has to normalise the query string away — one more stage, which the original
  table's shape concealed.

  **Survived — the whole of the validity argument.** Nothing the probe measured touches **G27**.
  The app was served out-of-process from the checkout itself, the one configuration in which the
  coupling holds by construction, so the probe is silent on that question by the same accident the
  G23 capture was. The two-trigger table is **unchanged in substance and changed in balance**, and
  the distinction has to be stated exactly because the loose version is wrong: **G24 is measured
  *satisfiable*, which is not the same as *satisfied*.** Its `Status:` is `assigned → M5.4` — open.
  Nothing has shipped an `activeScan` job, so no DAST finding about the sink exists in any
  production scan today, and **both triggers remain open**. What changed is their *character*: G24
  was an open question about whether the finding was obtainable at all, and is now a decision about
  scan policy with a measured answer behind it, while G27 is unchanged and is now the harder of the
  two. Read the table's G24 row as *"the scan plan is passive-only **while it is**"* rather than as
  a permanent bound; the register entry's title carries the same correction.

  **What this does NOT change is the deferral.** The derivation is still deferred; what changed is
  the reason, and it is deferred behind **both** triggers exactly as before. It was deferred
  because it *would produce a group with no information in it*. It is now deferred because
  **the group would be well-formed and possibly about two different systems** — a worse failure,
  and a stronger reason to wait for G27 rather than a weaker one. `ROADMAP.md`
  schedules the three pieces as **M5.4** (existence, behind consent), **M5.5** (validity, G27) and
  **M5.6** (the derivation itself) — three issues, where this decision's table implies two.

  **Still deferred, so the discharge is not read as wider than it is: the key's own field list.**
  This amendment records what is *out* and, in the roadmap, what M5 groups on. The frozen
  dataclass's fields — and the no-narrowing constraint section (b) imposes on whoever writes
  them — stay with the implementation issue, where matching code will exist to constrain the
  choice.

  **What M5 delivers instead is intra-tool, and is scoped in `ROADMAP.md` M5.1 rather than here.**
  Decisions A–C above concern cross-tool matching only. The roadmap entry carries the grouping
  signals, the measurement behind them, and the `PRODUCT_SPEC.md` §5-versus-FR-6 disagreement that
  the intra-tool scope rests on.

- **2026-08-25: the "implementation issue" the amendment above defers the key's field list to is
  `ROADMAP.md` M5.8.** No such issue existed when that deferral was written — M5.1 closed without
  building `CorrelateFindingsUseCase`, so it pointed at nothing, which is registered as **G30**.
  That field list and section (b)'s no-narrowing constraint are M5.8's acceptance criteria, and a
  field list departing from what is frozen above amends this ADR here.

## Alternatives considered

**1. A structural `Protocol` in `correlation/domain/` describing only the fields correlation
reads.** The closest rival, and it very nearly wins. It is legal — a Protocol is correlation's
own type — it needs no mapping step, and structural typing means a `Finding` satisfies it
without either module knowing. Two things decide against it, neither decisive alone. First,
**the conformance check is weaker and later**: a Protocol is satisfied at the call site where
a `Finding` is passed to something expecting it, so the check exists only where such a call
exists, and a Protocol with no current caller is checked nowhere while still reading as a
contract. The key's construction site cannot be absent, because without it there is no key.
Second, a Protocol invites `domain/` functions to accept **the entity itself**, which
re-imports every field's semantics into correlation's domain by attribute access — the whole
of `Finding` reachable through a description of four fields. The key makes the subset
explicit and total. Recorded as close, because if the drift-detection argument in (b) is ever
weakened, this is the option to revisit first.

**2. Matching logic in `application/` rather than `domain/`, taking the type by inference the
way `NormalizeScanUseCase` does.** Rejected on measurement rather than taste. The precedent
does not reach this case, and reading the file is what shows it. `normalize_scan.py` imports
exactly one thing from `scanning`, with the reasoning in the file:

```python
# `scanning`'s PORT, never its domain or adapters — … Note what is
# deliberately NOT imported: `ScanResult` itself. Its type is inferred from the
# port's return annotation, so mypy checks every attribute access below without
# this module naming a type it is forbidden to import.
from verion.modules.scanning.ports.scan_result_repository import ScanResultRepositoryPort
```

But it never passes a `ScanResult` anywhere. It **destructures to primitives at the boundary**:

```python
for result in await self._scan_results.get_succeeded_by_scan_id(run.scan_id):
    ...
    tool = ScannerTool(result.tool)
    ...
    observed.extend(
        mapper(
            project_id=run.project_id,
            scan_id=run.scan_id,
            raw_output=result.raw_output,
            ...
        )
    )
```

`result.tool` is a `str` handed to an enum constructor; `result.raw_output` is a `str` handed
as a keyword argument. The `result` object itself enters no annotated signature, and the
mapper type is declared to avoid naming parameters at all — `_Mapper = Callable[..., list[Finding]]`.

**So the precedent supports reading attributes off a port-returned value; it does not
demonstrate passing that value into an annotated signature, because it never does.** Note
also that the same file's `_persist(self, observed: list[Finding], run: NormalizationRun) -> list[str]`
annotates `list[Finding]` legally **only because `Finding` is `normalization`'s own domain**.
`correlation` has no equivalent move. Under this option every helper it wanted to factor out
would have to take unannotated or `Callable[..., X]`-shaped parameters, which is a real
ongoing cost rather than a one-time mapping.

**3. An anti-corruption type mirroring the whole entity, with a mapping at its boundary.**
Rejected as the **wide version of what is being adopted narrow**. Same mechanism, same
placement, same conformance site — and a drift surface of all twelve fields, two of them
structures carrying eight and six more, instead of the three or four correlation actually
matches on. Everything the mirror
buys over the key is a field correlation does not use.

**4. Promoting `Finding` to `shared_kernel/`.** Rejected on ADR-0018's criterion, which is
explicit that `shared_kernel/` takes "**closed vocabularies** — enumerations — that two or
more modules must **compare or order**, not merely **transport**. Entities and structures stay
with the module that owns them and travel by indirect import." `Finding` is a structure, and
promoting it pulls in `Location`, then `Evidence`, and hollows out `normalization/domain/`.

**What nothing currently says, and this ADR records because the rejection is weaker than it
looks: no import-linter contract guards `shared_kernel` purity.** ADR-007's own Consequences
says a rule of that kind "would need its own new contract, not something the existing set
generalizes to automatically". So this rejection rests **entirely** on a Tier 2 criterion with
no mechanical backstop — somebody could move `Finding` into `shared_kernel/` tomorrow and
`lint-imports` would report `17 kept, 0 broken`. Reopening this means overturning ADR-0018's
criterion deliberately, and nothing but review will notice if it is overturned by accident.

**5. `correlation/domain/` importing `verion.modules.normalization.ports` directly.**
**Contract-legal, and rejected on the record so the next reader does not find it legal and
stop there.** `cross-module-correlation` lists only each module's `.domain` and `.adapters`,
not `.ports`, so import-linter permits it. It does not solve the problem: importing a port
yields no *name* to annotate with — only a return type at a call site, and a `domain/`
function has only its own signature. And `layers-correlation` still forbids `domain/` reaching
`correlation`'s own ports (measured above), so this would put *another* module's persistence
interface inside a layer that may not touch its own. Legal and unhelpful is the worst
combination to leave undocumented.

**6. A structural `Protocol` in `shared_kernel/` instead of in `correlation/domain/`.** New
here, not on the roadmap's list. It solves the problem **once for `correlation`, `risk_engine`,
`brief` and `history`** rather than four times, which is a real argument and the reason it is
recorded rather than dismissed. Rejected by ADR-0018's criterion as literally written: a
Protocol describing a structure is not a closed vocabulary, and the criterion puts structures
with their owner. **The one-copy-instead-of-four argument does not go away**, and it will be
re-proposed at M6 when the second consumer arrives and the cost stops being hypothetical. At
that point it should be weighed as an amendment to ADR-0018's criterion, not as a local
convenience — and under the note in alternative 4 that nothing mechanical guards what lands in
`shared_kernel/`.

**7. A `TYPE_CHECKING`-guarded import of `Finding`.** Rejected as **illegal, not unworkable**,
and the distinction matters enough to state precisely, because the two failure modes look
alike and lead to different sentences.

- **`lint-imports` rejects it.** grimp reports the import at the line *inside* the guard, and
  the failure is byte-identical to the unguarded case apart from that line number:

  ```
  verion.modules.correlation is not allowed to import
  verion.modules.normalization.domain:

  -   verion.modules.correlation.domain._probe ->
  verion.modules.normalization.domain.finding (l.4)
  ```

- **`mypy --strict` accepts it**, with zero errors — and that green is *real*, not a forward
  reference silently unresolved. Verified with a control probe annotating a deliberately
  nonexistent name under the identical shape, which errors:

  ```
  error: Module "verion.modules.normalization.domain.finding" has no attribute "NoSuchType"  [attr-defined]
  ```

**So the technique works and the contract forbids it.** That alone would make it merely
currently-illegal, and somebody would reasonably ask why the contract is not relaxed —
`import-linter` 2.13 has an `exclude_type_checking_imports` option that would do exactly that.
**The reason not to is why this is rejected rather than deferred.** That option is a
**session** option: `_get_exclude_type_checking_imports` in
`importlinter/application/use_cases.py` reads it from `session_options` and returns `False` on
`KeyError`, and `pyproject.toml` does not set it. It is not per-contract. Enabling it to
unblock `correlation` would **remove type-checking imports from the graph for all eight
cross-module contracts at once**, and `lint-imports` would go on reporting `17 kept, 0 broken`
with no visible change — a mechanical gate quietly weakened while still reporting green, which
is the exact decay the tracked type-suppression baseline exists to detect one tool over.
