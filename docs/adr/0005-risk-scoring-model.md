# ADR-0005 — The risk scoring model: what a Risk is, the function over it, and what a score may not claim

## Status

Accepted — 2026-09-16 (M6.1).

**Reserved at M0, written at M6.1, and the gap between those dates matters.** `0005` was claimed
by a roadmap entry and left uncreated; `docs/adr/README.md` and `ARCHITECTURE.md` §12 both carried
a sentence saying so until this commit. Its number therefore sits among the foundational ADRs
while its content is M6's. Every decision below is taken against M5's shipped correlation and the
committed corpus — a reader arriving in number order should read it after ADR-0029, not after
ADR-0004.

## Context

ADR-0003 fixed the constraint — scoring is *"a documented, inspectable function of explicit
signals"* — and deferred the function here by name. FR-7 names the signals. `PRODUCT_SPEC.md` §10
asks for *"at least one clear, demonstrable case where correlation across 2+ tools produces a
materially better prioritization than looking at raw tool output"*.

What M5 shipped is narrower than those sentences assume, and it orders everything below. Measured
at `82b48d5` through the real mappers, `build_match_key` and `extract_routes`:

- **The one cross-tool group's membership is produced by the route map, not by agreement between
  the findings.** The `/calculate` surface takes the Semgrep `dangerous-eval` finding because
  exactly one route's span holds `app.py` line 28 (ADR-0029 decision 4). Its DAST members are
  whatever ZAP reported on that path: passive, **4 of 4** are header hygiene (`10038-1`, `10020-1`,
  `10036-2`, `10021`); active, **2 of 6** are plausibly the same vulnerability (`6-5` Path
  Traversal, `90036` Blind SSTI) and 4 are still headers. **No field distinguishes those cases.**
- **Three of FR-7's signals have no source in `src/`** — asset sensitivity, environment,
  reachability. Exposure exists only as `SecurityContext.exposure_tags`: free text, behind a
  persistence port, unreadable once a project has two context rows (**G55**).
- **There is no `Risk` type in `src/` at all.** A candidate Risk is `MatchGroup` — a key and
  `finding_ids` — recomputed per request and stored nowhere (ADR-0025 decision 1).
- `UNKNOWN` and `CRITICAL` severities are **0 of 34 and 0 of 37** across both corpora.

## Decision

### 0. A Risk is a SURFACE, not a vulnerability. This is chosen, not discovered

A group is **the thing its match key names** — a package, or a route path — and a Risk is
"everything wrong with that surface", not "these findings describe the same vulnerability".

The data does not contain the second reading: membership comes from the route map, and the signal
separating a substantive member from a coincidental one exists in no field. Choosing it would mean
the shipped grouping cannot be scored as it stands, blocking M6.2 until that signal is designed.
The surface reading also covers the package groups unchanged — 3 of the 7 are Trivy's, keyed on the
three distinct `PkgName`s its 20 findings carry — because "everything wrong with `urllib3`" is a
unit of remediation for the same reason `/calculate` is.

**Consequently no `RiskReasoning` text may say two findings describe one vulnerability**, and
`PRODUCT_SPEC.md` §5's **Risk** row carries this definition as of this commit.

### 1. The function, and the inputs it refuses

Per surface, over its members:

| signal | value | read from |
|---|---|---|
| `severity_signal` | highest `Severity.rank` among members whose severity is **not** `UNKNOWN`; `0` if none | `Finding.severity` |
| `exposure_signal` | `1` if any member's source is ZAP, else `0` | `Finding.source` |
| `corroboration_signal` | `1` if members carry two or more distinct sources, else `0` | `Finding.source` |

`priority_score = severity_signal + exposure_signal + corroboration_signal`; the bucket is
**`fix_now` at ≥ 6, `plan` at 4–5, `monitor` below 4**. `RiskReasoning` records each signal's value
*and the member that produced it*, so a bucket is re-derivable by hand — which is what rule 5
requires and why the arithmetic is this small.

**`UNKNOWN` contributes nothing and is never the maximum.** `shared_kernel/severity.py` already
says its bottom rank is *"a display convention, not a judgment"*; reading that rank as a score
would decide by accident. A surface whose members are all `UNKNOWN` scores exposure and
corroboration only, and the reasoning says no tool stated a severity.

**`exposure_signal` is what a DAST member IS**: a ZAP finding exists because a scanner reached the
surface over the network — explicit, and already in the data. It is *not* FR-7's exposure, the
project's own statement about the asset, which decision 4 declines.

**Refused, each on a measured ground:** **CVSS**, 20/20 on Trivy and **0 of 5 passive, 0 of 7
active** across the cross-tool surface's own members, so any CVSS term ranks every package group
above the surface §10 is about, by construction; **member count**, since `urllib3` is n=12 against
this surface's 5 or 7 and four of its DAST members are header hygiene; **CWE**, per decision 4; and **`native_severity`**, because
comparing `ERROR` against `HIGH` across tools is the incomparable-scales problem ADR-0018 decision
1 prevents. `source` **is** an input here, twice, which is that ADR's decision 3 answered — see its
amendment in this commit.

**This decision fixes priority only. The Risk's own `confidence` is DEFERRED to M6.2, seeded as
G63**, and the deferral is itself a finding: confidence is a second decision, it was drafted inside
this one, and **M6.1's declared byte ceiling is what caught it**. FR-7 and ADR-0003 both require a
confidence, so this ADR does not fully discharge ADR-0003's shape and says so.

### 2. `risk_engine` names nothing; it takes scalars at one construction site

It may not name `MatchGroup`, `MatchKey`, `Finding` or `Location`. **`correlation` publishes its
first port**, returning its own groups; `risk_engine/application/` calls it and takes the value by
inference off the port's return annotation, as `CorrelateFindingsUseCase` already does with
`FindingRepositoryPort`. `risk_engine/domain/` receives **scalars** — the key's fields and, per
member, `source` and `severity` — at one keyword-only construction site, `build_match_key`'s shape.
**A group carries ids only, so `risk_engine` must read findings itself** to see a severity; it
consumes two ports, both ports, so rule 3 holds.

**ADR-0023 alternative 6 — a structural `Protocol` in `shared_kernel/` — is re-proposed here as
that entry forecast, and rejected.** The argument and its grounds are a dated amendment at that
alternative, where the prediction lives.

### 3. Scoring is a pure function, run per request, persisting nothing

ADR-0025 decisions 1 and 2 hold unchanged: a score is derived from stored inputs exactly as the
grouping is, so **M6.2 writes no rows and M6.3 is not forced to**. M6.3's write stays the open
choice ADR-0025 decision 2 left it, untaken here; taking it takes **G37**'s protected-column
obligation early. Until one is taken there is no `risks` table and no upsert, and G37 stays latent
with its trigger still *the first Risk row written*.

**G35's second trigger fires here and the hole is not taken**: decision 2's port is why
`risk_engine` need not import `correlation`'s `application/`. The eight contracts are **not**
edited here; that remains G35's, and its entry carries what this changed.

**A scored listing reads the project's findings twice** — once inside correlation's use case, once
in `risk_engine`. ADR-0025 measured that read at **10.974–12.050 ms** and **26.293–30.271 ms** over
2,000 findings, so a scored request is two of those. **Accepted for M6**; the alternative, widening
correlation's port to carry per-finding scalars, makes `correlation` decide what `risk_engine`
needs. Seeded as **G61**, inheriting ADR-0025's scale trigger.

### 4. CWE, `Finding.confidence` and the three sourceless signals: declined, each with its cost

**CWE is not a scoring input.** Semgrep contributes **0 of 1** (**G6**), so one tool of three is
permanently silent; and `cwe` sits in `_REFRESHED_COLUMNS`, so a Trivy database update can rewrite
the stored value with nothing recording it (**G26**) — an input that changes under nobody's control
is untraceable, which is rule 5. Under decision 0 it is also unnecessary: a surface does not
require its members to share a taxonomy. **This makes both entries' M6 clauses wrong; both carry a
dated note saying so**, and both stay open.

**`Finding.confidence` is DECLINED**, discharging ADR-0018 decision 5's deferral to this issue. Its
two grounds hold, and a third is added that no document carried: **the degrees-versus-states hazard
is not exhibited by either capture.** Only codes `1`, `2` and `3` appear (passive `{3: 8, 2: 5}`,
active `{3: 9, 2: 6, 1: 1}`); no `Confirmed` or `False Positive` occurs anywhere. A scale designed
now would be designed against ZAP's documentation rather than data — the failure ADR-0018's own
Context records, where a documented severity field turned out not to exist. Re-propose when a
capture exhibits a state value, or a second tool supplies confidence. *(An input; the Risk's own
confidence, deferred in decision 1, is an output.)*

**Asset sensitivity, environment and reachability are declined for M6**, having no source. Exposure
is declined **as FR-7 means it** — free text behind a persistence port another module must not
consume (ADR-0022 decision 2), unreadable for a project detected twice (**G55**) — and replaced by
decision 1's DAST term, a weaker claim. **This edits ADR-0003's premise**, so that ADR carries a
dated amendment in this commit.

### 5. What a green M6.2 will not prove

ADR-0027 decision 5's pattern, stated before the code exists:

- **Nothing about `UNKNOWN` or `CRITICAL`** — 0 of 34 and 0 of 37 in the two *captured* corpora, so
  decision 1's `UNKNOWN` rule and the top of the scale are unreachable from real scanner output.
  Synthetic fixtures producing both already exist (`tests/fixtures/scanners/trivy_synthetic_edges.json`
  yields one `critical` and one `unknown`), so what M6.2 owes is not a fixture but **scoring-level
  coverage exercising those two branches** — and any new hand-written `Finding` it adds is **G19**
  and **G40**'s shape, against ADR-0026's profile or explicitly excused.
- **Nothing about §10's surface existing**: it needs a declaration in force and a readable route
  map, which is write-once per project (**G55**). Out of force, both corpora produce zero
  cross-tool groups.
- **Nothing about the corroboration signal being right.** Its only passive instance is one where
  4 of 4 DAST members are unrelated to the SAST finding. It says two tools reported on a surface;
  it does not say they agree. **G62**.
- **No latency claim.** Decision 3's doubling is arithmetic over ADR-0025's numbers.

## Consequences

**`PRODUCT_SPEC.md` §10, answered at the width the evidence supports** — the likeliest place in
this milestone to claim more than is true, so it is stated in both directions.

*Does the `/calculate` `{semgrep, zap}` surface rank above its members read separately?* **Yes, in
both corpora, and it is the only surface that does.** Scored by decision 1 it is
`4 + 1 + 1 = 6 → fix_now`. Its members scored alone: `dangerous-eval` `4 → plan`, and the DAST
members `3–4` in the passive corpus and `3–5` in the active one — so **the highest member alone is
4 passive and 5 active**, and the surface is strictly above every one of them in both. **Whole-corpus result: with the
declaration in force, 1 `fix_now` and 6 `plan` in both corpora; with it out of force, 8 `plan` and
no `fix_now` in either.** That is the §10 demonstration and it is real — raw tool output ranks
`dangerous-eval` level with eight Trivy HIGHs, and this function puts one surface above all of them.

*Does it rank above the corpus's other groups on any per-finding field?* **No, and this is the
honest half.** `urllib3` is n=12 carrying 6 HIGH findings against this surface's 1 or 3; CVSS is
20/20 on Trivy and absent from every member of this surface; CWE cannot carry the agreement because
Semgrep supplies none. **The
entire lift comes from two GROUP-level facts** — a DAST member exists, two tools reported here —
neither of which is a property of any finding. §10 is therefore satisfied **as a prioritization
that differs from raw tool output in a traceable way**, and *not* as a claim that this surface is
more dangerous than `urllib3`'s twelve CVEs. Nothing here establishes the second, and no reasoning
text may imply it.

**Register**: **G61**, **G62** and **G63** are opened by this commit. Nine entries carry a dated
note recording what this decision did to them: **G6**, **G19**, **G26**, **G33**, **G35**, **G37**,
**G40**, **G53** and **G55**.

**Amendments obliged and taken here**: ADR-0003 (its five signals, and the confidence its Decision
names), ADR-0018 (decision 5's deferral discharged; decision 1's `UNKNOWN` question and decision
3's `source` question both answered), ADR-0023 (alternative 6 re-proposed and rejected).

**`ARCHITECTURE.md` §4.1's `Risk` block stays "designed, not built"**: this ADR adds a function and
a signal set, not a table.

## Alternatives considered

**A group is a vulnerability** (decision 0's option (b)). Rejected because the shipped grouping
cannot deliver it and no available field repairs it — not because it is wrong. It is the better
product if the signal ever exists; **G62** carries it. Taking it now blocks M6.2 on a signal nobody
has designed.

**CVSS scaled into the severity term.** Rejected on the measurement that no member of the
cross-tool surface carries one while all 20 Trivy findings do: it would encode "Trivy findings
matter most" as arithmetic.

**Weight by member count.** Rejected: `urllib3` n=12 against `/calculate` n=5, four of whose five
members are header hygiene.

**Persist the score at M6.3.** Open, not taken — ADR-0025 decision 2 leaves it a choice, and taking
it means taking G37's protected-column obligation and G11's fourth-table forecast early, for a
value that is a pure function of stored inputs.

**Score inside `correlation`**, avoiding the second findings read. Rejected: it puts FR-7's decision
layer inside FR-6's module, against `ARCHITECTURE.md` §3's split.
