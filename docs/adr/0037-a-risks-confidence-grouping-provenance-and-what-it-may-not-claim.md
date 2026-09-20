# ADR-0037 — A Risk's confidence: grouping provenance, where it is computed, and what it may not claim

## Status

Accepted

## Context

FR-8 gives a Security Brief four parts. Three ship. **Confidence has never existed**, and four issues
across two milestones have recorded that rather than closing it: ADR-0005 decision 1 deferred the
scale at M6.1 and seeded **G63**; M6.2 emitted
none and asserted the absence; M7.1 recorded the absence rather than choosing (ADR-0032 decision 3);
M7.2 designed `SecurityBrief` without the field (ADR-0033 decision 2). FR-7 and ADR-0003's Decision
both name a confidence, and ADR-0003 carries a dated correction saying shipped code does not have one.

**Why it stalled, in G63's own words: *"either scale reaches a third module."*** A **grouping**
confidence needs provenance out of `correlation`, whose `MatchGroup` carries only `key` and
`finding_ids`. An **evidence** confidence needs `Finding.confidence`, which ADR-0005 decision 4
declined, plus a migration. That is a milestone's work, not an issue's, which is why four issues in a
row recorded the absence instead.

M8.5 is the milestone-shaped issue. `ROADMAP.md`'s M8.5 traces to M8's exit condition through the
Brief a user reads, and the M7→M8 boundary review assigned **G63**, **G74** and **G53** here.

Declared byte ceiling, **derived rather than chosen**, because ADR-0030's was invented and missed by
42.3%: ADR-0036 measures **19,051** bytes as a git blob with a **12,854**-byte `## Decision` span over
**13** decisions — 1,465 and 989 per decision. At this document's 12 decisions that gives **17,500
bytes blob (LF), of which 11,900 for the `## Decision` span**. Measured at acceptance and reported as
met or missed, never re-declared.

## Decision

### 1. Confidence is GROUPING PROVENANCE, and three things it may not claim

A Risk's confidence answers **how this Risk's membership was established**: whether every finding was
placed on the surface by a field its own scanner reported, or whether at least one was placed there by
Verion inferring a route.

It is **not** a statement that a finding is real, **not** a statement that the scanners agree or
describe one vulnerability (`CORROBORATION_DEFINITION`'s limit, **G62**), and **not** an input to the
priority (decision 7).

**FR-7's evidence-confidence input stays declined**, and this is a deferral rather than a cut:
`PRODUCT_SPEC.md` FR-7's 2026-09-19 note strikes reachability, asset sensitivity and environment and
leaves `confidence` in its input list. ADR-0005 decision 4's re-propose condition — *"a capture
exhibits a state value, or a second tool supplies confidence"* — is **unmet**: only ZAP supplies one,
and only codes `1`, `2` and `3` appear across both captures. Registered as **G94**.

### 2. Three values on one axis, keyed on `has_signal` and the builder's branch

| value | when |
|---|---|
| `ungrouped` | the key carried no signal, so nothing could be grouped on |
| `reported` | every member attached off a field its own scanner reported |
| `inferred` | at least one member was placed by the route map (ADR-0029 decision 4) |

**One axis, and the axis is provenance rather than cardinality.** A Trivy package surface with one
member was keyed on a real signal and would have absorbed a second finding on that package, so it is
`reported`; labelling it by its size would throw that away. `ungrouped` is exactly
`not MatchKey.has_signal`, which `group_by_match_key` already makes a singleton.

**Two vocabularies, stated once so neither reader is stranded.** The register says **`read`/`derived`**
— G63's `Deferral rationale:`, G53's Assignment, `ROADMAP.md`'s M6.2 bullet. Those are dated notes and
are not rewritten (**G34**). The API says **`reported`/`inferred`**, plus `ungrouped`, which the
register's two-value vocabulary has no word for. `read` ↔ `reported` and `derived` ↔ `inferred`.
The API words are chosen because **decision 11 makes them load-bearing**: a developer reading
`confidence: read` learns nothing about what was read.

### 3. The vocabulary lives in `shared_kernel/`, and this is the criterion's first POSITIVE application

ADR-0018 decision 2: *"`shared_kernel/` takes **closed vocabularies** — enumerations — that two or
more modules must **compare or order**, not merely **transport**."* `correlation` produces this value
and `risk_engine` compares it; neither may import the other's `domain/` (rule 3). It is inside the
criterion.

**This is the third *enum*, and the criterion was written for exactly this moment** — decision 2 says
*"`Severity` is the second entry … without one, the third arrives by habit."*

**It is the first admission SINCE the criterion was written, which is not the same as the first
positive application**, and the distinction matters because ADR-0018 records both. That decision
admitted `Severity` in the act of stating the criterion — its own words, *"Applied three times in this
issue, twice in the negative: `Severity` **in** (decision 2), `Confidence` out (decision 5), `Location`
out"* — and `ScannerTool` predates the criterion entirely (ADR-016 decision 4). Every application
**since** has been a refusal: `Confidence` and `Location` (ADR-0018 itself), `dedup_hash` (ADR-0019
decision 6), `Finding` **and** a structural `Protocol` (ADR-0023, which ADR-0018's own running counter
treats as one occasion), and that `Protocol` again (ADR-0005 decision 2). Five occasions by that
counting, and `Confidence` is the first thing let in since.

**Note the name collision, because two different things here are called confidence.** What ADR-0018
declined is `Finding.confidence`, a **per-finding** value and an *input*, still declined (**G94**).
What is admitted here is a **per-Risk** grouping provenance, an *output*. ADR-0005 decision 4 drew
that line first.

**The package's contents are stated accurately, because an argument from the criterion must not
mis-describe what it governs.** `shared_kernel/` holds `scanner_tools.py`, `severity.py` **and
`ports.py`** — `ClockPort` and `IdGeneratorPort`, two `Protocol`s that are neither closed vocabularies
nor enumerations. Decision 2 governs which **vocabularies** the package takes; it does not describe the
package's whole contents, and `ports.py` sits outside it. Not changed here.

**Rejected, each with its ground:**

- **Two enums, one per module, held equal by a test.** That is **G33**'s shape — two declarations kept
  in agreement by a test and nothing else — and creating a fresh instance of a registered defect when
  an alternative exists is not available.
- **A bare `str` crossing**, on ADR-0017's primitives precedent. `ScoredSurface.confidence: str` lets
  `"inferrd"` typecheck on a frozen domain type feeding three routes. A typo must be a type error.
- **`shared_kernel` is named by no import-linter contract** — `grep shared_kernel pyproject.toml`
  returns nothing — so nothing changes there, and rule 1's framework clause is unenforced for it. Moot
  here: a `StrEnum` imports `enum` and nothing else.

**G67 does not apply**, and it is named so a later reader sees the line drawn rather than crossed: its
subject is a **transported** structure, `NormalizationRun`'s six fields. This is compared vocabulary.

### 4. The BUILDER returns provenance, so the construction site names it

`build_match_key` returns its key **and** the provenance of that key, as a small frozen result type in
`correlation/domain/`.

**This is G53's own stated closure**, quoted because the entry resolves on it: *"a provenance-aware
check at the construction site — a second parameter naming where `url` came from, or a distinct type
for a derived path — either of which is a design change to a site an accepted ADR describes, and
therefore an amendment rather than a tidy-up."* ADR-0029 carries that amendment in this commit.

**Changing only `MatchGroup` would NOT close it**, and this is why the shape is decided here rather
than left to the implementation. The group is downstream of the builder, so its field would have to be
filled by somebody re-deriving *"was this url derived?"* from the key and the finding — a second copy
of the builder's rule, `mypy`-invisible, in `correlation` or (worse) in `risk_engine`. That is the
exact defect ADR-0023 section (c) names and G53 records: *"Semantic changes behind an unchanged
signature."* Returning the value makes the site total again.

**No fourth `MatchKey` field**, and **ADR-0023's frozen field list is untouched** — stated so nobody
goes looking for an amendment that is not owed. ADR-0029 decision 4 priced a fourth field and rejected
it as the most expensive of three shapes: inert under whole-dataclass equality, unable to satisfy
`_FIELD_SOURCES`, and breaking the partition test and `_group_order`. The partition, `has_signal` and
the conformance test all stand.

**Asserted, not left to `mypy`:** every value the builder can produce is declared, and every declared
value is produced by some input shape. A fourth branch added without deciding its provenance fails, and
so does an enum member no branch reaches. This is G53's second half — a new parameter getting `mypy`
and no conformance assertion — answered inside the fix for its first, for the return value. It is **not**
answered for `file_path`, `start_line` and `PathsServing`, which keep `mypy` and no assertion; that
residue stays on the record.

### 5. `MatchGroup` carries one confidence per member, aligned to `finding_ids`

A tuple, positionally aligned to `finding_ids` and sorted **with** it, never independently —
`matching.py`'s own *"Ordered rather than merely collected"*. A set would lose the alignment that makes
the values mean anything.

It crosses `CandidateRiskPort` by **inference**, exactly as the type already does: `risk_engine` names
no `correlation` type, so nothing about the contracts changes.

**`MatchGroup` gains its first field-set test here**, because this issue adds its first new field. A
bare enumeration would be the hand-written third copy ADR-0020 decision 4 and ADR-0023 section (b) both
argue against, so the load-bearing half is the **alignment invariant** — one confidence per member, in
member order — which nothing else catches and whose failure silently labels the wrong finding.

### 6. The surface's confidence is a FOLD, in `risk_engine/domain`

`inferred` if any member is; else `ungrouped` if any member is, reachable only for a singleton; else
`reported`. Total, because `ungrouped` implies `not has_signal` implies a one-member group.

**The fold lives with the surface**, because a surface is `risk_engine`'s unit (ADR-0005 decision 0) and
"this surface's membership was partly inferred" is a statement about the surface. The per-member value
reaches `risk_engine/domain/` as a `shared_kernel` scalar at the **one keyword-only construction site**
ADR-0005 decision 2 established, which is why no helper there needs to name a group or a finding.

**G77 does not fire.** `shared_kernel` is not another module, so the count of cross-module imports from
any `domain/` package stays at one — `brief/domain`'s, that entry's subject.

### 7. NOT summed into the priority, and this decision carries its own reopen condition

Confidence sits beside the score. ADR-0005 decision 1's function is unchanged and the thresholds do not
move.

**The ground, and it is corpus-bounded rather than a theorem.** The only cross-source pairing
`build_match_key` can produce is a route-derived Semgrep member with a ZAP member (**G64**; a Semgrep
finding carries no `Location.url`, so it reaches a path key only by derivation). Corroboration needs two
sources, so **every `fix_now` surface reachable from real scanner output contains an inferred member**:
`fix_now ⊆ inferred`. `scoring.py` states this under *"What this function cannot reach from **real
scanner output**"* — a fact about two captured corpora and the shipped mappers.

So a term penalising `inferred` would close the top bucket outright, and one rewarding it would reward
inference. Neither is available, which is the argument for carrying the value beside the score.

**Reopens if** any of three. **One is inherited and two are new**, and the set is deliberately not
called verbatim, because G64's clauses do not cover this fact:

- **Inherited from G64**, whose `Reopens if:` reads *"any change to the match key that lets two tools
  share a package surface, or the first real project whose highest-scoring surface is a `CRITICAL`
  package one"* — **the match-key clause only.** Its second clause is about one project's data and moves
  nothing about provenance.
- **New — a mapper change gives a Semgrep finding a `Location.url`.** The strongest of the three: such a
  finding takes the url branch, scores `reported`, and can pair with ZAP on the same path, producing a
  `fix_now` surface with **no inferred member at all**. No G64 clause reaches it, G64 being about the
  match key and package surfaces while this is a change in `normalization`'s mappers.
- **New — a second `zap_target_url`.** It removes the one-host bound that makes a path group's
  membership meaningful (**G53**'s dated note), so two hosts' paths collide and what a path group
  contains stops being what this fact was derived over.

**Why two are new:** G64's clauses are about what can reach the top *bucket*; this fact is about the
*provenance* every top-bucket surface has. A change can leave bucket reachability untouched and still
break the subset. If any clause fires, the argument above is re-derived rather than assumed.

### 8. Storage: its own column, and `ExplainableDecision` is UNTOUCHED

The value sits on `ScoredSurface`, on `ExplainableRisk`, and on `SecurityBrief` with a **nullable
`security_briefs.confidence` column**, `NULL` meaning a Brief written before M8.5 — `what_happened`'s
precedent exactly (ADR-0034 decision 3, migration `c5d2e8f41a93`). No backfill: nothing to compute it
from, since the surface it described may have moved.

**Not inside `ExplainableDecision`, and the ground is rule 6 rather than convenience.** That type's
docstring says it is *"everything a narrator may see"* and it is frozen *"because between 'decided' and
'narrated' nothing may change it: rule 6 enforced by the type rather than by a convention."* Decision 9
forbids the narrator this value. Putting a narrator-forbidden field in the narrator's carrier would make
that docstring false and degrade rule 6 to a convention — the structure-to-convention slide ADR-0034
decision 3 refused when it chose two calls. Confidence is also a property of the **grouping**, upstream
of the decision, so it belongs beside `finding_ids`, which *is* the grouping.

**What that placement buys, stated because it is the whole return:** `_DECISION_VERSION` does not move,
no v1 reader is owed, and **every stored Brief keeps reading back**. A field on `ExplainableDecision`
would have made `_decision_from_json` raise `StoredBriefUnreadable` on every existing row, since it
builds its values from `dataclasses.fields`. Asserted, so a later issue cannot undo it quietly.

**One ADR-0018 consequence applies directly** and is not discovered later: a value crossing a
persistence boundary *"must be reconstructed as `Severity(...)` before it is compared"*. The repository
reconstructs the enum on read rather than returning the raw column.

### 9. NO PROMPT receives it

Neither `explain` nor `describe`. Each prompt's rule 4 already forecloses the value, **in its own
wording rather than a shared one**: `explain`'s says *"You are not told what the vulnerability is …
or how confident anyone is"*, a statement about the input; `describe`'s says *"Do not state or guess
how urgent anything is, how to fix it, how much effort a fix takes, or how confident anyone is"*, a
prohibition on the model. Telling either would falsify the first and undercut the second, and would
move `PROMPT_VERSION`; `explain`'s prompt is byte-identical since M7.1 by ADR-0034 decision 3's
design.

**Stated explicitly so a later issue does not add it to the narrative without knowing why it was kept
out.** The value is a response field the UI renders; the narrator never mentions it. This also leaves
ADR-0034 decision 3's *"zero attacker-controlled bytes"* property untouched rather than needing an
argument about fixed vocabularies.

**The property already holds structurally, and the test is a regression guard rather than the
mechanism**: `render_facts` takes only `ExplainableDecision`, which decision 8 leaves alone, and
`_member_object` iterates `_RENDERED_FIELDS` over `BriefMember`, which this issue does not touch.

**How it is asserted — decided on a measurement, not on taste.** Positionally, by key, plus the
**whole** `CONFIDENCE_DEFINITION` absent from both messages of both prompts. **Never a value substring
and never sentence by sentence**: both were measured red at HEAD before this text was written.
`"reported"` appears in **three of the four rendered messages** — `describe`'s developer and user
messages, and `explain`'s user message, which renders `CORROBORATION_DEFINITION` verbatim. It is worse
than that count suggests: **five** string literals in `src/` can put the word into a rendered prompt,
the two least obvious being `scoring.py`'s own `Signal.note` texts, *"no member was reported by a DAST
scanner"* and *"every member was reported by …"*, which `_signal_line` renders whenever a signal does
not fire. And this definition's closing sentence is reused from `CORROBORATION_DEFINITION`, so a
sentence-level form collides with it too. Both would go green only by deleting their own subject. The
whole-constant form passes a partial render, which the positional assertion is what covers.

### 10. The definition: ONE owner, two placements

`correlation` declares `CONFIDENCE_DEFINITION` in its **published port module**, beside
`CandidateRiskAccessDenied` and for that class's stated reason: a published value other modules must
name belongs where they are allowed to name it. `risk_engine` and `brief` import the constant.
`cross-module-risk-engine` and `cross-module-brief` forbid `correlation.domain` and `.adapters`, not
`.ports`. One declaration, two readers, **no copy**.

**Two placements, because each route already has a home for its constants**, and the divergence is
grounded here in one sentence so it is not read as **G17**'s shape — two routes answering one question
differently. The definition is one constant *per response*, not per item:

- **`/scored-risks` carries it on the ENVELOPE**, beside `thresholds`. ADR-0030 decision 3 put the
  thresholds there because per item they are *"a constant repeated once per surface — the speculative
  shape ADR-0016 decision 3 and ADR-0021 both refused"*, and `SignalResponse` on that route carries no
  `definition` at all.
- **A Brief carries it on the ITEM**, as `{value, definition}`, on `BriefSignalResponse.definition`'s
  precedent. A Brief is a single narrated record and has no envelope to put it on.

Asserted **byte-identical across both placements**, which is what makes "one owner" a claim rather than
a convention — ADR-0030 decision 6's *"a docstring alone is a comment; an assertion makes it a claim"*.

Its text **names all three values and defines each**, so the definition and the enum cannot drift apart
silently; a value added without extending the text fails.

### 11. The INVERSION, recorded because the definition exists for it

On `/calculate` — the only cross-tool surface either corpus exhibits — the label points **opposite** to
how a developer will read it. Measured in **G62**: 4 of 4 passive DAST members are header hygiene
(`10038-1`, `10020-1`, `10036-2`, `10021`), *"unrelated to the `dangerous-eval` finding they are grouped
with"*. Those four attach through their own `Location.url` and are therefore `reported` — the label a
reader hears as solid. The `dangerous-eval` Semgrep member, the one the product exists to find, attaches
by derivation and is `inferred` — the label a reader hears as shaky.

So the confidence is **anti-correlated with substantiveness** on the one surface anybody can inspect.
That is why decision 10 makes the definition ride the response instead of leaving the field name and a
frontend's copy to carry the meaning, and why decision 1's list of what the value may not claim is part
of the text a user sees. Noted on G62. **Nothing here repairs G62**: the signal that would separate a
substantive pair from a coincidence still exists in no tool output.

### 12. What a green M8.5 does not prove

ADR-0027 decision 5's pattern, stated before the code exists.

- **Nothing about a second `zap_target_url`.** `ScannerConfig` carries one, so the path-keying bound
  holds by construction in every configuration CI exercises — decision 7's third reopen clause.
- **Nothing about a route map that has ever moved.** The map is frozen at each project's first detect
  (**G55**), so a stored confidence cannot yet go stale in CI or in production. **M8.7** ends that, two
  issues after this one; registered as **G93**. This is **G52**'s *"the one configuration in which the
  coupling holds by construction"* arriving again.
- **Nothing about whether a user reads the label as the definition intends.** Decision 11 is a measured
  claim about the corpus and an unmeasured hope about a reader. M8.3's cards are the first place that
  shows.
- **Nothing about a real model ignoring an instruction**, since decision 9 sends it nothing: the tests
  prove the value is absent from the prompt, which is a stronger property than compliance and a
  different one.

## Consequences

**Every register state below flips with M8.5's CODE commit, not with this one.** This document's commit
writes no `src/`, so G53, G63 and G74 stay `assigned → M8.5` until the code lands. Stated once here
rather than hedged in each line.

**G53 resolves.** Its stated closure is what that commit ships, and ADR-0029 carries the amendment its
`Deferral rationale:` says is owed. Its **second half does not resolve at all**, and becomes its own
entry — **G95** — rather than a note on a resolved one: `file_path`, `start_line` and `PathsServing`
still get `mypy` and no conformance assertion, and a trigger parked inside a frozen entry is what
**G46** exists to record.

**G74 resolves.** Recommended action and estimated effort were cut to V2 at the M7→M8 boundary;
confidence was the remainder.

**G63 resolves as to ADR-0003 and FR-8, and NOT as to FR-7.** ADR-0003's Decision names *"a confidence
value"* and one then ships, discharging its 2026-09-17 correction as to that clause. FR-8 is met in all
four parts — the entry's own *"the one that bites"* was that the Brief presents a confidence to a user,
and it now carries one. FR-7 asks for a confidence computed from an explainable combination *including*
confidence-as-input, which this is not; **G94** carries it, with ADR-0005 decision 4's re-propose
condition as its trigger. Closing G63 whole would retire an obligation the code does not meet.

**G66 is struck in part**, at that entry. Its `Blocks-if-unresolved:` said the unscored route carries
*"**nothing** the scored one does not, and the only difference between them is the **ORDER**"*. The
first clause holds and widens — the scored item gains `confidence` and its envelope
`confidence_definition`, and `/risks` gains neither. The second goes **false**. Its concrete cost is
unchanged, because confidence says nothing about order.

**`/risks` is deliberately not changed**, which is what keeps that superset relation true.
`test_a_risk_carries_no_score_and_no_priority` already forbids `confidence` there and becomes
load-bearing for this decision.

**Two documents outside this one carry the struck claim, and are amended with it**: ADR-0032's Context
and its decision 3 both say a scored Risk carries no confidence and that **G63** is open, and
ADR-0004's 2026-09-16 amendment says the same. Each gets a dated note in this commit. Three `src/`
docstrings and one test say it too, and are the code commit's to correct — named here so they are not
found later.

**G61 is unchanged**: the value rides carriers that already cross, and no read is added.

**G33, G35 and G77 each get a status line and no work**, deferred under Rules for M8 rule 1. G33's shape
was avoided rather than instantiated (decision 3); G35's hole was available and not taken for the fourth
time; G77 does not fire.

**What this costs later.** A fourth value, or a change to what any value means, is a `shared_kernel`
vocabulary change reaching three modules, a response-shape change on three routes, and — because the
column stores the value — a data migration rather than a recompute. That is the price of decision 8's
placement, and it is the same price `what_happened` pays.

## Alternatives considered

**An evidence confidence.** ADR-0005 decision 4's declined input, whose re-propose condition is unmet.
It would need `Finding.confidence`, a migration, a change to ADR-0019's refresh set, and a scale
designed against ZAP's documentation rather than against data — the failure ADR-0018's 2026-09-16
amendment records. **G94.**

**A numeric confidence.** It invites being summed into `priority_score`, which decision 7 forbids on a
measured ground, and no weighting has any basis in either corpus. Rule 5 and ADR-0003 forbid a number
without explicit inputs; this would be one.

**A bool.** Cheaper, and it cannot distinguish "nothing was grouped" from "grouped off tool fields",
which is the case decision 2 exists to name.

**Recomputing on read instead of storing.** It is the `is_current` flag ADR-0033 decision 2 already
rejected — *"it would recompute on every read (**G61**)"* — and it would make `GET …/briefs` do the
doubled findings read once per listed item.

**Rejected in place, with their grounds at the decision that rejects them rather than restated here:**
confidence inside `ExplainableDecision` (decision 8), the definition per item on `/scored-risks`
(decision 10), the definition declared beside `build_match_key` (decision 10), a fourth `MatchKey` field
(decision 4, and ADR-0029 decision 4 before it), two enums held equal by a test and a bare `str`
crossing (decision 3).
