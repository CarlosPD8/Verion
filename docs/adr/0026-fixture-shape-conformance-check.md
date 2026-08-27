# ADR-0026 — Checking a hand-written fixture's shape against the committed corpus

## Status

Accepted — 2026-08-27 (M5.3).

Written and accepted **before any of M5.3's fixtures or check code existed**, which is the
ordering ADR-0023's 2026-08-26 amendment adopted and ADR-0025 followed, and for the reason
those two give: a decision taken by the session that also writes its tests is taken by whatever
makes those tests pass. Every figure below was measured before this document was drafted, at
`444cd4635ef9ba0bef96a5aa702d48fe176003a4`.

## Context

M5.3 builds "a curated fixture set (deliberately vulnerable sample app findings) with expected
correlation groupings, used as a regression suite" — a proof artifact this roadmap explicitly
intends to put in front of people. **G19** is `assigned → M5.3` on the hazard that makes that
dangerous: synthetic data whose *shape* differs from production makes the artifact demonstrate
correlation over data the system will never see.

That is not an abstract worry here, because **M5.3's own roadmap entry already gives the
instruction in writing**:

> Semgrep findings carry `cwe = None` in production until G6 is resolved, so a fixture set
> giving them CWEs proves a signal that does not exist.

Nothing in this repository can verify that instruction. It is prose beside a fixture set, which
is the arrangement **G20** exists to name: a property two documents assert and no test asserts,
so it changes silently. This ADR decides what to build instead, and — as importantly — what the
thing built may and may not be said to establish.

Three prior decisions bear directly and are **cited, not re-argued**: ADR-0020's
`### 4. Three test layers hold the agreement, and none needs editing when a field is added`
(the shape this check is deliberately *not*), ADR-0023's `### (b) Where the conformance check
lives, and the constraint it imposes` (why a third hand-written copy is refused), and ADR-0023's
`### (c) What this does not detect` (the register in which a partial check states its own
bounds).

## Decision

### 1. A sample-based conformance check, not a derivation

M5.3's check compares a hand-written fixture's **field-presence profile** — for each field,
whether it is populated — against a profile **derived at run time from the three committed real
fixtures** in `tests/fixtures/scanners/`, mapped through the real mappers.

**Every profile row carries its denominator in the check's own output**: semgrep 1, trivy 20,
zap 13. A reader of a failure message sees that Semgrep's rows rest on a single finding, without
having to go and count.

This is the whole of the decision, and the two prohibitions below are as load-bearing as the
construction, because both describe it as something stronger than it is.

**Do not describe this as the shape of ADR-0020 decision 4.** Its first two layers compare
*declaration to declaration* — `FindingModel.__table__.columns` against a partition,
`_REFRESHED_COLUMNS` against `dataclasses.fields` and `inspect.signature` — and are exact and
total by construction. Its third is a **behaviour** layer, which does run against constructed
data, and the difference from this check is still decisive: it asserts a whole-object equality
against `merge_observation`, so the constructed input is an *argument to a total comparison*
rather than the source of the expected answer. Here the corpus **is** the expected answer.
Borrowing the name would import a guarantee this check does not have, and the guarantee is
precisely what a reader would rely on.

**Do not describe this check as total.** It is not, and section 3 below states its bounds in the
register ADR-0023's `### (c)` established, for the reason that ADR gives: a check described as
total and then found partial is worse than one described accurately.

#### The measured ground, which is two different claims and not one

These are stated separately because written in parallel they read as one measurement with two
columns, and they are not — the first is about how a mapper **constructs** a field, the second
is about whether a row is **structural or data-dependent**. Both were established by reading the
three mappers at the pinned SHA; what each *asserts* is labelled inside it, and the labels
differ, which is the point.

**(i) MEASURED. No ALWAYS row in any tool is constructed unconditionally by its mapper. Eleven
of eleven are data-derived, with no exception.** Every ALWAYS row could be `None` for a different
target: `file_path`, `start_line` and `end_line` come out of Semgrep's result body; Trivy's
`package`, `installed_version` and `file_path` are conditional expressions and its `cwe` and
`cvss` read `CweIDs` and `CVSS`; ZAP's `http_method` reads the instance, its `cwe` reads the
alert's `cweid`, and its `url` reads the instance's `uri` **falling back to the site's `@name`**.
**So ALWAYS is a property of this corpus and not of the code**, which is exactly what makes the
check sample-based rather than a restatement of the mappers.

**(ii) STRUCTURAL for most NEVER rows; MEASURED for exactly two.** A NEVER row is structural when
the mapper omits the field from its `Location(...)` call, or writes an unconditional literal
`None`. There are four such literals under three comments: *"Semgrep emits no CVSS at all."* in
`mappers/semgrep.py`; *"Trivy has no OWASP category concept."* in `mappers/trivy.py`; and
*"ZAP's traditional-json report carries no OWASP category and no CVSS."* in `mappers/zap.py`,
which covers two of the four. **The only two data-dependent NEVER rows in the entire profile are
Semgrep's `cwe` and `owasp_category`** — the mapper reads both from rule metadata, under the
comment *"tracked as G6, not worked around here by inventing a value"*, and the pinned ruleset
declares neither.

Semgrep's `cwe` is therefore **the profile's load-bearing row**: it is the one this check exists
to mechanise, it rests on `n = 1`, and it is data-dependent. See *Consequences*.

### 2. The partition is asserted, and this says which parts of the assertion can fail

- **Union against the declaration — LIVE.** The profile's field set equals
  `dataclasses.fields(Location)` plus the three `Finding` scalars `cwe`, `owasp_category` and
  `cvss`. A new `Finding` or `Location` field that no classifier bucket accounts for fails here
  rather than arriving silently. **This is adjacent to the "Added fields" hole ADR-0023's
  `### (c)` names and is not the same thing, and the gap between them is worth stating:** that
  bullet is about a new field that *should be a matching signal* reaching the key silently, and
  nothing here can tell a matching signal from any other field. What this layer buys is that the
  field's **existence** stops being silent. Whether it belongs in the key remains exactly as
  unchecked as that ADR says it is.
- **Disjointness — INERT, and deliberately not asserted.** The classifier is an
  `if`/`elif`/`else`, so no field can be placed in two buckets. Asserting it would test the
  language. It is written down here so that the absence reads as a decision rather than an
  omission.
- **Expected membership — LIVE, and the one that catches a re-capture.** Written as pinned
  literals against data read at run time: a re-capture that moved `parameter` to 13/13, or that
  made a currently-ALWAYS field partial, fails here. **This is the
  `test_the_real_cwe_cardinality_is_one_apart_from_a_single_two` construction, not a
  free-to-drift list** — the distinction ADR-0018 decision 4 argues at length and G20 contrasts
  against the unguarded identifier measurement. Naming which it is matters, because the two look
  identical in a diff.

### 3. What this check cannot assert

Said as plainly as ADR-0023's `### (c)`.

- **Id shape — and no corpus can supply it.** Ids come from `IdGeneratorPort`, so the property
  G19 was opened over (production ids are UUIDs and do not cluster; sequential ones changed a
  query plan and a benchmark by two orders of magnitude) is not a property of any captured
  scanner output. **Rule 9 remains its only source.**
- **The value shape of any field.** The profile records populated-or-not. A fixture whose
  `file_path` is `"a.py"` where production emits a repository-relative path, or whose `rule_id`
  is a synthetic label rather than the tool's own identifier, conforms.
- **Cardinality, ordering, distribution and width** — the four properties G19 names as the ones a
  planner reads, and a matcher with them.
- **ZAP's `parameter`, which is SOMETIMES (4/13).** It is excluded **by the rule** — a partial row
  constrains nothing — rather than by a hand-written exception, and **the exclusion is named in
  the check's output** so that a reader of a passing run knows the field was not examined.

Two sentences this section must carry, because both are readings that will otherwise be made:

**Shipping this check does not discharge G19.** The originating defect — id shape — is untouched
by anything here, and no corpus can supply it. What this ADR does discharge is narrower and is
stated as exactly that: the instruction *"State which properties of real findings the fixtures
reproduce and which they do not"*, which is not G19's own text but M5.3's, in the roadmap bullet
beginning *"Concretely: real ids are UUIDs (rule 9)"*. **Whether that satisfies G19's assignment
to M5.3 is not this document's to declare** — a register entry's status is settled in the
register, in the form G6 uses, whose status line reads *"open — the M5.1 assignment is
discharged, the gap is not"* over its own `Discharge (M5.1):` field. G19 carries no such field
today, and this ADR does not add one.

**M5.3 does not improve the denominators.** The profile is derived from the committed corpus, so
Semgrep stays at `n = 1` after this issue closes. Feeding M5.3's own fixtures into the profile
would make the fixture set the measure of its own generator, which is G19 exactly, stated in one
line.

### 4. M5.3 writes ZAP-shaped fixtures

MEASURED over the committed corpus through the real mappers and the shipped match key: of the
**seven signal-bearing groups, four are ZAP `url` groups** — `http://target.example:8080/` (5),
`…/calculate?expr=2*3` (4), `…/robots.txt` (2), `…/sitemap.xml` (2) — the other three being
Trivy `package` groups (urllib3 12, Werkzeug 6, Flask 2). And **zero hand-written ZAP-shaped
`Finding`s exist anywhere in `tests/`.**

A conformance check run over a suite containing no ZAP fixtures is **silent on ZAP by absence
rather than by conformance**, while reporting success — over the tool that carries four of the
seven signal-bearing groups. Stated by group count deliberately, because the finding count runs
the other way: ZAP is 13 of 33 grouped findings, and a sentence claiming both would be true of
neither.

**The intersection, stated once because it is easy to miss and it bounds the decision:** the tool
being added is the tool with the only partial field. Ten of ZAP's eleven profile rows are checked
— three ALWAYS (`url`, `http_method`, `cwe`) and seven NEVER — and **`parameter` alone is
unconstrained, because a SOMETIMES row constrains nothing.** So a ZAP fixture set putting
`parameter` at 0-of-N or at N-of-N passes either way. Adding ZAP fixtures closes an absence
across ten rows; it does not make the check say anything about the eleventh.

### 5. Scope: M5.3's own fixture module, named explicitly

The check takes its input from M5.3's fixture module by explicit reference. **It does not sweep
`tests/` with an exclusion list.** That list would be a third copy, free to drift from both sides
— the argument ADR-0023's `### (b)` already makes against a hand-written expected-annotation list
— and it would grow an entry every time an unrelated test constructed a `Finding` for its own
reasons.

**Divergences already in the tree are recorded, not corrected.** See **G40**.

## Consequences

**The profile is derived from a PASSIVE-plan corpus, and it goes stale silently. → G39.**
Nothing in the ZAP adapter or the ZAP mapper branches on the scan plan — but the plan determines
the report's content and the mapper reads content, and `parameter` is where that shows. The
committed capture's `4/13` is a fact about a spider-plus-passive plan (see
`tests/fixtures/scanners/README.md`'s section *"ZAP ran passive-only — the absence of an
injection finding is by design"*).

**What M5.4 moves is production, not the profile — and that is the whole hazard rather than a
qualification of it.** The profile is derived from the *committed* fixtures, so shipping an
`activeScan` job changes what ZAP emits against a real target and changes nothing this check
reads. `parameter` stays at 4/13, the assertions stay green, and the profile goes on describing
a scan plan production no longer uses. **The harm begins at the plan change and only becomes
visible at a re-capture** — which is the one event that would move the row and turn the pinned
membership literal red.

**The G6 dependency is the same shape, on the other load-bearing row, and it is why G39's
trigger is not keyed on ZAP.** Semgrep's `cwe` is NEVER *by data at n = 1*. Resolving G6 means
changing the pinned Semgrep ruleset so it declares metadata — again a change to production that
leaves the committed fixture, the profile and the assertion all untouched, so **this check goes
on asserting `NEVER` while production populates the field.** Both rows fail the same way and on
the same schedule: silently at the configuration change, visibly only if somebody re-captures.
G39's trigger therefore names **any change to a pinned scanner ruleset or scan plan** as well as
any re-capture — a trigger listing only the plan and the re-capture would miss G6 entirely,
because a ruleset change is neither.

**The reciprocal of G31, and this side of it is the unwritten one.** M5.3's ZAP fixtures will
carry full urls and will therefore encode the pre-M5.4 grouping. M5.4's entry already carries
*"Re-read G31 before shipping the `activeScan` job"*; the other side of that coupling — that
somebody is about to *write* fixtures which bake the current keying in — had no home until this
paragraph.

**A red suite after a re-capture is the guard working, not a brittle test.** Stated so the next
reader does not loosen it. This is the argument G20's `Note (M5.1)` makes: the G23 capture
brought `CVE-2024-49767` with two CWEs, and
`test_the_real_cwe_cardinality_is_one_apart_from_a_single_two` — whose own docstring records that
it is deliberately red at commit `00708b9` — went red rather than silently widening the evidence
an accepted ADR rests on. **The guarded measurement announced its own invalidation, and the
unguarded identifier measurement beside it could not.** A membership assertion that fails after a
re-capture is this check doing the only thing it was built to do.

**Acceptance criteria for the implementation stage — not work for this commit.** Each of the two
live assertion layers in decision 2 is **mutation-verified separately, and the mutation is
declared**. A single "verified by mutation" over the check as a whole would pass on the strength
of the membership layer while the union layer sat dead, which is G33's shape — a green
conformance test over a fraction of its own subject — arriving one document later.

**On the numbering.** `0024` is reserved for M5.4's scan policy and this ADR takes `0026`, so a
reader arriving here and finding no `0024` is looking at a reservation rather than a gap. See
`docs/adr/README.md`'s paragraph beginning *"Two numbers are reserved and not yet created"*,
which records both reservations and which roadmap entry claims each.

## Alternatives considered

**1. Prose in the fixture module's docstring, saying what the fixtures reproduce.** Rejected as
insufficient rather than as wrong — this ADR is partly that prose, and G19's own deferral
rationale accepts a documented habit where no mechanical check can exist. But a check *can* exist
for field presence, and G20 is the standing record of what happens to a fixture property that
only documents assert: the M5.1 re-capture moved that entry's element count from 30 to 39, and its
own second note records the superseded `30` surviving afterwards in **three further places**,
found one at a time by separate passes and by no gate.

**2. Derive the fixtures from the corpus instead of checking them against it.** Rejected. A
fixture set generated from the committed captures is the committed captures with different ids,
which reproduces nothing M5.3 needs — the suite exists to express *expected groupings* over
chosen cases, including negative ones.

**3. Feed M5.3's own fixtures into the profile as additional samples.** Rejected as G19 in one
move: it would raise Semgrep's denominator using the very data whose shape is in question, and
the check would then pass by construction.

**4. Sweep all of `tests/` with an exclusion list.** Rejected in decision 5, on ADR-0023
`### (b)`'s third-copy argument.

**5. Assert value shape as well as presence.** Rejected for this issue, not in principle. It
needs a decision per field about what production's shape *is* — and for `file_path` and `rule_id`
that question is G9's and G10's, both resolved in ways that make the answer depend on adapter
invocation rather than on anything a fixture can carry. Presence is the part that can be settled
against the corpus today.
