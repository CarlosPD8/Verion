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
