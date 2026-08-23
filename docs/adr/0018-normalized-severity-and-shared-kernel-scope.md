# ADR-0018: Normalized severity, unsourced fields, and what `shared_kernel/` takes

## Status

Accepted

## Context

M4.1 builds `Finding`, `Evidence` and the three per-scanner mapping functions. Those mappers have to answer a question the roadmap states in one line and that turns out to have consequences in M5, M6 and M8: **`Finding.severity` is one field, and three tools report severity on three incompatible scales.**

- Semgrep: `ERROR` / `WARNING` / `INFO`, on `extra.severity`.
- Trivy: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN`, on `Severity`.
- ZAP: **no severity field at all.** The traditional-json report carries `riskcode` (`"0"`–`"3"`) and a display string `riskdesc` of the form `"Medium (High)"` — risk, then confidence.

The same question arrives again for `cwe`, `owasp_category` and `cvss`, which the three tools populate in different, partly-empty subsets.

**This ADR is written against captured output, not against documentation.** M4.1's first task was capturing real Semgrep 1.173.0, Trivy 0.74.0 and ZAP 2.17.0 output; every count and field claim below was measured against `tests/fixtures/scanners/`, whose README records provenance and byte counts. That ordering was deliberate and it paid for itself immediately — the ZAP row of the mapping table this issue started with named a `High`/`Medium`/`Low`/`Informational` field that does not exist in the report.

Three facts from that capture are load-bearing here:

- **Maximum CWEs per element is 1, on every tool.** Trivy emits exactly one `CweIDs` entry on all 12 vulnerabilities; ZAP's `cweid` is a scalar; Semgrep's `extra.metadata` is `{}`.
- **This project's pinned Semgrep ruleset declares no metadata at all**, so every Semgrep finding in production carries no CWE and no OWASP category. Registered as **G6**.
- **Semgrep's `extra.fingerprint` and `extra.lines` are both the literal string `"requires login"`** for anonymous Semgrep OSS, and this repo sets no `SEMGREP_APP_TOKEN` anywhere. That is a property of the deployment, not of the capture. Registered as **G7**, because it reverses on a config change: a token makes `lines` the matched source line, inside a payload M4.5's endpoint returns.

**The Semgrep fixture is degraded in two independent ways, and a reader comparing them will conflate them if this is not said explicitly.** The empty `metadata` (no CWE, no OWASP — G6) is a property of the *pinned ruleset*; the `"requires login"` fields (G7) are a property of the *missing token*. Neither fix touches the other. In particular, **the CWE cardinality measurement below is unaffected by the token**: `metadata` is not token-gated, so Semgrep's contribution to that measurement would be zero CWEs with or without one, and the maximum of 1 comes from Trivy and ZAP. Setting a token would not change the decision in section 4; widening the ruleset could, which is why G6 names re-reading it as the trigger.

## Decision

### 1. The normalized scale is six members, and `UNKNOWN` is one of them

```python
class Severity(StrEnum):
    CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN
```

| normalized | Semgrep | Trivy | ZAP `riskcode` | why |
|---|---|---|---|---|
| `CRITICAL` | — | `CRITICAL` | — | only Trivy has a level above its own HIGH |
| `HIGH` | `ERROR` | `HIGH` | `3` | each tool's top actionable level |
| `MEDIUM` | `WARNING` | `MEDIUM` | `2` | direct |
| `LOW` | — | `LOW` | `1` | Semgrep has no LOW |
| `INFO` | `INFO` | — | `0` | non-actionable; kept distinct from `LOW` so M6 can drop it without dropping real LOWs |
| `UNKNOWN` | *(unrecognised)* | `UNKNOWN` | *(unrecognised)* | Trivy emits it literally |

**Semgrep's `ERROR` maps to `HIGH`, not `CRITICAL`**, and the asymmetry is the point: Trivy choosing `HIGH` means it had `CRITICAL` available and declined it, while Semgrep never had the option. Reserving `CRITICAL` for tools that can express it keeps that distinction real instead of inflating every SAST finding to the top of the scale.

**`UNKNOWN` is carried through rather than folded into `LOW` or `MEDIUM`.** Collapsing it would have a mapper invent a Risk Engine input — rule 5's "scoring must stay traceable to explicit inputs", violated one layer *upstream* of the Risk Engine, where nobody reviewing M6 would look for it.

**ZAP's severity is read from `riskcode`, not by parsing `riskdesc`.** `riskdesc` is a display convention that can change format; `riskcode` is the enumerated value.

**An unrecognised severity string degrades to `UNKNOWN` rather than raising, and that is the opposite of what ADR-016 decision 2 does with an unrecognised tool name — deliberately.** A tool name is deployment configuration this project controls, so a wrong one means a broken deployment and should fail loudly. A severity string is upstream data from a tool that can add a level in any release, and raising would take down normalization for every *other* finding in the same scan — the partial-failure corruption `PRODUCT_SPEC.md` §12 forbids, arrived at through a validation rule.

### 2. `Severity` lives in `shared_kernel/`, and the criterion is written down

ADR-016 decision 4 put `ScannerTool` in `shared_kernel/` because two modules had to agree on a vocabulary and neither could import the other's `domain/`, and it **recorded** that widening rather than doing it silently — "a real change in that package's character". That did not leave the package closed. It set a test, and `Severity` meets it with more consumers than `ScannerTool` had: `normalization` constructs it, `risk_engine` orders by it for `RiskReasoning.severity_signal`, M5 ranks correlated findings, M8 filters on it, and none of those may import `normalization`'s domain (rule 3).

`Severity` is the second entry, so the criterion is stated explicitly here and in `ARCHITECTURE.md` §7 — without one, the third arrives by habit:

> `shared_kernel/` takes **closed vocabularies** — enumerations — that two or more modules must **compare or order**, not merely **transport**. Entities and structures stay with the module that owns them and travel by indirect import.

**The scope clause is load-bearing rather than a hedge.** An enum's *members* are the shared knowledge: to write `severity >= Severity.HIGH` you must import the type by name. A structure's *fields* are reachable by attribute without importing the type — `scanning` reads `connected_repo.url` and `.provider` today without `ConnectedRepo` living in `shared_kernel/`, the precedent ADR-0017 cited. Without the clause the criterion would pull in `Location`, then `Finding` itself, and hollow out `normalization/domain/`.

Applied three times in this issue, twice in the negative: `Severity` in (decision 2), `Confidence` out (decision 5), `Location` out — M5 will compare locations, but it compares fields, not the type.

**`Severity` overrides `__lt__`/`__le__`/`__gt__`/`__ge__`, and this is not incidental.** A plain `StrEnum` inherits `str`'s ordering, under which `Severity.HIGH >= Severity.CRITICAL` is `True` because `"high"` sorts after `"critical"`. That is the exact expression this decision argues the type exists to make possible, so inheriting it silently wrong would place a lie inside `risk_engine` — the module `CLAUDE.md` singles out for disproportionate test rigor. A non-`Severity` operand raises `TypeError` rather than returning `NotImplemented`, because `NotImplemented` would let Python fall back to the reflected `str` comparison and restore alphabetical ordering through the back door. Both operand orders are covered: Python gives a subclass's reflected method priority, so `"zzz" > Severity.HIGH` also routes to `Severity.__lt__` and raises. Verified directly, not assumed, and pinned by a test.

Equality is deliberately untouched, so persistence and JSON keep working as they do for every other `StrEnum` here.

**But equality and ordering do not survive a boundary equally, and the asymmetry is worth stating because the sentence above would otherwise read as blanket reassurance.** `Severity.HIGH == "high"` is `True`, so a value read back from a `String` column or a JSON body still compares equal; `Severity.HIGH >= "high"` **raises**. Ordering is the half `risk_engine`, M5 and M8 actually use. So: **a severity crossing a persistence or HTTP boundary must be reconstructed as `Severity(...)` before it is compared.** M4.3's repository hydration and M4.5's query parameters are the two places that will meet this first, and both have it in their roadmap entries. It fails loudly rather than silently, which is the design intent — but "loudly" only helps if somebody knows to expect it.

### 3. `native_severity` keeps what the mapping discards

The mapping's real loss is **relative position within each tool's own scale** — see the `ERROR`/`HIGH` case above. It is not recoverable from `severity` alone, which is an argument for M6 keeping `Finding.source` as a scoring input, not for distorting the table.

`Finding.native_severity: str` carries the tool's literal value (`"ERROR"`, `"CRITICAL"`, `"Low"`). Recovering it from `Evidence.raw_payload` instead would require a downstream reader to JSON-parse a blob **and know each tool's field name** — Semgrep's `extra.severity`, Trivy's `Severity`, ZAP's `riskcode`. That is per-tool knowledge downstream of `normalization`, exactly the leak `CLAUDE.md` forbids. It is a plain `str`, not a fourth enum: nobody compares native severities across tools, so it fails the compare-or-order criterion by construction.

The collapse is therefore lossy for **ordering** and lossless for **provenance** (FR-9).

### 4. A field with no source is `None`, never `""` and never a guess

| field | Semgrep | Trivy | ZAP |
|---|---|---|---|
| `cwe` | `extra.metadata.cwe`, only if the rule declares it | `CweIDs` | `cweid`, a bare number |
| `owasp_category` | `extra.metadata.owasp`, same caveat | — | — |
| `cvss` | — | `CVSS`, keyed by vendor | — |

Same reasoning ADR-016 decision 2 used to make `raw_output` nullable rather than `""`: an empty string conflates "the tool said nothing" with "there is nothing", and M6 would have to guess which.

**`cwe` is a single `str | None`, and that is measured rather than assumed.** The maximum across every element of all three real fixtures is 1. An earlier draft reached the same shape by taking the first of a list, on the reasoning that a list makes "same CWE" ambiguous for correlation — that reasoning was wrong and is recorded here so it is not repeated: set correlation is well defined (non-empty intersection) and strictly more expressive than equality, so taking the first would not remove ambiguity, it would manufacture silent false negatives in M5 whenever the shared CWE was not first.

**What the measurement is and is not evidence for, since a single number invites over-reading.** It is a fact about *these three targets* — one `requirements.txt`, one Python file, one static HTML page — not a fact about the tools. Other ecosystems demonstrably emit several CweIDs per advisory. So the decision is "one value is right for the data this project has seen, and widening is cheap if that changes", not "these tools emit one CWE". Two tests carry that distinction because one cannot: **`test_every_real_vulnerability_carries_exactly_one_cwe` guards the fixture** — the assertion is a literal and the fixture is data read at run time, so a re-capture bringing two fails it (verified by mutation, not assumed) — while **`test_multiple_cwes_keep_the_first_and_lose_none` guards the mapper's behaviour** against a synthetic two-CWE vulnerability, so the truncation is specified rather than incidental. Without the second, `next(iter(...))` would be an unexamined silent drop and the first production npm scan would be where anyone found out. Nothing is discarded either way: the full list stays in `raw_payload`, so M5 can widen to set intersection later without a re-scan.

Spellings are canonicalised to `CWE-<n>`, because the three tools disagree and M5 compares across them: Trivy's `"CWE-20"`, ZAP's bare `"693"`, and a Semgrep rule's `"CWE-95: Improper Neutralization…"` must produce the same string or the comparison silently never matches. ZAP's `-1` and `0` are "none known" sentinels and become `None` rather than `CWE--1`.

**`cvss` is the CVSS **v3** base score, NVD first, and never a v2 score.** Trivy supplies both for older CVEs and they are different scales — a v2 6.8 and a v3 6.8 do not mean the same thing. Mixing them in one float would make M6's `severity_signal` compare incomparable numbers: a rule-5 violation dressed up as arithmetic. Vendor preference is `nvd`, `redhat`, `ghsa`, then any remaining vendor in sorted order, so the choice is deterministic and traceable rather than "whichever key came first". A CVE with only a v2 score yields `None`, which correctly means "no comparable score" and leaves `severity` unaffected.

### 5. What `Finding` deliberately does **not** carry

**`confidence` — deferred to M6.1.** The criterion from decision 2 answers in the negative, on two independent grounds.

*Comparison.* Nothing outside `normalization` compares confidence today, and nothing is scheduled to. `RiskReasoning`'s five signals are `severity_signal`, `exposure_signal`, `reachability_signal`, `asset_sensitivity_signal` and `environment_signal`; confidence is not among them, and `Risk.confidence` is an **output** M6 computes from those signals rather than an aggregation of finding confidences. The prospective-consumer argument that carries `Severity` — a named field of the domain model today, two milestones out — has no counterpart.

*Ordering.* Only ZAP supplies it, and in the JSON report it is an opaque numeric code (`"2"`, `"3"`), not the words. Its vocabulary mixes degrees (`High`/`Medium`/`Low`) with **states** (`Confirmed`, `False Positive`). Mapping `False Positive` onto `LOW` would tell M6 "weak evidence" when ZAP said "this is not a finding" — an inversion, not a lossy compression. A correct scale needs a separate state axis, and designing one now would mean designing it with no consumer to design against. Semgrep can supply `extra.metadata.confidence`, under the same G6 caveat as CWE; Trivy has no confidence concept at all.

There is deliberately no `native_confidence` either. `native_severity` exists as the **residue of a lossy transform**; confidence undergoes no transform here, so there is no residue. FR-9 is satisfied the way it is for every other unmapped field — `Evidence.raw_payload` holds the source element verbatim.

**`dedup_hash` — deferred to M4.2.** Computing one here would mean inventing the identity rule that issue exists to decide (**G5**), and M4.2 lands before M4.3 persists anything, so nothing is at risk from the wait.

Both absences are pinned by a test, so re-adding either is a deliberate act rather than a drive-by.

### 6. `Evidence.raw_payload` is a copy of the per-finding slice

Not a reference into `ScanResult.raw_output`, because a reference dangles by design here: `RunScanUseCase` upserts on `(scan_id, tool)` and a retry re-runs every enabled scanner (ADR-016 decision 1), so that blob can be replaced by a later attempt's output or nulled entirely if the retry's run of that tool fails. Once M4.2's identity model lands a `Finding` also outlives the scan that produced it. An index into a mutable, replaceable blob breaks silently, and silently is the worst way for evidence to break.

The cost is real: in the normal case where every element becomes a finding, `Evidence` roughly doubles the bytes a scan stores. Two things bound it, and one is M4.2's — attaching `Evidence` to the *deduplicated* finding rather than to each per-scan observation makes a finding seen in 300 scans store one payload instead of 300. A per-payload character cap bounds the pathological single element, mirroring `RunScanUseCase._MAX_FAILURE_REASON_CHARS`.

## Consequences

M4.2 receives a settled `Finding` shape with two holes deliberately left in it — identity and `dedup_hash` — plus the per-tool identity candidates the fixtures actually revealed. One of those candidates is now known to be unusable: **Semgrep's `fingerprint` is the constant `"requires login"`**, so it cannot serve as an identity input, and M4.2 would otherwise have discovered that after designing around it.

M6 inherits three things it must decide rather than inherit: what `UNKNOWN` severity means to a score (the enum's rank places it lowest for *sorting*, which is a display convention and not a judgment), whether confidence becomes a scoring input and on what scale, and whether `source` compensates for the relative-position loss in decision 3.

M5 gets a canonical CWE it can compare across tools, and a `Location` whose fields it can compare without knowing which tool produced either side.

`shared_kernel/` grows its second vocabulary entry and, for the first time, a written rule for admitting a third. The rule is stated as a criterion rather than a list, so it can be applied to a case nobody has thought of yet.

**G6 is opened**: the pinned Semgrep ruleset declares no metadata, so SAST contributes no CWE and no OWASP category in production. It fails silently — Trivy and ZAP both supply CWEs, so the gap is invisible unless someone groups by `source`.

`ARCHITECTURE.md` §4 changes shape: `Finding` gains `native_severity` and `title`, loses `confidence` and `dedup_hash` for now, and references `shared_kernel`'s `Severity`. §7 gains the criterion.

## Alternatives considered

**`Severity` in `normalization/domain/`.** The case is that only `normalization` constructs one today, and everyone else receives one attached to a `Finding` through a contract-legal indirect import — the shape ADR-0017 established when `ConnectedRepoRepositoryPort` returns `projects`' domain type to `scanning`. **True for transporting the value, false for comparing it.** `risk_engine` orders by severity, M8 filters, M5 ranks; none of that works with an opaque value. The moment `risk_engine` writes `if severity >= Severity.HIGH` it imports the type by name, which under this option lives in `normalization.domain` and is exactly what the `cross-module-risk-engine` contract forbids. It works until M6 and then forces the same move with more code on top of it.

**Folding `UNKNOWN` into `LOW` or `MEDIUM`** so the scale has five members. Rejected: it invents a Risk Engine input (rule 5), and it removes the safe landing place for a severity string a future tool release adds.

**A plain `StrEnum` with no comparison overrides**, ordering left to a `SEVERITY_RANK` map callers apply by hand. Rejected: `>=` still *works*, silently and alphabetically, and the failure mode is a wrong priority rather than an error. A rule people must remember at every comparison site is the kind of rule this project has repeatedly found unenforceable.

**`confidence: str | None` carrying the tool's native value.** Rejected as **worse than having no field**: it puts three vocabularies in one field of the *common* schema — ZAP's `"2"` beside Semgrep's `"HIGH"` — which is the scanner-format leak `CLAUDE.md` forbids, arriving through a field that looks normalized because it sits on `Finding`. It would invite a downstream `if finding.confidence == "HIGH"` that is silently wrong for two tools out of three.

**A `Confidence` enum now.** Rejected: no second comparer, and the degrees-versus-states problem means the scale would be guessed. ADR-016 decision 3's reasoning applies directly — pre-normalizing for a hypothetical consumer.

**`cwes: tuple[str, ...]`.** Not rejected on principle, and it is the right answer if the measurement changes; the measured maximum is 1 on every tool today, and `ARCHITECTURE.md` §4 says one. The test that pins the measurement is what makes revisiting this a deliberate act.

**Parsing ZAP's `riskdesc` string for severity** instead of reading `riskcode`. Rejected: `"Medium (High)"` is a display format, and it also embeds confidence, so a parser would have to split a human-readable string to recover two values that are already separate structured fields.

**A tagged union of three `Location` types.** Rejected: it forces every downstream reader to branch on which tool produced the finding, which is per-tool knowledge living downstream of `normalization` — the leak the whole common schema exists to prevent.

**Guarding against an all-`None` `Location`.** Implemented, then removed when a real ZAP site-level alert with an empty `instances` list disproved the premise that every finding is locatable. The guard turned real output into an exception raised mid-map, which would discard every other finding in the same scan. The alert now falls back to the site it is nested under — not a guess, since that nesting is ZAP's own statement of where the alert applies.

**One `Finding` per ZAP *instance* rather than per alert.** Deferred, not rejected. An alert has one `riskcode`, one `cweid` and one solution, while `instances[]` lists every URL the rule fired on — which is the occurrence/sighting concept **G5** says the model is missing. Splitting per instance now would pre-empt M4.2's identity decision. Every instance stays verbatim in the evidence, so M4.2 can revisit it with the full data.
