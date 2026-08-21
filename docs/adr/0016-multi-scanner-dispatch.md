# ADR-016: Multi-scanner dispatch, partial-failure semantics, and per-project scanner configuration

## Status

Accepted

## Context

M3.2, M3.4 and M3.5 each added exactly one scanner path end to end — `SemgrepAdapter`, `TrivyAdapter`, `ZapAdapter`. Only the first is wired: `platform/worker.py`'s `on_startup` builds `SemgrepAdapter` alone, and `RunScanUseCase` takes a single `scanner: ScannerPort`. A `Scan` can therefore only ever produce one `ScanResult`.

That is drift, not an unanswered design question. The schema and the architecture document already assume N tools per scan: `ScanResultModel`'s `UniqueConstraint(scan_id, tool)`, `ARCHITECTURE.md` §4's `raw_results: [ScanResult]  # one per tool that ran`, and §8's sequence diagram naming `ScannerPort (Semgrep/Trivy/ZAP)` as one participant returning "raw results (per tool)". Only the roadmap and the code diverged from that.

It is on the critical path for the next two milestones, which is why it was escalated from the Deferred gaps register (G1, confirmed at M3.4/M3.5/M3.6) into M3.7 ahead of M4. M4 designs the `Finding` schema and its per-scanner mapping functions; M5's `CorrelateFindingsUseCase` exists specifically to link findings originating from *different* tools. Neither is meaningfully exercisable while one scan yields one result.

Four questions have to be answered before any of that code can be written, and each one constrains what M4 and M5 can assume. They are answered together in one ADR because they are not independent — the dispatch shape determines what partial failure can even mean, and the target-kind question only exists because dispatch has to select scanners rather than being handed one.

## Decision

### 1. One arq job per `Scan`, scanners run concurrently

`RunScanUseCase` receives `scanners: Mapping[ScannerTool, ScannerPort]` and runs the enabled ones concurrently inside a single `run_scan` job, via `asyncio.gather` over per-scanner coroutines that never raise — each wraps its scanner in a `try` and converts any failure into that tool's `ScanResult`. Note this is *not* `return_exceptions=True`: capturing the failure inside each coroutine, rather than letting it propagate into `gather`, is what guarantees a sibling is never cancelled mid-run and never has output discarded that was about to succeed. Dispatch is **not** fanned out to one arq job per `(scan, tool)`.

The decisive argument is **snapshot coherence**, not job bookkeeping. Fan-out means each job performs its own `RepoCheckoutPort.checkout()`. A push landing between two of those jobs gives Semgrep and Trivy *different commits*. M5 correlates a Semgrep `file:line` against a Trivy dependency finding on the premise that both tools observed the same tree; fan-out lets that premise be false, silently, with no artifact recording that it happened. A single job checks out once and hands the same path to every repo-based scanner, so the premise holds by construction.

Secondary, and the reason M3.3 built it this way: a single job keeps `RunScanUseCase` the sole owner of `Scan` status. Fan-out turns scan completion into a distributed-completion problem — either a coordinator job, or a race-prone "last one out turns off the lights" check requiring row locks — for no gain that M4 or M5 can use.

`UniqueConstraint(scan_id, tool)` still earns its keep under this design: it is the mechanism that makes the per-tool upsert idempotent across retries. It anticipates N *rows* per scan. It does not require N *jobs*.

**arq's `job_timeout` must be set explicitly.** Concurrent wall-clock is `max()`, not `sum()`: ZAP 300s, Trivy 180s, Semgrep 60s, so a full three-scanner run is ~300s plus checkout. arq's default `job_timeout` is 300s (`arq/worker.py:204`, verified against the installed package per ADR-009), which would kill a legitimate three-scanner run at roughly the moment ZAP finishes — an intermittent failure that would look like a ZAP bug. `WorkerSettings.job_timeout` is set to 600s. Each adapter keeps its own hard timeout and explicit process kill (ADR-011 points 3 and 8), so arq's timeout is a backstop against a hung job, not the mechanism that bounds a scanner.

**Retry re-runs every enabled scanner, not just the failed ones.** Only `COMPLETED` short-circuits; `PARTIAL` does not. Re-running only the failures would pair a freshly-checked-out ZAP result with a stale Semgrep result from an older commit — the same snapshot incoherence rejected above, arriving through a different door. This is stated explicitly because it is the obvious place for a future change to "optimize" incorrectly, and because it extends M3.3's already-documented trade-off: a retry redoes real work, and buys correctness in that window rather than work-avoidance.

### 2. Per-tool outcome lives on `ScanResult`; `Scan.status` is derived

```
ScanResultStatus (new domain StrEnum): SUCCEEDED | FAILED

ScanResult
  id, scan_id, tool
  status:         ScanResultStatus
  raw_output:     str | None      # non-null iff SUCCEEDED
  failure_reason: str | None      # non-null iff FAILED
```

A tool that fails still gets a row. That row is what tells M4 the tool was attempted and failed, rather than never having been enabled — a distinction M4 cannot otherwise make — and it is what keeps the `(scan_id, tool)` upsert idempotent when a job is retried.

`raw_output` becomes nullable rather than being set to `""` on failure. An empty string cannot distinguish "ran, produced no output" from "never produced output", and M4 would have to guess which it was. The invariant is enforced in two places: a `__post_init__` on the frozen domain dataclass (pure Python, rule 1 clean), and a database `CHECK` constraint, following the same defensive-constraint idiom already used by `UniqueConstraint(scan_id, tool)` and `WebhookDeliveryModel`'s primary-key-as-dedup.

`ScanStatus` gains `PARTIAL`, derived once every scanner has returned:

| Outcome | `Scan.status` |
|---|---|
| every enabled tool succeeded | `COMPLETED` |
| some succeeded, some failed | `PARTIAL` |
| every enabled tool failed | `FAILED` |
| no tools enabled | `FAILED`, with a `Scan`-level reason |

**`Scan.failure_reason` is not overloaded.** It keeps exactly the meaning M3.3 gave it: a failure that occurred *before any tool ran* — no connected repo, no GitHub connection, an unsupported provider, a failed checkout. In those cases no `ScanResult` rows exist at all and `Scan.status` is `FAILED`, unchanged from today. On `PARTIAL`, `Scan.failure_reason` stays `None` and the per-tool `failure_reason` fields carry the detail. Two fields with disjoint meanings, rather than one field that has to be interpreted differently depending on status.

**What M4 queries.** `ScanResultRepositoryPort` gains a named method:

```python
async def get_succeeded_by_scan_id(self, scan_id: str) -> list[ScanResult]:
    """WHERE scan_id = :scan_id AND status = 'succeeded'"""
```

This is the real deliverable of this decision. M4 does not read `Scan.status` at all and does not filter the full result list by hand. `Scan.status` is a derived, human-facing summary; making it M4's source of truth would put a normalization pipeline downstream of a display field. The `CHECK` constraint pays off precisely here: every row this method returns is guaranteed to have non-null `raw_output`, so M4's per-scanner mappers take `str`, not `str | None`, and the "is this safe to normalize" question is answered by the query rather than by a convention M4 has to remember.

A blanket `Scan`-level `FAILED` when one tool fails would discard a succeeding scanner's output, which is exactly the state corruption `PRODUCT_SPEC.md` §12 forbids ("Scan orchestration must tolerate partial failure (e.g., ZAP times out but Semgrep succeeds) without corrupting project state"). This design satisfies that requirement by making the surviving output queryable, not merely present.

**Per-tool configuration errors are per-tool outcomes.** ZAP enabled with no target URL configured produces `ScanResult(tool="zap", status=FAILED, failure_reason=...)`; Semgrep and Trivy still complete normally and the scan is `PARTIAL`. An *unknown* tool name in configuration is a different class of problem — a deployment or configuration error, not a tool outcome — so it raises and the whole scan is `FAILED` with a `Scan`-level reason. The write path below validates against the known tool set, which should make this unreachable; it fails loudly rather than silently if it is not.

### 3. Scanner configuration is a `ScannerConfig` entity in `projects`, one row per project

```
scanner_configs
  id              String(36)  PK
  project_id      FK projects.id, UNIQUE
  enabled_tools   ARRAY(String)          -- e.g. ["semgrep", "trivy"]
  zap_target_url  String NULL
  updated_at      DateTime(timezone=True)
```

Not new columns on `SecurityContext`. The two have different lifecycles: `SecurityContext` is a *detected and user-confirmed description of the application*, re-derived by `BuildSecurityContextUseCase` whenever repo content changes. Scanner configuration is *operational configuration* that must survive that re-derivation. Folding it in would hand `BuildSecurityContextUseCase` and `UpdateExposureTagsUseCase` responsibility for state they do not own, and `exposure_tags` in particular is user-confirmed exposure annotation, not configuration.

**The table belongs to `projects`, and `scanning` reads it through a published port** — `projects/ports/scanner_config_repository.py::ScannerConfigRepositoryPort` — exactly as `RunScanUseCase` already reads `ConnectedRepoRepositoryPort` (rule 3). It is project configuration, and it does not migrate into `scanning` merely because `scanning` is its only consumer today.

**One row per project with explicit columns, rather than a normalized `(project_id, tool)` table.** The deciding factor is missing-row ambiguity, more than the normalization trade-off: in the normalized shape, a row that is not there cannot say whether the tool was disabled or was never configured, and resolving that needs a documented rule someone has to remember at every read site. `enabled_tools` as an explicit array has no such gap — present means enabled, absent means not.

`zap_target_url` is genuinely a wart: tool-specific configuration sitting in a generic entity — and it does not stay in the entity, it propagates into `RunScanUseCase`'s dispatch signature (see decision 4 for what that costs). It is accepted as debt with a verifiable exit condition rather than a vague one — **migrate to the normalized `(project_id, tool)` shape when a second tool needs tool-specific settings.** Not "when it feels messy". Note that this trigger may never fire inside MVP scope: `PRODUCT_SPEC.md` §9 lists "Additional scanners beyond Semgrep/Trivy/ZAP" as V2. (It could also fire from an existing tool — a per-project Semgrep ruleset replacing the app-level `Settings.semgrep_ruleset` would do it — which is why the trigger is written against *tool-specific settings* rather than against *new scanners*.) Pre-normalizing now would be paying complexity for hypothetical flexibility, the same reasoning ADR-014 used to reject a per-project webhook secret.

**Default when no configuration row exists: `["semgrep", "trivy"]` enabled, ZAP off.** Expressed as a domain-level constant, not as a backfill migration, so existing projects work immediately with no stale rows to keep in sync. The asymmetry is deliberate and security-derived, not a convenience: Semgrep and Trivy need only a checked-out repo — no user-supplied target, no SSRF surface — so they are safe to run without explicit opt-in. ZAP requires a target URL that only a user can supply, so it structurally cannot be defaulted on.

That default lives in `scanning` (`domain/scanner_dispatch.py`), not in `projects` beside `ScannerConfig`. Its rationale is a property of the scanners — what they take as a target and what that exposes — which is `scanning`'s knowledge; `projects` records what a user *chose*, and this decides what happens when they chose nothing. Rule 3 forces the same split anyway, since `scanning` may import another module's ports but not its domain. The distinction between "never configured" (`None` → default) and "configured to run nothing" (an empty list → run nothing, and the scan fails with `NoScannersEnabled`) is made in exactly one function, `resolve_enabled_tools`, so no caller can collapse the two with a truthiness check.

**A write path ships with this issue** — `UpdateScannerConfigUseCase` and an owner-gated `PUT /projects/{project_id}/scanner-config`. Without it, ZAP dispatch would be dead-by-construction: code that cannot execute in a running system because nothing can write the configuration that enables it. That is a different thing from this project's previous deferrals (persistence in M2.1, `di.py` wiring ahead of a route), each of which left a coherent system with a piece missing and what existed working; it is what M3.4 declined to do when it refused to add a `run_trivy_scan` to `worker.py` with nothing enqueueing it. There is also a cost specific to this issue: M3.7 exists to demonstrate that one trigger fans out to multiple scanners, and that demonstration is incomplete if ZAP can only be enabled by hand-inserting rows into Postgres.

The write path is owner-gated through the existing `require_owner` (`projects/domain/authorization.py`), matching M2.3's precedent that write actions on project data require OWNER while reads are member-level. Enabling a scanner costs real compute and can point an attack tool at a URL; it is squarely a write action.

**The write path checks well-formedness only — an http(s) scheme and a hostname — and deliberately does *not* reject private or loopback targets.** It cannot reuse ADR-013's `validate_target_url_syntax` in any case: that function lives in `scanning/domain/`, which `projects` may not import (rule 3). But even with the boundary out of the way, duplicating the private-range check here would be the wrong call. Rejecting internal targets at configuration time would make the stored URL *look* pre-approved, and that impression is exactly what would later make `ZapAdapter.run()`'s gate seem redundant. It is not redundant: DNS can rebind between configuring a target and scanning it, so the resolved-IP check has to run at scan time, every time.

One check the write path *does* make, which is not an exception to any of this: it rejects `user:pass@host`. That is a rule-12 concern, not an SSRF one — `urlparse` leaves `.hostname` populated when userinfo is present, so a credential would otherwise pass the scheme and hostname checks and be persisted in `scanner_configs.zap_target_url`, returned by this resource's response schema, and echoed into a stored `ScanResult.failure_reason` if it ever reached the scanner. Refusing it says nothing about where the target resolves, so it pre-approves nothing. `scanning`'s own gate rejects the same shape; its message was also changed here to stop quoting the offending URL back, since as of this issue that message can be persisted.

So both of ADR-013's gates still run as the literal first lines of `ZapAdapter.run()`, unchanged, against a persisted and previously-"validated" target — and a target that is well-formed but internal is accepted at write time and rejected at scan time, surfacing as that tool's `failure_reason`. Slightly later feedback, in exchange for one gate that is unambiguously the only gate. A unit test pins this behaviour in place specifically so that "hardening" the write path is a deliberate, visible decision rather than an unnoticed one.

### 4. `ScannerPort` gains `tool` and `target_kind`

```python
class ScannerTargetKind(StrEnum):  # scanning/domain/scanner_target_kind.py
    REPO_PATH = "repo_path"
    URL = "url"


class ScannerPort(Protocol):
    tool: ScannerTool
    target_kind: ScannerTargetKind

    async def run(self, target: str) -> RawScanResult: ...
```

`tool` answers the question the roadmap asked: dispatch must select scanners by name, but `tool` was previously known only *after* `run()` returned, inside `RawScanResult`. It is implemented as a class-level constant on each adapter, and each adapter constructs `RawScanResult(tool=self.tool, ...)` so the identity used for selection and the identity used for persistence cannot drift apart.

It is typed as a new `ScannerTool` `StrEnum` rather than a bare `str`, and that enum lives in `shared_kernel/scanner_tools.py`. Two modules have to agree on this vocabulary — `projects` validates it when configuration is written, `scanning` selects on it at dispatch — and neither may import the other's `domain/` (rule 3). The alternative is each module keeping its own literal set of the same three names, where adding a scanner means remembering to edit both and nothing catches you if you don't. `shared_kernel/` previously held only cross-cutting `Protocol`s (`ClockPort`, `IdGeneratorPort`); this is a deliberate, small widening of it to shared vocabulary, and it is what makes the worker's registry `dict[ScannerTool, ScannerPort]` — a typo there is a type error rather than an `UnknownScanner` raised at scan time.

`target_kind` answers the half of that question the roadmap did not name. `SemgrepAdapter` and `TrivyAdapter` take a local, already-checked-out filesystem path; `ZapAdapter` takes a live target URL. `ScannerPort.run`'s existing docstring records this asymmetry but leaves it to each caller to know which is which — workable when there was one hard-coded scanner, not workable when dispatch is generic. Branching on `tool == "zap"` inside `RunScanUseCase` would special-case an integration inside application logic, which is exactly what rule 4 forbids; `target_kind` makes the distinction *data carried by the port* rather than a conditional on a name, which is what rule 4 asks for.

**How far that actually goes, stated precisely rather than generously.** A future `REPO_PATH` scanner drops in with no dispatch change at all. A second `URL` scanner does not: `RunScanUseCase` takes `zap_target_url: str | None` and routes it in the `else` branch, so a second URL-kind adapter would silently be handed ZAP's target. The *shape* of the routing is generic; the *value* is still named per-integration inside application logic. This is the same `zap_target_url` wart recorded as debt in decision 3, and it reaches further than that entry implies — it is in the use case's signature, not only in the config entity. It resolves the same way and on the same trigger: when a second tool needs tool-specific settings, the normalized `(project_id, tool)` config makes the target a per-tool lookup and this parameter goes away with it. Recorded here because "a future scanner declares its kind and dispatch needs no change" is true of exactly half the cases, and the untrue half fails silently — the second URL scanner would run, succeed, and produce a real `ScanResult` for the wrong target. Also tracked as **G2** in `ROADMAP.md`'s Deferred gaps register, which is where the `Blocks-if-unresolved:` field and the escalation check live; this paragraph explains the design, that entry is what will actually get re-read.

It also buys a concrete property: `RunScanUseCase` performs the checkout only when at least one enabled scanner declares `REPO_PATH`, so a ZAP-only project never clones the repository at all.

## Consequences

M4 gets an unambiguous contract. `get_succeeded_by_scan_id(scan_id)` returns exactly the rows that are safe to normalize, with `raw_output` guaranteed non-null by a database constraint rather than by convention. M4 never has to interpret `Scan.status`, and never has to distinguish "this tool wasn't enabled" from "this tool failed" — the presence of a `FAILED` row answers that.

M5 gets the guarantee it actually depends on: every `ScanResult` under one `scan_id` came from the same checkout, so correlating a Semgrep location against a Trivy dependency is well-founded. That guarantee comes from the dispatch shape, and it is the reason fan-out was rejected.

The cost is a single job holding several concurrent subprocesses (two native processes plus a Docker container) for up to ~300s of wall clock, and a worker slot occupied for that whole time. `WorkerSettings.max_jobs` bounds how many scans run at once; per-scan concurrency is bounded by the number of enabled tools. This is an acceptable MVP shape and is the direct trade for snapshot coherence — a fan-out design would parallelize better across scans while making cross-tool correlation unsound.

`PARTIAL` is a new status that every downstream consumer of `Scan.status` must handle. Today that is the scanning API surface; M8's dashboard will be the first real consumer. Written down here because "a status nobody handles" is a normal way for a new enum member to cause a bug later.

**A behaviour change worth calling out: a scanner failure no longer re-raises, so arq no longer retries it.** In M3.3 a single scanner's failure propagated out of `RunScanUseCase`, and arq's retry/backoff applied. That is now wrong: a retry re-runs *every* enabled scanner (see decision 1) and could turn a succeeded result into a failed one, discarding output that was already good — the corruption §12 forbids, arrived at by way of a retry policy. A tool failure is instead a terminal, recorded outcome, and re-triggering is the user's or CI's call. Failures *before any tool runs* — checkout, missing repo, missing connection, no scanners enabled, an unknown scanner — still re-raise and still retry, which is where automatic retry was earning its keep anyway (a checkout that failed on a network blip). The trade accepted here is that a transient scanner failure now needs a re-trigger rather than recovering on its own.

CI runtime grows. The multi-scanner integration test runs all three real scanners, adding one more container-bound ZAP run to a `Tests (pytest …)` step already dominated by them (26.5s of a 37.3s run, 71%, in 2 tests out of 245). ZAP is included deliberately rather than for completeness: it is the only scanner taking a URL, so with Semgrep and Trivy alone both scanners receive the same target type and the dispatcher is never exercised against the heterogeneous case decision 4 exists to handle — the one thing a fake cannot prove, since a fake shows the dispatcher routes the right *value*, not that a real ZAP container accepts it while a real Semgrep process accepts something structurally different in the same run. Per CLAUDE.md's own measurement, the 120s threshold is only reachable through container-bound tests anyway, and the mitigation is already identified (a separate CI job for them); one more such test does not change the shape of that plan, it may only trigger it an issue earlier.

## Alternatives considered

**Fan-out to one arq job per `(scan, tool)`.** Rejected primarily on snapshot coherence: per-job checkout allows different tools to scan different commits, which makes M5's cross-tool correlation unsound in a way nothing would record. Secondarily, it distributes ownership of `Scan` status, requiring a coordinator job or a lock-based completion check that M3.3's state machine was deliberately designed to avoid. Its real advantages — independent per-tool retry and no shared job budget — do not outweigh a correctness property the next two milestones rest on. Worth revisiting only if scan volume makes worker-slot occupancy the binding constraint, and then only alongside a mechanism that pins all tools to one resolved commit.

**A blanket `Scan`-level `FAILED` when any tool fails**, keeping `ScanStatus` as it is. Rejected: it discards a succeeding scanner's output, the exact corruption `PRODUCT_SPEC.md` §12 forbids, and leaves M4 unable to tell which raw results are trustworthy.

**Keeping per-tool outcome only in `Scan.failure_reason`** as free text naming the failed tool. Rejected: unparseable, unqueryable, and it forces M4 to string-match a human-readable message to decide what to normalize.

**Setting `raw_output = ""` on failure instead of making it nullable.** Rejected: `""` conflates "ran and produced nothing" with "produced nothing because it failed", and it would prevent the `CHECK` constraint that gives M4 its non-null guarantee.

**Scanner configuration as new columns on `SecurityContext`.** Rejected: different lifecycle (re-derived by detection, which would clobber configuration), and it would give `BuildSecurityContextUseCase`/`UpdateExposureTagsUseCase` ownership of state that is not theirs. Overloading `exposure_tags` specifically was ruled out up front — it is user-confirmed annotation, not configuration.

**A normalized `(project_id, tool)` scanner-configuration table.** Rejected for MVP on missing-row ambiguity: an absent row cannot distinguish "disabled" from "never configured", which needs a documented rule at every read site. Adopt it when a second tool needs tool-specific settings — a concrete, checkable trigger, which per `PRODUCT_SPEC.md` §9 may not fire within MVP scope at all.

**A `tool_settings` JSONB column** instead of an explicit `zap_target_url`. Rejected: untyped, unmigratable, and not greppable, for flexibility exactly one tool needs today. The explicit column makes the wart visible, which is what makes the exit trigger above enforceable.

**Deferring the configuration write path to a later issue.** Rejected: it would leave ZAP dispatch structurally unable to execute in a running system, and a reader would reasonably assume code in `worker.py` runs. This project's previous deferrals all left a coherent system with a piece missing; this one would not.

**Two separate ports, `RepoScannerPort` and `DastScannerPort`,** instead of `target_kind` on one port. Conceptually cleaner — the target type would be in the type system rather than in a runtime enum — but it forks the dispatch machinery in two for a single DAST implementation, and every registry, DI factory and test fake would double. Revisit if DAST scanners grow their own distinct lifecycle (authentication, session handling, scan policies) rather than differing only in what `target` means.

**Branching on `tool == "zap"` inside `RunScanUseCase`.** Rejected outright: special-casing an integration inside application logic is what rule 4 exists to prevent, and it would have to be edited for every future scanner.

**Each module keeping its own set of tool-name literals**, instead of `ScannerTool` in `shared_kernel/`. Rejected: the same three strings in two places, where adding a scanner means editing both and nothing fails if you forget. The cost of the chosen option is a small widening of `shared_kernel/` from "cross-cutting Protocols" to "cross-cutting Protocols and shared vocabulary", which is a real change in that package's character and is why it is recorded here rather than done silently.

**Rejecting private/loopback targets in the configuration write path.** Rejected — see decision 3. It would duplicate ADR-013's range check on the wrong side of a module boundary, and, more importantly, would create the impression that a stored target has been pre-approved. The one gate that matters has to run at scan time because DNS can rebind; anything that makes it look optional is a liability, not defence in depth.

**Letting a scanner failure re-raise so arq retries it**, as M3.3 did. Rejected once retries re-run every scanner: an automatic retry could overwrite a good result with a failed one. Recorded under Consequences as a deliberate loss of automatic recovery for transient scanner failures.
