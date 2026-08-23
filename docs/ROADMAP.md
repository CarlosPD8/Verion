# Verion — 16-Week Roadmap

**Status:** Draft v1.0
**Related:** `PRODUCT_SPEC.md`, `ARCHITECTURE.md`
**Audience:** primary developer + Claude Code as pairing partner

---

## How to use this document

This roadmap is organized as **Milestones → Issues**, following the module boundaries defined in `ARCHITECTURE.md` and the functional requirements (FR-1 to FR-10) in `PRODUCT_SPEC.md`.

Conventions for every issue:
- **Module** — which hexagon it belongs to (from `ARCHITECTURE.md` §3).
- **Depends on** — issues/milestones that must land first.
- **Acceptance criteria** — the definition of done; Claude Code should not consider an issue complete until these are all true, including tests.
- Every issue that touches `domain/` or `application/` must ship with **unit tests using in-memory port fakes** — no exceptions, per the architecture's enforcement rules.
- Every issue that adds an adapter must ship with an **integration test** against the real dependency (Postgres/Redis/tool CLI).

Suggested workflow with Claude Code: work one issue at a time, open a branch per issue, keep PRs small enough to review in one sitting. Use this roadmap as the shared source of truth for scope — if an issue needs to grow, update this document first, then the code.

---

## Milestone 0 — Foundations (Week 1)

**Goal:** empty-but-real skeleton: repo, CI, module scaffolding, no business logic yet.

- **M0.1 — Repository & tooling setup**
  Module: `platform/` · Depends on: —
  - Repo initialized with the folder structure from `ARCHITECTURE.md` §7 (empty modules with `domain/application/ports/adapters` subfolders).
  - Linting, formatting, pre-commit hooks configured (ruff/black or equivalent).
  - `docker-compose.yml` with Postgres + Redis for local dev.

- **M0.2 — CI pipeline skeleton**
  Module: `platform/` · Depends on: M0.1
  - GitHub Actions workflow: lint → unit tests → build.
  - Import-linter rule added and passing on empty scaffolding, enforcing the dependency rule from `ARCHITECTURE.md` §10.

- **M0.3 — FastAPI app bootstrap + DI wiring**
  Module: `platform/` · Depends on: M0.1
  - App factory pattern, settings via env vars, health check endpoint.
  - Dependency-injection container wiring ports to adapters at startup (even if adapters are stubs for now).

- **M0.4 — ADRs formalized**
  Module: docs · Depends on: —
  - `docs/adr/0001-modular-monolith.md`, `0002-hexagonal-architecture.md`, `0003-explainable-scoring.md`, `0004-llm-downstream-of-scoring.md` written in full (context/decision/consequences), based on the summaries in `ARCHITECTURE.md` §12.

---

## Milestone 1 — Identity & Projects (Weeks 2-3)

**Goal:** a user can sign up, log in, and create a project. FR-1, FR-2.

- **M1.1 — Identity domain & use cases**
  Module: `identity` · Depends on: M0
  - `User` entity, password hashing, `RegisterUserUseCase`, `AuthenticateUserUseCase`.
  - Unit tests with in-memory `UserRepositoryPort` fake.

- **M1.2 — Identity adapters**
  Module: `identity` · Depends on: M1.1
  - Postgres `UserRepository` adapter + migration.
  - FastAPI routers: `POST /auth/register`, `POST /auth/login` (JWT).
  - Integration tests against real Postgres.

- **M1.3 — Projects domain & use cases**
  Module: `projects` · Depends on: M1.1
  - `Project`, `Repository` entities. `CreateProjectUseCase`, `ConnectRepositoryUseCase`.
  - RBAC check (owner/member) enforced at use-case level, not just API level.

- **M1.4 — Projects adapters**
  Module: `projects` · Depends on: M1.3
  - Postgres repository adapter + migration.
  - REST endpoints for project CRUD + repo connection.

- **M1.5 — GitHub OAuth / App connection**
  Module: `projects` · Depends on: M1.4
  - `VcsProviderPort` + `GitHubAdapter` (repo listing, metadata read).
  - E2E flow: log in → connect a real GitHub repo.

---

## Milestone 2 — Security Context (Weeks 3-4)

**Goal:** connecting a repo produces a real Security Context. FR-3.

- **M2.1 — Context extraction domain logic**
  Module: `projects` · Depends on: M1.5
  - `SecurityContext` entity, `BuildSecurityContextUseCase`.
  - Detection rules for language/framework from repo file signatures (e.g. `package.json`, `requirements.txt`, `Dockerfile`) — implemented as a pure domain service, testable without a real repo.

- **M2.2 — Context extraction adapter**
  Module: `projects` · Depends on: M2.1, M1.5
  - Adapter that pulls the relevant files via `VcsProviderPort` and feeds the detection service.
  - Integration test against a handful of real sample repos (fixtures).

- **M2.3 — Manual context annotation**
  Module: `projects` · Depends on: M2.1
  - API + minimal UI for user to confirm/edit context (`public_facing`, `handles_pii`, etc.).
  - Note: the UI portion ships as part of M8.4's onboarding flow, which already depends on this
    issue — M2.3 itself delivers the API only (detect/get/annotate routes, Postgres persistence,
    owner/member permission gating).

---

## Milestone 3 — Scanning Infrastructure (Weeks 4-6)

**Goal:** a scan can be triggered and produces raw tool output, end to end for one scanner first. FR-4.

> **Note — multi-scanner orchestration was M3.7, and is resolved.** M3.2/M3.4/M3.5 each added exactly one scanner path end to end (per M3.2's own "first scanner, walking skeleton" framing), and `platform/worker.py` dispatched `SemgrepAdapter` alone. Carrying that gap unassigned through three issues was deliberate, but a post-M3 review moved it onto the critical path: M4 designs the `Finding` schema and its per-scanner mappers, and M5 exists specifically to correlate findings across *different* tools — neither was meaningfully exercisable while a `Scan` could only ever produce one `ScanResult`. Closed by M3.7 below (see `docs/adr/0016-multi-scanner-dispatch.md`), ahead of M4; G1 in the Deferred gaps register records the full history.

- **M3.1 — Scan orchestration domain**
  Module: `scanning` · Depends on: M2
  - `Scan` entity, `TriggerScanUseCase`, `JobQueuePort`.
  - Redis-backed `JobQueuePort` adapter.

- **M3.2 — ScannerPort + SemgrepAdapter (first scanner, walking skeleton)**
  Module: `scanning` · Depends on: M3.1
  - Define `ScannerPort` interface.
  - `SemgrepAdapter`: runs Semgrep against a cloned repo, returns raw SARIF/JSON.
  - This is the **walking skeleton** — first fully working slice from trigger → raw results stored.

- **M3.3 — Worker process**
  Module: `scanning` · Depends on: M3.2
  - Background worker consumes queue, runs `ScannerPort`, persists raw `ScanResult`.
  - Idempotency: safe to retry a failed scan job (per `ARCHITECTURE.md` §9).

- **M3.4 — TrivyAdapter**
  Module: `scanning` · Depends on: M3.2
  - Second `ScannerPort` implementation — this issue is also the first real test of "adding a scanner only needs an adapter," per the architecture's core promise.

- **M3.5 — ZapAdapter (DAST, optional per project)**
  Module: `scanning` · Depends on: M3.2
  - Drives ZAP Automation Framework via YAML plan against a user-confirmed, allow-listed target.
  - **SSRF protection enforced here** — validate/allow-list target URL before invocation (`PRODUCT_SPEC.md` §11).

- **M3.6 — CI-triggered scanning**
  Module: `scanning` · Depends on: M3.3
  - GitHub Actions integration / webhook receiver triggers `TriggerScanUseCase` on push.

- **M3.7 — Multi-scanner dispatch** — done
  Module: `scanning` · Depends on: M3.3, M3.4, M3.5 · **Decisions recorded in `docs/adr/0016-multi-scanner-dispatch.md`**
  - One trigger fans out to every scanner enabled for the project. **Prerequisite for M4 and M5**, not a nice-to-have: `CorrelateFindingsUseCase` (M5.1) exists to link findings from *different* tools, and a `Scan` could previously only ever produce one.
  - **This was drift, not an open design question.** The schema and the architecture doc already assumed N tools per scan — `ScanResultModel`'s `UniqueConstraint(scan_id, tool)`, `ARCHITECTURE.md` §4's `raw_results: [ScanResult]  # one per tool that ran`, and §8's sequence diagram showing `ScannerPort (Semgrep/Trivy/ZAP)` returning per-tool results. Only the roadmap and the code had diverged from that.
  - **Decided — dispatch shape:** one arq job per `Scan`, scanners concurrent via `asyncio.gather`, **not** fan-out per `(scan, tool)`. The deciding argument turned out not to be the job budget but *snapshot coherence*: fan-out means one checkout per job, so a push landing mid-scan lets Semgrep and Trivy see different commits — which makes M5's cross-tool correlation unsound with nothing recording that it happened. `arq`'s default 300s `job_timeout` had to be raised to 600s, since concurrent wall-clock is `max()` (ZAP's 300s) plus checkout.
  - **Decided — partial-failure semantics:** per-tool `status`/`failure_reason` on `ScanResult` (a failed tool still gets a row), `ScanStatus.PARTIAL`, and `Scan.status` derived from the per-tool outcomes. **M4's entry point is `ScanResultRepositoryPort.get_succeeded_by_scan_id`** — never `Scan.status`, which is a human-facing summary. A DB `CHECK` constraint makes "succeeded implies non-null `raw_output`" true for any writer, so M4's mappers take `str`, not `str | None`.
  - **Decided — scanner configuration:** a `ScannerConfig` entity in `projects` (one row per project, `enabled_tools` array + `zap_target_url`), read by `scanning` through `ScannerConfigRepositoryPort` (rule 3). `SecurityContext` was rejected on lifecycle grounds — detection re-derives it and would clobber configuration. Unconfigured defaults to Semgrep+Trivy, with ZAP structurally undefaultable because only a user can supply its target. Ships with an owner-gated `PUT /projects/{id}/scanner-config`, without which ZAP dispatch would be dead-by-construction.
  - **Decided — `ScannerPort` identity:** gains `tool` (a shared `ScannerTool` enum) *and* `target_kind`, the half the question above did not name — Semgrep/Trivy take a checkout path, ZAP takes a URL, and dispatch routes on that rather than on a `tool == "zap"` branch (rule 4).
  - `ScanStatus` / `ScanResult` schema changes landed with Alembic migrations (`b1c4d7e29a03`, `c2d5e8f31b14`).
  - **SSRF re-validation stays inside `ZapAdapter.run()`** — persisting a validated target does not replace ADR-013's gate, since DNS can rebind between configuration time and scan time, which is the entire reason the gate exists. The write path checks well-formedness only, deliberately, so the stored URL never looks pre-approved.
  - Integration test: one trigger produces `ScanResult` rows for three real tools, and a deliberately failing scanner does not discard a succeeding scanner's output — asserted through `get_succeeded_by_scan_id`, the query M4 will actually use, not merely by both rows existing.

---

## Milestone 4 — Normalization (Weeks 6-7)

**Goal:** raw scanner output becomes the common `Finding` schema. FR-5.

- **M4.0 — Pipeline boundary: what triggers normalization, and what `Scan.status` means once it exists** — done
  Module: `scanning` + `normalization` · Depends on: M3.7 · **Decisions recorded in `docs/adr/0017-normalization-trigger-and-pipeline-progress.md`**
  - **Prerequisite for M4.1**, which is why it sits before it rather than being folded into it: M4.1 builds `Finding` and the per-scanner mappers, and cannot say where they are invoked from, what they run on after a partial scan, or what marks the work done. Surfaced by the M3→M4 milestone-boundary review as its most consequential finding, and escalated into an issue for the reason G1 became M3.7 — a finding recorded only as prose is one nobody acts on.
  - **This issue is a decision first and code second** — the questions below get answered and recorded in an ADR (next free number: **0017**) before implementation, the same ordering M3.7 used.
  - **Scope:** the decision, the `ARCHITECTURE.md` reconciliation, and any `ScanStatus`/schema change the decision implies. The `Finding` entity and the per-scanner mapping functions stay M4.1.
  - **The drift being closed.** `ARCHITECTURE.md` §8 shows `TriggerScanUseCase` orchestrating the whole pipeline synchronously — scan → normalize → correlate → score → brief — and setting `status=complete` only once `SecurityBrief` is persisted. The code does something else: `TriggerScanUseCase` creates a `Scan` and enqueues; `RunScanUseCase` ends at persisting `ScanResult` rows and sets `COMPLETED` there. So `COMPLETED` means "every enabled scanner finished", not "the pipeline finished" — and §8, which M4.1 is told to build from, describes a design that was never built.
  - **Decision — what triggers normalization:** inside the same arq job after the scanners return, a separate enqueued job, or lazily on read. The three bullets below state what each actually costs.
  - **Option — inside the same arq job.** The snapshot-coherence argument that decided ADR-016's decision 1 **does not extend here**: normalization consumes persisted `ScanResult` rows, not the checkout, which `RunScanUseCase`'s `finally` deletes anyway. What it buys is a single failure domain. What it costs is an ordering trap with no safe side — appended *after* `self._scans.update(scan)`, a normalization exception still commits `COMPLETED` (`worker.py` commits in `finally`), propagates to arq, and the retry returns immediately at `if scan.status == ScanStatus.COMPLETED: return`, so normalization silently never runs, permanently, with no error state; placed *before* that update, a JSON-parsing bug instead re-runs every scanner on retry, ~64s of container work.
  - **Option — a separate enqueued job.** Decouples the failure domains: a normalization bug retries without re-running scanners. The cost is **not** the fan-in problem M3.7 avoided — that was N jobs racing to decide one `Scan`'s status, whereas this is a linear one-to-one handoff. It is a **dual write**: the Postgres commit and the Redis enqueue cannot be made atomic, so either the commit lands and the enqueue is lost (a `COMPLETED` scan that silently never produces findings) or the job runs before the commit is visible. Name the mitigation — transactional outbox, or an idempotent normalize job plus a reconciliation sweep — rather than leaving the gap implicit.
  - **Option — lazily on read.** Makes normalization latency user-visible at `GET /projects/{id}/findings` (M4.5; M4.3 when this issue was written), and sits badly with the milestones either side: M4.2's dedup ("re-running a scan doesn't duplicate identical findings") needs findings that persist across scans, and §8 has M5 reading `Findings` from the database, not from a request-scoped computation.
  - **Decision — how `PARTIAL` interacts.** A partial scan has succeeded rows worth normalizing and failed ones that aren't; `get_succeeded_by_scan_id` already draws that line. Normalization must run on `PARTIAL` — skipping it would discard a succeeding scanner's output one layer up, the same corruption `PRODUCT_SPEC.md` §12 forbids and ADR-016 decision 2 was built to prevent. Decide what the `Scan` looks like afterwards: it must not become `COMPLETED`, or the record that a tool failed is erased. Decide the degenerate case too — a scan where every tool failed has nothing to normalize; is the stage skipped, or does it run and produce zero findings?
  - **Decision — what `ScanStatus` means once M4 exists.** If normalization is a separate stage, `COMPLETED` becomes ambiguous in exactly the way §8 already is. The constraint to design against: ADR-016 decision 2 fixed `Scan.status` as a *derived summary of per-tool outcomes* and had M4 read `get_succeeded_by_scan_id` instead, specifically so a human-facing field never becomes a pipeline's input. Growing the enum with pipeline stages contradicts that and conflates two orthogonal axes — per-tool outcome × pipeline progress — which multiply out as M5, M6 and M7 each add a stage. The alternative is keeping `ScanStatus` scanner-scoped and tracking pipeline progress separately. Decide it and record it; do not let it drift.
  - **Reconcile `ARCHITECTURE.md` in the same change**, per CLAUDE.md's rule that a document gets fixed in the PR that changed the reality — the four items below.
  - **§8's sequence diagram**, redrawn to whatever is decided. It is the spec M4.1 reads, and it is currently a picture of a pipeline that was never built.
  - **§4's `Scan` and `ScanResult`.** `Scan` still has no `failure_reason` (added M3.3, two milestones stale), and `ScanResult` has no field breakdown at all — so M3.7's `status`, `failure_reason` and nullable `raw_output` are absent from the document M4.1 is told to build `Finding` from.
  - **§4's `Finding.source (semgrep|trivy|zap)`**, which should reference `shared_kernel/scanner_tools.py`'s `ScannerTool` rather than re-establishing a literal set — the duplication ADR-016 decision 4 centralised that enum to prevent.
  - **§9's claim that `IngestScanResultUseCase` is idempotent**, about a use case that exists nowhere in `src/`. Whatever this issue names the normalization entry point settles whether that sentence becomes true or gets removed.
  - **Decided — `ScanStatus` stays scanner-scoped.** No enum change, no `scans` migration. Its blast radius turned out to be a single `if`: across all of `src/` the only behavioural reader is `RunScanUseCase`'s `== COMPLETED` retry guard. ADR-016's "today that is the scanning API surface" named a consumer that does not exist — `scanning`'s one endpoint is the webhook, whose ack `status` is a literal string. Corrected in ADR-0017's Context rather than by amending an accepted ADR.
  - **Decided — a separate enqueued job, with the progress row as the outbox.** `NormalizationRun` (one row per scan, `UNIQUE(scan_id)`), owned by `normalization`, written by `RunScanUseCase` through a **primitives-only** port inside the same transaction as the `ScanResult` rows — so the Postgres-commit-plus-Redis-enqueue dual write stops existing rather than being compensated for. `ARCHITECTURE.md` §9's unit-of-work rule is amended for stage handoffs specifically. Same-job was rejected as *incompatible with ADR-016*, not merely expensive; lazily-on-read on M4.2/§8 grounds.
  - **Decided — normalization runs on `PARTIAL` and on an all-tools-failed scan**, on one invariant chosen to avoid a second code path: a row exists **iff** `ScanResult` rows were persisted. A `PARTIAL` scan cannot later become `COMPLETED` — structurally, since all three writers of `Scan.status` live in `scanning`.
  - **Two ordering/idempotency constraints, both pinned by tests** rather than left to comments: the handoff row is written *after* the upsert loop and *before* `_scans.update(scan)` (reversed, a failure would commit `COMPLETED` and the retry would short-circuit, losing normalization permanently); and the write is `ON CONFLICT DO NOTHING`, never `DO UPDATE`, which would reset a running/completed row to pending.
  - Schema change landed with an Alembic migration (`d4a7c1b8e630`), `upgrade` and `downgrade` both verified.
  - **Deliberately not shipped, trigger M4.4:** the arq enqueue, a `normalize_scan` job, the reconciliation sweep query, and the partial index the sweep will want. With no `Finding` entity they would be dead-by-construction. *Trigger was M4.1 when this issue closed; M4.1 moved it to M4.4, because all four also need the `Finding` table that M4.3 creates — see ADR-0017's Amendments.* Until M4.4 lands the system writes a `pending` row on every scan that nothing advances — intended, and recorded in ADR-0017's Consequences.
  - Integration test: a `PARTIAL` scan leaves a `pending` handoff row and is reachable from `normalization_runs` + `scan_results` alone, with no query in that path touching `scans` — plus round-tripping all four statuses through the real adapter, which is what proves the enum and the `CHECK` agree on the same strings.

**M4 is six issues where this roadmap originally planned three.** M4.0 was inserted by the M3→M4 boundary review; M4.1 then split into four because six of the items it carried all write `Finding` rows, and the table for those does not exist until M4.3. M3 went 6 issues → 7 for the same reason (M3.7 was work M3.4/M3.5/M3.6 kept deferring). Recorded here so the growth is visible rather than discovered.

- **M4.1 — Finding domain model** — done
  Module: `normalization` · Depends on: M4.0 · **Decisions recorded in `docs/adr/0018-normalized-severity-and-shared-kernel-scope.md`**
  - `Finding`, `Evidence`, `Location` entities and `shared_kernel`'s `Severity`, per `ARCHITECTURE.md` §4.
  - **Captured real Semgrep/Trivy/ZAP output as fixtures before writing the mapping functions.** Landed in `tests/fixtures/scanners/`, at the repo root of `tests/` rather than under `unit/` so M4.4's integration test reads the same files through the same `scanner_fixture` conftest loader — otherwise one issue's files get moved in another issue's diff. Provenance, byte counts, redactions and coverage gaps are in that directory's README.
  - **Correction to this issue's original premise, which was wrong.** It said a single run of M3.7's `test_multi_scanner_dispatch.py` "yields the whole set". It does not: that test scans `octocat/Hello-World`, which holds a README and nothing else, against a one-rule Python-only ruleset — so Semgrep returns `results: []` and Trivy finds no manifest, and two of three fixtures would have been empty envelopes. The per-adapter targets were used instead; each already has a passing test asserting a real finding against it.
  - Pure mapping functions per scanner (Semgrep→Finding, Trivy→Finding, Zap→Finding), unit tested against those fixtures plus labelled synthetic ones for the rows real output does not reach (Trivy emits no `CRITICAL`/`LOW`/`UNKNOWN` against this target; ZAP emits no riskcode `0` or `3`).
  - **Decided — the normalized severity scale, and `shared_kernel/`'s admission criterion.** Six members including `UNKNOWN`; `native_severity` keeps what the collapse discards. `shared_kernel/` now has a written rule — *closed vocabularies two or more modules must compare or order, not merely transport* — applied three times in the issue, twice in the negative (`Confidence` and `Location` both declined). `Severity` overrides its comparison operators because a plain `StrEnum` makes `HIGH >= CRITICAL` true alphabetically, which would put a silent lie inside `risk_engine`.
  - **Deliberately not in `Finding`:** `confidence` (→ M6.1) and `dedup_hash` (→ M4.2). Both are pinned absent by a test so re-adding either is deliberate.
  - **Moved out of this issue, to M4.4:** the arq enqueue, the `normalize_scan` job, the reconciliation sweep, the partial index, the `started_at`/`finished_at` state machine, and the `PARTIAL`-scan integration test. All six write `Finding` rows and the Postgres adapter for those is M4.3, so shipping them here would have been the dead-by-construction code ADR-0017 deferred them to avoid. ADR-0017's trigger was corrected to M4.4 in an `## Amendments` entry in the same change.
  - Verified: 267 unit tests pass, ruff/format clean, mypy 175 files with suppressions still 0/0, import-linter 17/17, check_claims 4/4. No `src/` file outside `normalization/domain/` and `shared_kernel/severity.py` changed; no migration, no port, no adapter.

- **M4.2 — Deduplication and `Finding` identity**
  Module: `normalization` · Depends on: M4.1
  - Dedup hash strategy; re-running a scan doesn't duplicate identical findings.
  - **Resolves G5** — the `Finding`-identity gap. This issue lands *before* M4.3 persists anything, which is what makes the register's `Status: assigned → M4.2` safe: no wrong shape ever reaches disk. Deciding the hash without deciding identity is not possible in either order, which is why they are one issue.
  - **Inputs M4.1 produced**, so this does not start from scratch: per-tool identity candidates are Trivy `VulnerabilityID` + `PkgName` + `InstalledVersion`, ZAP `pluginid`/`alertRef` + `uri` + `param`, and Semgrep `check_id` + `path` + line range. **Semgrep's `fingerprint` is not a candidate** — it is the literal string `"requires login"` for anonymous Semgrep OSS, and this repo sets no `SEMGREP_APP_TOKEN`. Verified against captured output, not assumed.
  - **The mapper signature is provisional and this issue may change it.** `map_<tool>_output(*, scan_id, raw_output, id_generator, clock)` assumes `Finding` is scan-scoped; if identity resolves to the sighting model G5 names, `scan_id` leaves the mapper. Blast radius, so it is known before it is hit: the three mappers' signature, `Finding.scan_id`, `Evidence.finding_id`, the three mapper test modules, and where `dedup_hash` is computed. Nothing outside `normalization/domain/` and `tests/unit/` moves with it.
  - Also open here: whether a ZAP alert becomes one `Finding` or one per `instances[]` entry. M4.1 chose one-per-alert deliberately, because instances *are* occurrences and splitting them would have pre-empted this decision. Every instance is in the evidence, so the data is available.

- **M4.3 — `Finding` persistence**
  Module: `normalization` · Depends on: M4.2
  - Postgres adapter and Alembic migration for the shape M4.2 decided. `FindingRepositoryPort`, `Base` from `platform/db.py` (rule 8), string IDs (rule 9).
  - Depends on M4.2 rather than M4.1 deliberately: the table cannot be created before the identity decision that determines its keys.
  - Ships persistence with no production writer, which is this project's established shape for a deferral (ADR-016 decision 3 cites persistence in M2.1 and `di.py` wiring ahead of a route). The writer arrives in M4.4.
  - **Hydration must reconstruct `Severity(...)`, not leave a bare `str`.** `Severity.HIGH == "high"` is True but `Severity.HIGH >= "high"` **raises** — equality survives a `String` column, ordering does not, and ordering is the half M5/M6/M8 use (ADR-0018 decision 2). Same for `ScannerTool`.

- **M4.4 — Close the scan→normalize handoff**
  Module: `normalization` + `platform` · Depends on: M4.3
  - The four items ADR-0017 deferred, plus the state machine and the acceptance test that need them. This is the issue where the pipeline first actually runs end to end.
  - `NormalizeScanUseCase`, reading `get_succeeded_by_scan_id` and never `Scan.status`; a `normalize_scan` arq job registered in `WorkerSettings.functions`; the enqueue from `run_scan`, which belongs **after** the commit since the row is the record and the enqueue is only a latency optimization.
  - The reconciliation sweep, which **must select on `normalization_runs` and `scan_results` and never read `Scan.status`** (ADR-0017 decision 2, stated there as an invariant), plus the partial index on `WHERE status = 'pending'` in the migration that ships the query it serves.
  - The `started_at`/`finished_at` state machine, left unconstrained in both the domain guard and the `CHECK` because those transitions are this issue's to define.
  - **Integration test: a `PARTIAL` scan is normalized, produces findings from the succeeded tools only, and the failed tool contributes none** — asserted through `get_succeeded_by_scan_id`, not by row counts alone. Build it like `test_normalization_handoff.py`: real Postgres, **in-process fake scanners fed M4.1's committed fixtures as their `raw_output`**. Reusing `test_multi_scanner_dispatch.py`'s three real adapters would add a fourth ZAP-class test, and per `CLAUDE.md` roughly three more of those trip the 120s CI split.
  - Closes the window, open since M4.0, in which every scan writes a `pending` progress row that nothing advances.

- **M4.5 — Findings read API**
  Module: `normalization` · Depends on: M4.4
  - `GET /projects/{id}/findings`. Depends on M4.4, not M4.3: an endpoint shipped before the writer would return an empty list for a whole issue, which is dead-by-construction on the read side.
  - **A `?severity=` or `?min_severity=` filter must coerce to `Severity(...)` before comparing.** A query parameter arrives as a `str`, and comparing one against a `Severity` raises rather than silently ordering alphabetically (ADR-0018 decision 2) — which is the intended failure, but only helps someone who expected it.
  - **Rule 12 applies to `Evidence.raw_payload` here**, and this is the issue where it starts to matter — a dedicated response schema, never the entity (rule 10). Semgrep's `extra.lines` is normally the matched source line, and secret-detection rules match secrets. It is *currently* inert: anonymous Semgrep OSS redacts that field to `"requires login"` and this repo sets no `SEMGREP_APP_TOKEN`. Adding one would silently arm it, so decide deliberately what this endpoint exposes rather than inheriting the current accident.

---

## Milestone 5 — Correlation Engine (Weeks 7-9)

**Goal:** related findings across tools become a single candidate Risk. FR-6. This is one of the two "star" components.

- **M5.1 — Correlation strategy design + domain logic**
  Module: `correlation` · Depends on: M4
  - Define the concrete matching signals for MVP (e.g., same endpoint path referenced by SAST taint sink and DAST result; same file/dependency referenced by SCA and SAST).
  - `CorrelateFindingsUseCase` implemented as pure domain logic, unit tested with constructed Finding fixtures covering both "should correlate" and "should NOT correlate" cases.

- **M5.2 — Correlation persistence + API**
  Module: `correlation` · Depends on: M5.1
  - `Risk` entity (candidate, unscored yet), Postgres adapter.
  - Endpoint to inspect a Risk's constituent Findings (evidence traceability, `ARCHITECTURE.md` §9).

- **M5.3 — Correlation accuracy test suite**
  Module: `correlation` · Depends on: M5.1
  - A curated fixture set (deliberately vulnerable sample app findings) with expected correlation groupings, used as a regression suite — this becomes a demonstrable "proof" artifact for the CV/portfolio narrative.

---

## Milestone 6 — Risk / Decision Engine (Weeks 9-11)

**Goal:** correlated Risks get an explainable priority and confidence. FR-7. The other "star" component.

- **M6.1 — Scoring model design**
  Module: `risk_engine` · Depends on: M5
  - Formalize the explainable function: severity + confidence + exposure + reachability (where available) + asset sensitivity + environment → priority bucket (`fix_now`/`plan`/`monitor`) + confidence + `RiskReasoning`.
  - Document the exact formula/weights in `docs/adr/0005-risk-scoring-model.md` — this is the piece most worth being able to explain in an interview.
  - **`Finding.confidence` is this issue's to add or to decline** (deferred here by ADR-0018, since M4.1 had no consumer to design a scale against). Two things to design against rather than around: only ZAP supplies confidence, as an opaque numeric code, and its vocabulary mixes degrees (`High`/`Medium`/`Low`) with **states** (`Confirmed`, `False Positive`) — mapping `False Positive` onto a low degree would tell this engine "weak evidence" when ZAP said "not a finding". Semgrep can supply it via rule metadata, under the same G6 caveat as CWE; Trivy has no such concept. If it becomes a scoring input it needs a scale with a state axis, plus a nullable column on M4.3's table.
  - **Two severity inputs come with caveats from ADR-0018.** `Severity.UNKNOWN` means the tool did not know, not "lowest risk" — the enum ranks it lowest for *sorting* only, and treating that as a score would be deciding by accident. And the normalization discards relative position within each tool's own scale (Semgrep's `ERROR` is its maximum; Trivy's `HIGH` means `CRITICAL` was available and declined), which is the argument for keeping `Finding.source` as a scoring input.

- **M6.2 — Scoring implementation**
  Module: `risk_engine` · Depends on: M6.1
  - `ComputeRiskUseCase`, pure domain logic, unit tested extensively — this is the highest-value test suite in the whole project (must be provably explainable and stable).

- **M6.3 — Scoring persistence + API**
  Module: `risk_engine` · Depends on: M6.2
  - Persist priority + reasoning on `Risk`. Endpoint returning ranked Risks per project.

---

## Milestone 7 — Security Brief / Explanation Layer (Weeks 11-12)

**Goal:** each scored Risk gets a developer-facing narrative. FR-8.

- **M7.1 — ExplanationProviderPort + LLM adapter**
  Module: `brief` · Depends on: M6
  - Port interface; adapter calls the model with a strict prompt: structured `RiskReasoning` in, narrative text out — no re-deciding priority.
  - Test with a fake/deterministic adapter for CI stability; real LLM call covered by a small integration test.

- **M7.2 — Security Brief generation & persistence**
  Module: `brief` · Depends on: M7.1
  - `GenerateSecurityBriefUseCase`, `SecurityBrief` entity, Postgres adapter.
  - Endpoint returning the full Brief with evidence links (evidence traceability, FR-9).

- **M7.3 — Prompt safety**
  Module: `brief` · Depends on: M7.1
  - Explicit handling for the fact that raw finding/evidence text originates from scanned (potentially untrusted) source code — sanitize/constrain what gets interpolated into the LLM prompt to avoid prompt-injection-via-scanned-content.

---

## Milestone 8 — Dashboard & History (Weeks 12-13)

**Goal:** the actual product surface a user interacts with. FR-10.

- **M8.1 — History/audit domain**
  Module: `history` · Depends on: M6
  - `RiskEvent` log, `ResolveRiskUseCase` / `DismissRiskUseCase` with required reason.

- **M8.2 — Dashboard API**
  Module: `history` · Depends on: M8.1
  - `GetProjectDashboardUseCase` — ranked Risks + Briefs + scan history read model.

- **M8.3 — Frontend: project dashboard (Next.js)**
  Module: frontend · Depends on: M8.2
  - Project list, Security Brief cards (per the UI sketch in `PRODUCT_SPEC.md` §3), drill-down into raw evidence.

- **M8.4 — Frontend: onboarding flow**
  Module: frontend · Depends on: M1.5, M2.3
  - Connect repo → confirm Security Context → trigger first scan, guided flow.

---

## Milestone 9 — Verification Loop (Week 13-14)

**Goal:** close the loop — fixing something and re-scanning demonstrably updates the Risk state.

- **M9.1 — Re-scan diffing**
  Module: `history` + `correlation` · Depends on: M8
  - When a new scan runs, previously open Risks are re-evaluated; resolved ones are marked with the evidence diff that justified it.

- **M9.2 — Frontend: verification UI**
  Module: frontend · Depends on: M9.1
  - "Re-scan" action, before/after evidence view on a resolved Risk.

---

## Milestone 10 — Security Hardening (Weeks 14-15)

**Goal:** Verion meets the security bar it recommends to others (dogfooding, per `PRODUCT_SPEC.md` §11).

- **M10.1 — Threat model document**
  Module: docs · Depends on: all prior
  - Formal threat model for Verion itself (STRIDE or similar), covering the SSRF surface, secrets handling, and auth.

- **M10.2 — RBAC & rate limiting audit**
  Module: `identity`/`platform` · Depends on: M1
  - Verify enforcement at every endpoint, add rate limiting middleware.

- **M10.3 — Secrets management pass**
  Module: `platform` · Depends on: —
  - Ensure no secret ever touches logs/DB in plaintext; env-based secret injection.

- **M10.4 — Security headers + dependency scanning on Verion itself**
  Module: `platform` · Depends on: —
  - Verion's own CI runs Trivy/Semgrep against its own repo — the dogfooding proof point.

---

## Milestone 11 — Testing, Docs, Deployment (Weeks 15-16)

**Goal:** ship-quality polish.

- **M11.1 — E2E test suite**
  Module: `tests/e2e` · Depends on: M9
  - Full pipeline run against a deliberately vulnerable sample repo, asserting final Brief content — this is the flagship demo artifact.

- **M11.2 — Documentation pass**
  Module: docs · Depends on: all
  - README with architecture diagram, setup instructions, and a recorded/gif demo of the full flow.

- **M11.3 — Deployment**
  Module: `platform` · Depends on: all
  - Deployed instance (e.g., a small VPS or cloud free tier) running the full docker-compose stack, publicly reachable for demo purposes.

- **M11.4 — Final review against PRODUCT_SPEC.md**
  Module: — · Depends on: all
  - Walk every FR (FR-1 to FR-10) and confirm it's demonstrably met; note any conscious scope cuts.

---

## Summary Timeline

| Weeks | Milestone |
|---|---|
| 1 | M0 — Foundations |
| 2-3 | M1 — Identity & Projects |
| 3-4 | M2 — Security Context |
| 4-6 | M3 — Scanning Infrastructure |
| 6-7 | M4 — Normalization |
| 7-9 | M5 — Correlation Engine |
| 9-11 | M6 — Risk / Decision Engine |
| 11-12 | M7 — Security Brief / Explanation Layer |
| 12-13 | M8 — Dashboard & History |
| 13-14 | M9 — Verification Loop |
| 14-15 | M10 — Security Hardening |
| 15-16 | M11 — Testing, Docs, Deployment |

---

## Milestone-boundary review

Run at **every milestone boundary**, timeboxed to **~45 minutes**. Reads the Deferred gaps register below as its main input.

**Why this is scheduled rather than ad-hoc, stated honestly — because the case for it is narrower than the first pass makes it look.** The post-M3 review found seven documentation drifts, three latent bugs, and one critical-path blocker. Most of that does not recur:

- The **three bugs** were a one-time backlog flush, and were surfaced by *introducing* `mypy --strict` rather than by any step below. They existed because no type checker had ever run; it now runs on every commit and that class cannot accumulate again.
- The **doc drifts** are now largely automated by `scripts/check_claims.py`, whose blocking checks and non-blocking suppression report are enumerated in the script itself.
- The **critical-path blocker is the recurring value.** No per-commit gate can notice that M5 has become unbuildable — that takes stepping back and asking whether the next milestone's assumptions still hold in code.

So the review has shrunk to roughly its most valuable third. **That is the argument for scheduling it, not against it:** the expensive parts were automated away, and the part that remains is cheap and irreplaceable.

### The checklist

Ordered by observed value, not tidiness. Steps 2 and 4 are mostly mechanical now.

1. **Do the next milestone's stated dependencies still hold in code?** Take its first two issues and trace each `Depends on:` to the code that must already exist. *This is the step that found M3.7, and the only step here that has ever found something no gate could.*
2. **Run `uv run python scripts/check_claims.py`, then review what it structurally cannot check.** *Scope is listed explicitly because the first execution of this checklist proved that leaving it implicit narrows it: the original wording named only code comments and time-stamped markers, so the sweep grepped for those, covered `ARCHITECTURE.md`, and never opened `PRODUCT_SPEC.md` or `README.md` — where three drifts were sitting, including a status line four milestones stale.*
   - **Files:** `CLAUDE.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `PRODUCT_SPEC.md`, `README.md`, `.claude/agents/`.
   - **Drift classes:** stale prose about implementation status; `TODO` / "as of M#.#" markers older than one milestone; broken or outdated internal cross-references (§ numbers, section names); and completion or status claims that outran reality.
   - *Found `vcs_provider.py`'s "GitHubAdapter doesn't implement these yet", three milestones stale; and, once the scope above was written down, `PRODUCT_SPEC.md`'s "see Section 12" pointing at Architecture Principles instead of Security Principles.*
   - When renumbering a numbered list in any of these files, grep for citations of the old numbers first — `§11.1` and `§11.5` are each cited by ADRs, so an insert would break a cross-reference while fixing one.
3. **Review the Deferred gaps register** — anything at 3+ confirmations, and re-read every `Blocks-if-unresolved:` against the milestone now starting. A gap that was background debt last milestone may be critical path this one; that transition is the thing being watched for.
4. **Compare tracked metrics against the latest green CI run** — the `Tests (pytest …)` step duration and the suppression count — and record the new baseline in `CLAUDE.md`. *This is where the ±8s variance and the runtime concentration in a handful of container-bound tests surfaced.*
   - The step *duration* is available from the unauthenticated jobs API (`/actions/runs/<id>/jobs`), but the `--durations=10` per-test breakdown is only in the job **log**, which that API refuses without auth (403). Reading it needs `gh` or a **dedicated `actions:read`-only token** — not a reuse of the push credential. Until one exists, that half of this step needs the numbers pasted in by hand.
5. **Spot-check the newest adapter against the Tier 2 ADRs, and re-read this milestone's own ADRs for undischarged deferrals.** ADR-011's nine subprocess points and ADR-013's gate placement for the adapter; CI cannot see these, and adapters are the only place they apply. Then, for each ADR written or amended during the milestone just ending, read the whole document for a deferral carrying a trigger condition — they have turned up in Consequences, in Decision, and in Alternatives considered, so those three are where to look first, not where to stop — and confirm the trigger either has not fired or produced a register entry. Bounded on purpose — only the closing milestone's ADRs, so each is read exactly once ever, at the boundary right after it was written. *Found ADR-012's Trivy-timeout deferral, whose named trigger fired in M3.7 and whose unvalidated number became an input to ADR-016's `job_timeout` arithmetic — recorded as G4. The "read the whole document" wording is itself a finding of that same pass: this step originally said "check its Consequences", which would have missed ADR-014's only trigger-carrying deferral, sitting in Alternatives considered. Do not re-narrow it to a section list.*

### Keeping it from becoming box-ticking

A checklist that reports "all clear" every time is worse than no checklist. Two mitigations:

- **Every step produces a written artifact** — either a finding, or an explicit "checked X against Y, no change". Recorded in the review's commit message, and summarised as one row in the log below. "No change" is a valid result; silence is not.
- **The exit ramp, defined now rather than when it is needed.** If **two consecutive reviews** produce only "checked, no change" artifacts for **steps 1, 3, and 5** — meaning no finding, no new issue, and no register entry from any of those three, twice running — cut the cadence to every other milestone. A step recorded as **not performed** does not count as "checked, no change" and does not advance this test; only a step that was actually run and found nothing does. Record it as a new row in the log with `Cadence:` set to the new value, and say why in that review's commit message. Steps 2 and 4 are excluded from this test on purpose: they are mechanical and will keep passing, so including them would make the condition unreachable.

### Review log

One row per review, plus any standalone pass that re-runs part of the checklist outside a boundary — those say so in the Boundary column and mark every step they skipped as **not performed**, which per the exit-ramp rule above means they cannot advance it. **They are also skipped when identifying the last two rows** — otherwise inserting one would stall the ramp indefinitely rather than merely delaying it, since a row that cannot advance the test would permanently occupy one of the two slots it reads.

| Date | Boundary | Steps with findings | Cadence |
|---|---|---|---|
| 2026-08-20 | post-M3 | 1 (M3.7 critical path); 2 (7 doc drifts, incl. `vcs_provider.py`); 3 (register created, G1 seeded retrospectively); 4 (runtime + suppression baselines recorded); 5 **not performed** — this checklist postdates the pass | every milestone |
| 2026-08-21 | post-M3.7 (M3→M4) | 1 (no captured scanner-output fixtures; §8's pipeline/`status=complete` conflicts with the M3.3/M3.7 state machine; §9's `IngestScanResultUseCase` does not exist); 2 (§4 stale for `Scan`/`ScanResult`; §4's `Finding.source` duplicates `ScannerTool`) — **plus 3 more found only after this pass widened step 2's scope**, which is the change recorded above: `PRODUCT_SPEC.md`'s "see Section 12", §11's missing webhook principle, `README.md` claiming M0/not-runnable four milestones late; 3 **checked, no change** — G1 resolved → M3.7, G2 re-read against M4 and not on its critical path; 4 (pytest step 45s → **64s**, suppressions 0/0 unchanged); 5 (ADR-011 point 9's "not a credential" premise became conditionally false when M3.7 made the ZAP target user-configured) | every milestone |
| 2026-08-21 | **standalone investigation, not a boundary review** — step 5 run in full over M3's six ADRs, under its widened scope | Only step 5 performed; 1, 2, 3, 4 **not performed** (already done in the row above, same boundary) so this row does not advance the exit-ramp test. 5 swept **0011, 0012, 0013, 0014, 0015, 0016**. *Undischarged, trigger fired:* ADR-012's Trivy-timeout validation — trigger named as "whichever future issue does that wiring", fired at M3.7 (which changed the adapter only to add `tool`/`target_kind`), never discharged, and ADR-016 then used the unvalidated 180s as an input to `job_timeout = 600s` without referencing ADR-012 → **G4**. ADR-012's *second* deferral, the independent scheduled refresh job, is absorbed into G4's `Deferral rationale:` and is deliberately not its own entry. *Covered already:* ADR-016's `(project_id, tool)` normalization, trigger "when a second tool needs tool-specific settings" — not fired, is **G2**. *Fired and discharged:* ADR-011's "`TrivyAdapter` and `ZapAdapter` follow this shape when they land (M3.4/M3.5)". *Trigger dormant, no entry warranted:* ADR-016's fan-out revisit (if worker-slot occupancy becomes the binding constraint), its two-ports revisit (if DAST scanners grow a distinct lifecycle), and `PARTIAL` needing its first real downstream consumer at M8; ADR-014's per-project webhook secret (if independently rotatable per-project trust boundaries are ever required). *No trigger, so out of scope by step 5's own rule:* ADR-013's un-CI-testable public-target DAST path, ADR-015's `tests/` exclusion. **Two findings about the step itself, one fixed here.** ADR-014's only trigger-carrying deferral sits in *Alternatives considered*, which step 5's original wording ("check its Consequences") did not cover — found only because the sweep read whole documents, and the step is widened to say so **in this same commit** rather than deferred to the next boundary. That makes twice that a step under-scoped itself and was corrected by being run: step 2 was widened mid-pass in the row above and immediately turned up three more drifts. *Not* fixed: the "~5 minutes" figure is untested by this pass — an agent read 9,653 words in 1.8 min, which is not a fair test of an estimate written for a human — but M3 closed with six ADRs where that estimate assumes 1-3, so a comparably ADR-dense milestone could consume most of the 45-minute box on this step alone | every milestone |

---

## Deferred gaps

Known gaps that are not yet anybody's issue. This exists because noting a gap in a commit message does not scale: **multi-scanner orchestration was correctly identified and correctly deferred three times (M3.4, M3.5, M3.6) and still became a critical-path blocker for M4 and M5 without anyone noticing.** It took a dedicated review pass to catch, and had it been missed, it would have surfaced at M8 with four milestones built on top.

**`Blocks-if-unresolved:` is the field that does the real work.** G1 was not missed because it went unrecorded — it was recorded three times, in increasing detail. It was missed because nobody wrote down *what it would break*, so its promotion from background debt to critical path was invisible. Fill that field in seriously: name the milestone and the concrete thing that breaks, not "may cause problems later". An entry whose `Blocks-if-unresolved:` is vague is an entry that will be re-read and skipped.

Rules, enforced by `scripts/check_claims.py`:

- Entries use fixed fields so they can be parsed: `Confirmed:`, `Status:`, `Blocks-if-unresolved:`, and optionally `Deferral rationale:`.
- Add a milestone to `Confirmed:` each time the gap is re-encountered and deferred again.
- **At three or more confirmations**, an entry must carry either `Status: assigned → <issue>` or an explicit `Deferral rationale:`. Re-noting it a fourth time with neither fails CI. Three is the threshold because three is where this one broke: M3.4 and M3.5 were reasonable deferrals, but by M3.6 the repetition had become information nobody was acting on.
- Resolved entries stay here with `Status: resolved → <issue>`, as the record of how long it took and what it was blocking.

### G1 — Multi-scanner orchestration
Confirmed: M3.4, M3.5, M3.6 · Status: resolved → M3.7
Blocks-if-unresolved: M4 (the `Finding` schema and its per-scanner mappers would be designed without ever seeing Semgrep+Trivy+ZAP output for the same scan), M5 (`CorrelateFindingsUseCase` exists to link findings across *different* tools, and a `Scan` can only ever produce one)
Resolution: M3.7 — ADR-016. Three milestones between first confirmation (M3.4) and assignment, one issue between assignment and resolution. The `Blocks-if-unresolved:` field turned out to understate it: designing this properly also required a partial-failure model (`ScanResult.status`, `ScanStatus.PARTIAL`) and a home for per-project scanner configuration, neither of which was visible while the gap was recorded only as "orchestration is missing".

### G2 — `zap_target_url` is a per-integration value inside generic dispatch
Confirmed: M3.7 · Status: open
Deferral rationale: fixing it now means normalizing `scanner_configs` to `(project_id, tool)` for a second URL scanner that does not exist and that `PRODUCT_SPEC.md` §9 puts in V2 — the pre-normalizing-for-a-hypothetical that ADR-016 decision 3 argues against, on the same reasoning ADR-014 used to reject a per-project webhook secret. Resolve on the trigger already stated there: **when a second tool needs tool-specific settings.**
Blocks-if-unresolved: any future `ScannerTargetKind.URL` scanner. `RunScanUseCase.execute` takes a single `zap_target_url: str | None` and routes it in the `else` branch of the `target_kind` check, so a second URL-kind adapter is silently handed **ZAP's** target rather than its own. It fails silently — the scanner runs, succeeds, and produces a real `ScanResult` for the wrong target, which M4 then normalizes and M5 correlates as if it were that tool's view of the system. Nothing raises, and no test today would catch it.
Note: `ScannerPort.target_kind` itself is fine — dispatch's *shape* is generic and carries no `tool == "zap"` branch (rule 4). What is per-integration is the *value*, in the use case's signature. Recorded here and not only in ADR-016 because prose has no `Blocks-if-unresolved:` field and no escalation check, which is the exact lesson G1 above is the record of.

### G3 — CI action majors are behind, and running on a runtime they don't declare
Confirmed: post-M3.7 · Status: open
Deferral rationale: found while removing a dead `python-version` input from `setup-uv`, and deliberately not bundled into that fix. Three majors across `actions/checkout` (v4→v5), `actions/cache` (v4→v5) and `astral-sh/setup-uv` (v3→v10) is real behaviour-change surface — seven setup-uv majors alone, including changes to cache handling and new `python-version`/`activate-environment` inputs that could change which interpreter CI runs. That deserves its own verification pass rather than riding along inside a one-line false-claim fix.
Blocks-if-unresolved: **all of CI, at once and without warning.** Every run annotates "The following actions target Node.js 20 but are being forced to run on Node.js 24: `actions/cache@v4`, `actions/checkout@v4`, `astral-sh/setup-uv@v3`". They are already executing on a runtime they do not declare; the only thing holding that up is GitHub's compatibility shim. When it is removed, all three fail and no workflow runs. Newer majors declaring `node24` already exist for all three, so this is ours to do, not something that resolves by waiting.
Note: `setup-uv` stopped publishing floating major tags after v7 — `v8`/`v9`/`v10` do not resolve, only exact versions such as `v10.0.1`. Whenever this is done it must pin an exact version or a SHA, consistent with `aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567 # v0.3.1`, currently the only SHA-pinned action in `ci.yml`. Separately, and *not* part of this gap: the cache-save/restore failures on every run since run #1 are GitHub-side and affect both cache consumers independently, so upgrading is not expected to fix them.

### G4 — Trivy's 180s timeout has never been validated against a live DB refresh
Confirmed: M3.4, post-M3.7 · Status: open
Deferral rationale: **the remedy is already written down, and has been since M3.4.** ADR-012's own Consequences names "decoupling DB refresh from per-scan latency entirely via an independent, scheduled refresh job, with every scan then passing `skip_db_update=True` against a cache that's kept warm out-of-band", and defers it as "a legitimate direction" that was not that issue's job. Given the finding below that the refresh runs *inside* the 180s budget rather than alongside it, that stops being a latency optimization and becomes the mitigation. It is deferred again here for the same reason the measurement is: both need a worker running real scans against a cold Trivy cache on production network, which does not exist before deployment. Act without waiting if a production Trivy `failure_reason` ever reads "timed out". One adjacent number is readable today: CI's `Warm Trivy vulnerability DB cache` step runs 0-6s across the twelve runs sampled on 2026-08-20/21, and `actions/cache` reports "Failed to restore: Cache service responded with 400" on every one of them (G3, re-verified against the annotations API for this entry) — so 4-6s is an upper bound on `trivy fs --download-db-only` with GitHub's cache layer contributing nothing, which bounds the happy path at single-digit seconds against 180s. It remains a proxy, not the measurement: `--download-db-only` on GitHub's network from a runner is not a refresh inside a real `trivy fs` on a production worker, and it says nothing about the case that actually matters, a slow or rate-limited registry pull.
Blocks-if-unresolved: **M4 and M5, silently, on any production scan whose DB refresh runs long.** `TrivyAdapter` is wired into `platform/worker.py` with no arguments, so production gets `skip_db_update=False` (live refresh) and `timeout_seconds=180.0`, and that 180s budget covers the refresh *and* the scan in one `trivy fs` invocation — the refresh is inside the scan's budget, not additional to it. On overrun `asyncio.wait_for` raises `ScannerExecutionFailed` (`trivy_adapter.py`), which since M3.7 is caught by `_run_scanner`'s deliberately broad `except Exception` (`run_scan.py`) and recorded as `ScanResult(tool="trivy", status=FAILED)`. It never reaches arq, so **there is no retry and no backoff** — before M3.7 that same exception was in `execute`'s re-raise tuple and arq re-ran the scan, where a transient slow refresh would most likely have succeeded. The scan derives to `PARTIAL`, `get_succeeded_by_scan_id` returns Semgrep and ZAP but not Trivy, and M4 normalizes with **no SCA findings at all** while M5 correlates a view of the system with the entire dependency dimension missing — successfully, with nothing raising and nothing marking the result as incomplete beyond a status field neither module reads. Recovery requires a human to re-trigger.
Note: ADR-016 decision 1 computes `WorkerSettings.job_timeout = 600s` from "ZAP 300s, Trivy 180s, Semgrep 60s" and references ADR-012 nowhere, so the unvalidated number is now an input to a second decision. What is open is *validating* 180s, not a claim that it is wrong — ADR-012 named the issue that would validate it and that issue shipped without doing so. **`Status:` stays `open` rather than `assigned → M11.3`** deliberately: M11.3 is the earliest point at which measuring becomes *possible*, not an issue anybody has scoped this into, so this entry depends on review step 3 re-reading it at each boundary and on escalation at a third confirmation — the intended handling for something unactionable until deploy. **One anomaly in the proxy, recorded rather than smoothed over:** the readings split cleanly at 2026-08-21T14:01Z — 0-1s on every run before, 4-6s on every run after, with no `ci.yml` change between — and that split is not explainable from anything readable without the job log, so 4-6s is the number to trust and the 0-1s runs are unaccounted for rather than "warm". **`Confirmed:` deliberately lists two, not three.** M3.7 encountered the *number*; it never encountered the *deferral* — ADR-016 mentions ADR-012, `skip_db_update` and a DB refresh nowhere at all. This register counts a milestone where a gap was re-encountered *and deferred again*, which presupposes somebody read it and chose not to act, and the threshold exists because "the repetition had become information nobody was acting on". An inadvertent carry-forward is arguably worse, but it is a different thing: counting it would make `Confirmed:` mean something in G4 that it does not mean in G1-G3, and would make the field nearly unfalsifiable, since almost any later decision using a deferred value carries it forward. The mechanism for catching *that* failure is review step 5's widened scope, not this field. Treat the entry as though it were at the threshold anyway — it carries a `Deferral rationale:` voluntarily, which is exactly what the threshold would compel. Recorded here rather than only in ADR-012's Consequences because prose has no `Blocks-if-unresolved:` field and no escalation check — the lesson G1 and G2 already record, this time about an ADR.

### G5 — `Finding` has one `scan_id`, but dedup is required *across* scans
Confirmed: M4.0 · Status: assigned → M4.2
Deferral rationale: the decision belongs to M4.1/M4.2, which own the `Finding` entity and the dedup strategy respectively — M4.0's scope is explicitly the pipeline boundary, and deciding `Finding`'s shape here would design the entity one issue before the issue that builds it, without a single captured scanner fixture to design against (M4.1's own prerequisite). Recorded now rather than at M4.1 because M4.0 edited `ARCHITECTURE.md` §4 and would otherwise have left the tension sitting in prose it had just touched. Resolve at **M4.2**, the issue whose acceptance criterion is "re-running a scan doesn't duplicate identical findings" — that criterion cannot be met without answering this.
Blocks-if-unresolved: **M9.1's re-scan diffing, and M4.2's own acceptance criterion.** `ARCHITECTURE.md` §4 gives `Finding` a single `scan_id` plus a `dedup_hash`, while `PRODUCT_SPEC.md` FR-5 requires deduplication "across repeated scans". With one `scan_id` there are only two outcomes and both are wrong: either the same underlying finding gets a fresh row per scan, so it is duplicated and `dedup_hash` never actually dedupes anything across scans; or the first row is kept and its `scan_id` points at a stale scan, so nothing records that the finding was seen again. M9.1 ("previously open Risks are re-evaluated; resolved ones are marked with the evidence diff that justified it") then cannot distinguish "still present in the latest scan" from "last seen three scans ago" — and it fails *silently*, marking a live finding resolved because no new row carries it. The missing concept is a sighting/occurrence: a `Finding` identified by its dedup hash, with per-scan observations hanging off it.
Note: this is a schema-shape gap, not a bug in anything shipped — no `Finding` code exists yet, which is exactly why it is cheap now and expensive after M4.3 persists the wrong shape and M5 correlates on it.
Note (M4.1): **`Finding` now exists and this entry is still correctly assigned to M4.2 — the sequencing is what makes that safe, and it is written here so a later reader does not mistake it for an oversight.** M4.1 shipped the entity, so at a glance a shape decision now lands *after* the thing it shapes. But M4.1's renumbering put M4.2 ahead of M4.3, so the identity decision still lands before anything is persisted, and the Note above is satisfied on its own terms: nothing reaches disk in the wrong shape, and M5 has nothing to correlate on yet. Moving the entry to M4.1 was considered and rejected — M4.1 had to capture the fixtures first, which is what dissolves this entry's stated blocker, and deciding identity in the same issue would have meant deciding it in the hours after first seeing the data. M4.1 hands M4.2 the per-tool identity candidates instead, including the finding that Semgrep's `fingerprint` is unusable (it is the literal string `"requires login"`), and leaves `dedup_hash` off `Finding` entirely rather than shipping a placeholder.

### G6 — Semgrep's pinned ruleset declares no CWE or OWASP metadata
Confirmed: M4.1 · Status: open
Blocks-if-unresolved: **M6, silently, and M5's CWE-based matching with it.** `rulesets/default.yml` has no `metadata:` block at all — verified against real captured output, where `extra.metadata` is `{}` — so every Semgrep `Finding` in production carries `cwe = None` and `owasp_category = None`. M6's `RiskReasoning` and any CWE-based correlation in M5 therefore see nothing from SAST: not an error, not a gap anything reports, just an entire signal dimension permanently absent for one of three tools while the code reading it looks correct. Trivy supplies `CweIDs` and ZAP supplies `cweid`, so the asymmetry is invisible unless someone groups findings by `source`. The same empty `metadata` also means Semgrep supplies no confidence, which is one of the inputs M6.1 needs for its own deferred decision on that field. Distinct from **G7**, which is the token-gated half of Semgrep's degraded output and has an independent cause and fix.
Deferral rationale: the two fixes are a production scanning-configuration change, not a mapper change, and neither belongs in an issue about the domain model. Either add `metadata: {cwe: [...], owasp: [...]}` to the pinned rule — cheap, but it is editing what production scans with — or widen the ruleset, which the determinism-over-registry-breadth reasoning in `default.yml`'s own comment argues against without its own decision. The mapper is already correct: it reads both fields when a rule declares them, and a synthetic fixture proves it, so resolving this needs no code in `normalization` at all. Re-read when M5.1 picks its matching signals, and again when M6.1 defines `severity_signal`.
Note: not a bug in anything shipped, and deliberately not worked around — a mapper that invented a CWE would be feeding the Risk Engine an untraceable input, which is rule 5 violated one layer upstream of where anyone would look for it (ADR-0018 decision 4).
Note: this is the *ruleset* half of Semgrep's degraded output. The token half is **G7**, and the two are independent — adding `metadata:` to `default.yml` does nothing for `fingerprint`/`lines`, and setting a token does nothing for CWE or OWASP. Conflating them would make either fix look like both.

### G7 — Two Semgrep fields are redacted because no `SEMGREP_APP_TOKEN` is set, and setting one silently arms a rule-12 exposure
Confirmed: M4.1 · Status: open
Blocks-if-unresolved: **M4.5's response surface and M4.2's identity options, in opposite directions, on a config change nobody would connect to either.** Semgrep OSS redacts `extra.fingerprint` and `extra.lines` to the literal string `"requires login"` for anonymous users, and this repo sets `SEMGREP_APP_TOKEN` nowhere — not in `ci.yml`, not in `Settings`, not in `.env`. Verified against real captured output. Two consequences, both of which flip the moment somebody adds a token for better rules or telemetry: (1) **`extra.lines` becomes the matched source line.** It is inside `Evidence.raw_payload`, which M4.5's endpoint returns, and secret-detection rules match secrets — so a token turns a rule-12-inert field into a rule-12-live one with no code change and no review of M4.5. (2) **`fingerprint` becomes usable as a dedup/identity input**, which M4.2 will have already designed around, having been told (correctly, today) that it is a constant. Nothing raises in either direction; the first is a leak and the second is a missed option.
Deferral rationale: nothing is wrong today — no token means no source in the payload — so there is nothing to fix, only something to *notice at the right moment*, which is exactly what this register is for and what prose has repeatedly failed to do (the G1 lesson). Adding a token is a real decision with its own trade-offs (Semgrep's registry becomes a network dependency of every scan, which `rulesets/default.yml`'s own comment argues against, and it sends scan telemetry off-box) and it is not M4.1's to make. Re-read when M4.2 picks identity inputs, and again at M4.5 before deciding what the endpoint exposes — both entries already carry the conditional wording.
Note: the fix, if a token is ever added, is not to remove it: it is to decide deliberately what M4.5 returns, per rule 12 and rule 10 (a dedicated response schema, never the entity). Separately from `Finding`, this is also why M4.1 did *not* treat `"requires login"` as a sentinel and null it out — the string is the tool's real output, and `raw_payload` is a verbatim copy by design (ADR-0018 decision 6).

### G8 — `ruff --fix` runs on every commit and can silently rewrite a test into a weaker one
Confirmed: M4.1 · Status: open
Blocks-if-unresolved: **any future `--fix` over a test whose assertion is structural — the result is a test that passes while asserting less than its name, its docstring and (in the case that produced this entry) its ADR all claim, with nothing in the pipeline that detects the gap.** It has already happened once, in the commit that opened this entry. `test_severity.py` asserted that `Severity`'s comparison operators reject a non-`Severity` operand in **both** operand orders. `ruff`'s SIM300 (yoda-conditions) rewrote `Severity.HIGH < other` to `other > Severity.HIGH` and `Severity.HIGH >= other` to `other <= Severity.HIGH`, which collapsed four distinct assertions into two duplicated pairs and deleted every direct-order case. The rewrite is *semantically* valid — both forms raise — which is exactly why no tool objected: in a test whose subject **is** the operand order, a semantics-preserving rewrite is still a coverage-destroying one, and ruff cannot know the difference. ADR-0018 then stated in writing that both orders were "verified directly, not assumed, and pinned by a test". The verification had been correct; the tool invalidated it afterwards, and the claim outlived it. This is the `test_tampered_state_is_rejected` failure shape with the author replaced by an automatic tool.
The mechanism, verified rather than assumed: `.pre-commit-config.yaml` runs the `ruff` hook with `args: [--fix]`, so it fires on **every commit**, not only when invoked by hand. `ci.yml` runs `ruff check .` with no `--fix`, so CI never introduces a rewrite — and never catches one either. Probed directly with a throwaway file: the hook rewrites on disk, fails the commit with "files were modified by this hook", and leaves the **original** in the index, so the developer re-runs `git add` and commits. `pytest` is not a pre-commit hook, so the rewritten test is never re-executed before the commit lands; CI then runs the weakened test and it goes green. Nothing else looks: `check_claims.py` re-derives claims from artifacts but cannot see that an assertion stopped asserting what it says, the suppression metric is blind to it, and review step 5 reads ADRs rather than tests.
Deferral rationale: the blast radius today is **one file, and it is closed.** `Severity` is the only type in `src/` that overrides a comparison operator (verified by grep for `__lt__`/`__le__`/`__gt__`/`__ge__`/`__eq__`/`total_ordering`), `test_severity.py` is the only test where operand order is the subject, and it is now written with `operator.lt(a, b)` rather than infix — a function call is not a comparison expression, so SIM300 has nothing to rewrite. `ruff check tests/ --diff` and `ruff check src/ --diff` are both currently empty, and a scan of `tests/` for the other rewritable structural patterns (constant-on-left comparisons, `== None`/`== True`, `not x in`) returns zero hits. So there is nothing to fix right now — only a trap to notice the next time a test's subject is the *shape* of an expression. **Explicitly not resolved with `# noqa: SIM300`:** that would take the tracked suppression count from 0 to 1 for convenience, which is precisely the decay the metric exists to detect, and it would leave the rewrite one deleted comment away from happening again.
Note: the real options, when this next matters, are (a) keep writing such tests in `operator`-function form, which is what M4.1 did and costs nothing, (b) drop `--fix` from the pre-commit hook so the tool reports and a human edits, or (c) add `pytest` to pre-commit so a rewrite is re-executed before the commit lands — (c) is the only one that generalizes beyond comparisons, and it is also the one that puts the full suite in the commit path, which `CLAUDE.md`'s tracked runtime makes expensive. Re-read whenever a test is added whose subject is argument order, operand order, or expression structure, and at any change to `.pre-commit-config.yaml`.

---

## V2 Backlog (explicitly out of this roadmap)

Tracked separately, not scheduled: AI-driven automated remediation, attack graph modeling, MCP/LLM security scanning, cloud/CSPM integration, runtime telemetry, additional scanners, team collaboration, Jira/Slack integrations, advanced analytics, fix-effort prediction as a scored dimension.
