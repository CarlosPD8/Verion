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

- **M4.1 — Finding domain model**
  Module: `normalization` · Depends on: M3
  - `Finding`, `Evidence` entities per `ARCHITECTURE.md` §4.
  - Pure mapping functions per scanner (Semgrep→Finding, Trivy→Finding, Zap→Finding), unit tested against real sample tool outputs (fixtures, not live scans).

- **M4.2 — Deduplication**
  Module: `normalization` · Depends on: M4.1
  - Dedup hash strategy; re-running a scan doesn't duplicate identical findings.

- **M4.3 — Persistence + API**
  Module: `normalization` · Depends on: M4.1
  - Postgres adapter, `GET /projects/{id}/findings` endpoint.

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
4. **Compare tracked metrics against the latest green CI run** — the `Tests (pytest …)` step duration and the suppression count — and record the new baseline in `CLAUDE.md`. *This is where the ±8s variance and the 71%-of-runtime-in-2-tests concentration surfaced.*
5. **Spot-check the newest adapter against the Tier 2 ADRs** — ADR-011's nine subprocess points and ADR-013's gate placement. CI cannot see these, and adapters are the only place they apply.

### Keeping it from becoming box-ticking

A checklist that reports "all clear" every time is worse than no checklist. Two mitigations:

- **Every step produces a written artifact** — either a finding, or an explicit "checked X against Y, no change". Recorded in the review's commit message, and summarised as one row in the log below. "No change" is a valid result; silence is not.
- **The exit ramp, defined now rather than when it is needed.** If **two consecutive reviews** produce only "checked, no change" artifacts for **steps 1, 3, and 5** — meaning no finding, no new issue, and no register entry from any of those three, twice running — cut the cadence to every other milestone. A step recorded as **not performed** does not count as "checked, no change" and does not advance this test; only a step that was actually run and found nothing does. Record it as a new row in the log with `Cadence:` set to the new value, and say why in that review's commit message. Steps 2 and 4 are excluded from this test on purpose: they are mechanical and will keep passing, so including them would make the condition unreachable.

### Review log

One row per review. The last two rows are what the exit-ramp test reads.

| Date | Boundary | Steps with findings | Cadence |
|---|---|---|---|
| 2026-08-20 | post-M3 | 1 (M3.7 critical path); 2 (7 doc drifts, incl. `vcs_provider.py`); 3 (register created, G1 seeded retrospectively); 4 (runtime + suppression baselines recorded); 5 **not performed** — this checklist postdates the pass | every milestone |
| 2026-08-21 | post-M3.7 (M3→M4) | 1 (no captured scanner-output fixtures; §8's pipeline/`status=complete` conflicts with the M3.3/M3.7 state machine; §9's `IngestScanResultUseCase` does not exist); 2 (§4 stale for `Scan`/`ScanResult`; §4's `Finding.source` duplicates `ScannerTool`) — **plus 3 more found only after this pass widened step 2's scope**, which is the change recorded above: `PRODUCT_SPEC.md`'s "see Section 12", §11's missing webhook principle, `README.md` claiming M0/not-runnable four milestones late; 3 **checked, no change** — G1 resolved → M3.7, G2 re-read against M4 and not on its critical path; 4 (pytest step 45s → **64s**, suppressions 0/0 unchanged); 5 (ADR-011 point 9's "not a credential" premise became conditionally false when M3.7 made the ZAP target user-configured) | every milestone |

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
Confirmed: M3.7 · Status: open · Deferral rationale: fixing it now means normalizing `scanner_configs` to `(project_id, tool)` for a second URL scanner that does not exist and that `PRODUCT_SPEC.md` §9 puts in V2 — the pre-normalizing-for-a-hypothetical that ADR-016 decision 3 argues against, on the same reasoning ADR-014 used to reject a per-project webhook secret. Resolve on the trigger already stated there: **when a second tool needs tool-specific settings.**
Blocks-if-unresolved: any future `ScannerTargetKind.URL` scanner. `RunScanUseCase.execute` takes a single `zap_target_url: str | None` and routes it in the `else` branch of the `target_kind` check, so a second URL-kind adapter is silently handed **ZAP's** target rather than its own. It fails silently — the scanner runs, succeeds, and produces a real `ScanResult` for the wrong target, which M4 then normalizes and M5 correlates as if it were that tool's view of the system. Nothing raises, and no test today would catch it.
Note: `ScannerPort.target_kind` itself is fine — dispatch's *shape* is generic and carries no `tool == "zap"` branch (rule 4). What is per-integration is the *value*, in the use case's signature. Recorded here and not only in ADR-016 because prose has no `Blocks-if-unresolved:` field and no escalation check, which is the exact lesson G1 above is the record of.

---

## V2 Backlog (explicitly out of this roadmap)

Tracked separately, not scheduled: AI-driven automated remediation, attack graph modeling, MCP/LLM security scanning, cloud/CSPM integration, runtime telemetry, additional scanners, team collaboration, Jira/Slack integrations, advanced analytics, fix-effort prediction as a scored dimension.
