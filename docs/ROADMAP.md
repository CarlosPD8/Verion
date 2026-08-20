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
  - Import-linter (or dependency-cruiser) rule added and passing on empty scaffolding, enforcing the dependency rule from `ARCHITECTURE.md` §10.

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

> **Note — multi-scanner orchestration is M3.7.** M3.2/M3.4/M3.5 each add exactly one scanner path end to end (per M3.2's own "first scanner, walking skeleton" framing), and `platform/worker.py` dispatches `SemgrepAdapter` alone. Carrying that gap unassigned through three issues was deliberate, but a post-M3 review moved it onto the critical path: M4 designs the `Finding` schema and its per-scanner mappers, and M5 exists specifically to correlate findings across *different* tools — neither is meaningfully exercisable while a `Scan` can only ever produce one `ScanResult`. Assigned as M3.7 below, ahead of M4.

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

- **M3.7 — Multi-scanner dispatch**
  Module: `scanning` · Depends on: M3.3, M3.4, M3.5
  - One trigger fans out to every scanner enabled for the project. **Prerequisite for M4 and M5**, not a nice-to-have: `CorrelateFindingsUseCase` (M5.1) exists to link findings from *different* tools, and a `Scan` can currently only ever produce one.
  - **This is drift, not an open design question.** The schema and the architecture doc already assume N tools per scan — `ScanResultModel`'s `UniqueConstraint(scan_id, tool)`, `ARCHITECTURE.md` §4's `raw_results: [ScanResult]  # one per tool that ran`, and §8's sequence diagram showing `ScannerPort (Semgrep/Trivy/ZAP)` returning per-tool results. Only the roadmap and the code diverged from that.
  - **This issue is a decision first and code second** — the four questions below get answered and recorded in an ADR before implementation.
  - **Decision — dispatch shape:** one arq job per `Scan` running scanners concurrently, vs. fan-out to one job per `(scan, tool)`. The `(scan_id, tool)` constraint already anticipates fan-out; a single job keeps `RunScanUseCase` the sole owner of `Scan` status, as M3.3's state machine deliberately designed it. Weigh ZAP's 300s timeout against Semgrep's 60s when sizing a shared job budget.
  - **Decision — partial-failure semantics:** `PRODUCT_SPEC.md` §12 already requires surviving "ZAP times out but Semgrep succeeds" without corrupting state. `ScanStatus` cannot express that today, and one `Scan`-level `failure_reason` cannot say *which* tool failed. Decide where per-tool outcome lives and what `Scan.status` derives to. A blanket `Scan`-level `FAILED` would discard a succeeding scanner's output — precisely the corruption §12 forbids — and M4 must be able to tell which raw results are safe to normalize.
  - **Decision — where per-project scanner configuration lives:** nothing stores which scanners a project enables, nor ZAP's target URL; M3.5's "optional per project" was never given a home. Decide between new columns on `SecurityContext` and a dedicated config entity in `projects`. **Do not overload `SecurityContext.exposure_tags`** — that is user-confirmed annotation owned by `UpdateExposureTagsUseCase`, not configuration. `scanning` reads whichever is chosen through a published port, same precedent as `ConnectedRepoRepositoryPort` (rule 3).
  - **Decision — whether `ScannerPort` gains a tool identity:** dispatch must select scanners by name, but `tool` is only known *after* `run()` returns, inside `RawScanResult`.
  - `ScanStatus` / `ScanResult` schema changes land with Alembic migrations.
  - **SSRF re-validation stays inside `ZapAdapter.run()`** — persisting a validated target does not replace ADR-013's gate, since DNS can rebind between configuration time and scan time, which is the entire reason the gate exists.
  - Integration test: one trigger produces `ScanResult` rows for more than one tool, and a deliberately failing scanner does not discard a succeeding scanner's output.

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

## V2 Backlog (explicitly out of this roadmap)

Tracked separately, not scheduled: AI-driven automated remediation, attack graph modeling, MCP/LLM security scanning, cloud/CSPM integration, runtime telemetry, additional scanners, team collaboration, Jira/Slack integrations, advanced analytics, fix-effort prediction as a scored dimension.
