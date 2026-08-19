# CLAUDE.md — Project Context for Claude Code

This file is read automatically by Claude Code at the start of every session. It exists so the project's intent, architecture, and conventions don't need to be re-explained. Keep it in sync as the project evolves — if a rule here stops being true, fix this file in the same PR that changed the reality.

---

## What this project is

**Verion** — a developer-oriented AppSec platform that converts security findings from existing scanners (Semgrep, Trivy, OWASP ZAP) into correlated, explainable, prioritized remediation decisions.

North star: *"From security findings to security decisions."*

Full context lives in:
- `docs/PRODUCT_SPEC.md` — vision, personas, functional requirements, MVP/V2 scope
- `docs/ARCHITECTURE.md` — hexagonal architecture, module boundaries, domain model, sequence diagrams
- `docs/ROADMAP.md` — 16-week plan, milestones, issue-level breakdown
- `docs/adr/` — architecture decision records

**Read `PRODUCT_SPEC.md` and `ARCHITECTURE.md` before making any structural decision.** If a task isn't covered by `ROADMAP.md`, check whether it fits the current milestone before starting it — don't silently expand scope.

---

## Non-negotiable architectural rules

This project uses **Hexagonal Architecture (Ports & Adapters)** inside a **modular monolith**. These rules are enforced by CI (import-linter), not just convention:

1. `domain/` code has **zero imports** from `adapters/`, FastAPI, SQLAlchemy, or any third-party framework. Pure Python only.
2. `application/` (use cases) orchestrates `domain/` through **ports** (interfaces), never through concrete adapters.
3. A module never imports another module's `domain/` or `adapters/` directly — only its published ports.
4. Every new external integration (a scanner, an LLM provider, a VCS) is added as an **adapter implementing an existing or new port** — never by special-casing it inside application/domain logic.
5. The **Risk/Decision Engine's scoring must stay traceable to explicit inputs.** Do not introduce a black-box ML model or an unexplained numeric score. If you're tempted to, stop and flag it — this breaks the product's core value proposition.
6. **The LLM (Explanation Layer) narrates decisions already made by the Risk Engine — it never determines priority.** Structured scoring happens first and is persisted; the LLM call only turns that structured result into readable text.

If a requested change would violate one of these, say so explicitly before implementing it, rather than working around it silently.

---

## Testing requirements (definition of done)

No issue is complete without:

- **Unit tests** for any `domain/` or `application/` code, using **in-memory fakes of the relevant ports** — no real DB/network/LLM calls in unit tests.
- **Integration tests** for any new adapter, against the real dependency (Postgres, Redis, or the actual tool CLI/API), using `docker-compose` services.
- For `correlation` and `risk_engine` specifically: tests must cover both positive cases (should correlate / should score high) and negative cases (should NOT correlate / should score low) — these two modules are the product's core differentiator and deserve disproportionate test rigor.
- Passing CI (lint, import-linter architecture check, unit + integration tests) before considering an issue done.

---

## Working style

- Work **one roadmap issue at a time** (see `ROADMAP.md`). Don't bundle unrelated changes into one PR.
- Before implementing, restate which module and which port(s)/entities are involved, so we can catch architecture drift before writing code, not after.
- Prefer small, reviewable diffs over large ones — this project is meant to demonstrate engineering discipline, and that includes commit/PR hygiene.
- When a decision has real trade-offs (e.g., how to weight a signal in the Risk Engine, how to structure a correlation rule), surface the trade-off and a recommendation rather than silently picking one — these are exactly the decisions worth documenting in an ADR.
- If you add a new architectural decision of consequence, propose an ADR entry in `docs/adr/` rather than only writing code.

---

## Third-party skills

The `fastapi-python` marketplace skill (`mindrally/skills`, installed via the `skills.sh` CLI — `npx skills add mindrally/skills@fastapi-python`) may be active in this project. Its guidance applies ONLY within `src/verion/modules/*/adapters/inbound/api/` (routing style, Pydantic conventions, HTTP error handling, naming).

It does NOT override this file's architectural rules. In particular:

- Its "Dependencies: FastAPI, Pydantic v2, asyncpg/aiomysql, SQLAlchemy 2.0" guidance must never result in `domain/` or `application/` importing SQLAlchemy directly — persistence stays behind `*RepositoryPort`, implemented only in `adapters/outbound/db/`, per ADR-002 and the import-linter contracts in ADR-007.
- Its dependency-injection suggestions must not lead to ad-hoc, inline `Depends()` wiring scattered across endpoints — all wiring goes through named factory functions in `platform/di.py`, per ADR-008.
- Its "favor functional, declarative programming over class-based approaches" preference applies to routes/utilities, not to `domain/` entities or value objects, which may be modelled as classes, dataclasses, or Protocols where that's the clearer design.

If a suggestion from that skill conflicts with any rule elsewhere in this file, this file wins.

---

## Tech stack quick reference

| Layer | Choice |
|---|---|
| API | FastAPI |
| Frontend | Next.js |
| DB | PostgreSQL |
| Queue/cache | Redis |
| SAST | Semgrep |
| SCA/container | Trivy |
| DAST | OWASP ZAP (Automation Framework) |
| VCS | GitHub API / Actions |
| Containerization | Docker / docker-compose |

---

## Things to actively avoid

- Don't build a SAST/SCA/DAST engine from scratch — Verion integrates existing tools, it doesn't replace them (see `PRODUCT_SPEC.md` §2 for the explicit rationale).
- Don't add V2-scope features (automated PR remediation, attack graphs, MCP/LLM security scanning, cloud/CSPM, Jira/Slack integration) without an explicit decision to pull them into the current roadmap.
- Don't let a scanner adapter's output format leak into `correlation/` or `risk_engine/` — everything downstream of `normalization/` speaks only the common `Finding` schema.
- Don't interpolate raw scanned source/finding content directly into an LLM prompt without going through the sanitization step defined for the Explanation Layer (`ROADMAP.md` M7.3) — scanned content is untrusted input.
