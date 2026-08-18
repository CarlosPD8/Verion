# Verion

**From security findings to security decisions.**

Verion is a developer-first AppSec platform that unifies signals from existing security tools — SAST, SCA, secrets, DAST — understands the context of the application being protected, correlates evidence across sources, and turns raw findings into prioritized, explainable, and verifiable remediation decisions.

> **Status:** early development (M0). This repo currently holds the product and architecture specs; implementation is in progress following the roadmap below.

---

## The problem

Modern AppSec tooling is excellent at detecting issues and increasingly good at generating individual fixes. It's still weak at the layer in between: helping a developer understand, out of 100+ findings from several disconnected tools, **which 3 things actually matter today, why, and what to do about them.**

Verion doesn't compete with scanners — it sits on top of them.

```
Semgrep, Trivy, ZAP findings
            │
            ▼
  Normalization → Correlation → Risk scoring → Explanation
            │
            ▼
      A ranked, evidence-backed Security Brief
```

## Core differentiators

- **Decision-oriented, not detection-oriented** — surfaces the few things that matter instead of a wall of findings.
- **Evidence-backed correlation** — related findings across tools (e.g. SAST + DAST on the same endpoint) are grouped into one traceable risk.
- **Explainable scoring** — every priority is a traceable function of severity, exposure, reachability, and asset sensitivity, never an opaque number.
- **Stack-aware context** — recommendations account for the actual framework, deployment, and data sensitivity of the project being scanned.

## Architecture

Verion is built as a **modular monolith using Hexagonal Architecture (Ports & Adapters)**: each module (identity, projects, scanning, normalization, correlation, risk engine, brief, history) keeps its domain logic free of framework and infrastructure dependencies, with scanners, storage, and the LLM explanation layer plugged in as swappable adapters.

Full design and rationale: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Tech stack

| Layer | Choice |
|---|---|
| API | FastAPI |
| Frontend | Next.js |
| Database | PostgreSQL |
| Queue / cache | Redis |
| SAST | Semgrep |
| SCA / container | Trivy |
| DAST | OWASP ZAP (Automation Framework) |
| VCS | GitHub API / GitHub Actions |
| Containerization | Docker / docker-compose |

## Documentation

| Document | Contents |
|---|---|
| [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md) | Vision, personas, functional requirements, MVP/V2 scope |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Hexagonal architecture, module boundaries, domain model, sequence diagrams |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | 16-week plan, milestones, issue-level breakdown |
| [`docs/adr/`](docs/adr) | Architecture decision records |
| [`CLAUDE.md`](CLAUDE.md) | Project conventions and non-negotiable rules for AI-assisted development |

## Roadmap status

Building in 16 weeks across 12 milestones — see [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full breakdown.

- [ ] M0 — Foundations
- [ ] M1 — Identity & Projects
- [ ] M2 — Security Context
- [ ] M3 — Scanning Infrastructure
- [ ] M4 — Normalization
- [ ] M5 — Correlation Engine
- [ ] M6 — Risk / Decision Engine
- [ ] M7 — Security Brief / Explanation Layer
- [ ] M8 — Dashboard & History
- [ ] M9 — Verification Loop
- [ ] M10 — Security Hardening
- [ ] M11 — Testing, Docs, Deployment

## Getting started

Setup instructions will be added once M0 (repository scaffolding) is complete.

## License

MIT.
