# Verion — Product Specification

**Status:** Draft v1.0
**Owner:** [Your Name]
**Last updated:** 2026-08-21

---

## 1. Product Vision

**North Star:**
> "From security findings to security decisions."

Verion is a developer-oriented AppSec platform that unifies signals from existing security tools (SAST, SCA, secrets, DAST), understands the context of the application being protected, correlates evidence across sources, and converts raw findings into prioritized, explainable, and verifiable remediation decisions.

Verion does not compete with scanners. It sits on top of them, turning the output of tools like Semgrep, Trivy, and OWASP ZAP into something a developer can actually act on in minutes rather than hours.

---

## 2. Problem Statement

Modern AppSec tooling is very good at **detection** and increasingly good at **generating individual fixes**. It is still weak at the layer in between: helping a developer understand, out of 100+ findings from 3-4 disconnected tools, **which 3 things actually matter today, why, and what to do about them.**

Symptoms of this gap:

- Findings from different scanners are not correlated, so the same underlying risk appears as 4 unrelated tickets.
- Severity scores (CVSS, tool-specific ratings) are context-free — a "critical" finding in dead code ranks the same as a "critical" finding on a public authentication endpoint.
- Developers receive lists, not explanations. There's rarely a "why does this matter *here*" attached to a finding.
- Verifying that a fix actually worked usually means re-running everything manually.

Verion's thesis: **the differentiator is not another detector — it's the decision layer above the detectors.**

---

## 3. Target User & Personas

### Primary user: the individual developer / small team
Someone who receives security findings as part of their normal workflow (PRs, CI pipelines) and is expected to act on them without being a security specialist.

**Persona — "Alex", Backend Developer**
- Works at an early-stage startup or mid-size product team, ~5-8 engineers, no dedicated security hire.
- Gets a wall of Dependabot/Semgrep alerts on every PR and mostly ignores or bulk-dismisses them.
- Wants: "tell me what's actually dangerous and how to fix it," not a dashboard to interpret.

**Persona — "Priya", Engineering Lead / Security Champion**
- Not a full-time security engineer, but accountable for the team's security posture.
- Needs a defensible way to say "these are the top risks in our stack and here's the evidence," e.g. for a board update or a customer security questionnaire.
- Wants: correlated, auditable risk reporting — not a raw findings export.

### Secondary user (future / V2)
Security engineers at slightly larger orgs who want a correlation and triage layer across multiple existing tools instead of building one in-house.

---

## 4. User Journeys

### Journey 1 — Onboarding a project
1. User signs up and creates a project.
2. Connects a GitHub repository.
3. Verion detects the stack (framework, language, dependencies, deployment config) to build the **Security Context**.
4. User confirms/adjusts detected context (e.g., "this API is public-facing," "this service touches PII").

### Journey 2 — Running a scan
1. Scan is triggered manually or via CI (GitHub Actions).
2. Workers dispatch Semgrep (SAST), Trivy (SCA/containers), and OWASP ZAP (DAST, if configured) against the project.
3. Raw results are normalized into the common `Finding` schema.
4. Correlation Engine groups related findings into candidate risks.
5. Risk/Decision Engine scores and prioritizes.
6. AI Explanation Layer produces a **Security Brief**.

### Journey 3 — Reviewing a Security Brief
1. User opens the project dashboard and sees a short, ranked list ("Fix now" / "Plan" / "Monitor") instead of a raw findings table.
2. For each item: why it matters, supporting evidence (which tools/sources contributed), recommended action, estimated effort, confidence level.
3. User can drill into raw evidence at any time — nothing is a black box.

### Journey 4 — Fixing and verifying
1. User applies the recommended fix.
2. Triggers re-scan (manual or automatic on push).
3. Verion re-evaluates the specific risk and marks it resolved, with a diff of what evidence changed.
4. Resolution is logged in the project's security history.

---

## 5. Core Concepts

| Concept | Description |
|---|---|
| **Security Context** | The structured understanding of what is being protected: framework, language, DB, APIs, auth mechanism, deployment target, dependencies. Conditions how everything downstream is interpreted. |
| **Finding** | A normalized unit of output from any scanner, mapped to a common schema (vulnerability, severity, source, asset, evidence, location, CWE, OWASP category, CVSS, references). |
| **Correlation** | The process of linking findings from different tools/sources that plausibly describe the same underlying attack surface. |
| **Risk** | A correlated, contextualized group of evidence with a computed priority, confidence, and reasoning — the actual unit a developer should think about. |
| **Security Brief** | The developer-facing explanation of a Risk: what happened, why it matters, what to do, how to verify. |

---

## 6. Functional Requirements (MVP)

**FR-1 — Authentication & Users**
Users can sign up, log in, and manage a personal account. Basic RBAC (owner/member) at the project level.

**FR-2 — Projects & Repositories**
Users can create a project and connect one GitHub repository to it.

**FR-3 — Security Context extraction**
System detects language, framework, key dependencies, and deployment signals (Dockerfile, CI config) from the connected repo and stores them as structured Security Context. User can manually annotate context (e.g., "public-facing," "handles PII").

**FR-4 — Scanning**
System can trigger scans (manual + on-push via GitHub Actions) that run:
- Semgrep (SAST)
- Trivy (SCA / dependency & container scanning)
- OWASP ZAP (DAST, optional, requires a reachable target)

**FR-5 — Finding Normalization**
All raw scanner output is transformed into the common `Finding` schema, including deduplication of identical findings across repeated scans.

**FR-6 — Correlation Engine (basic)**
System groups findings that share asset/location/context signals (e.g., same endpoint referenced by SAST and DAST) into a single candidate Risk.

**FR-7 — Risk / Decision Engine**
System computes priority and confidence for each Risk using an explainable combination of: severity, confidence, exposure, reachability (where available), asset sensitivity, and environment. Every score must be traceable to its inputs — no unexplained single number.

**FR-8 — Security Brief**
For each prioritized Risk, system generates a structured explanation: what happened, why it matters, evidence sources, recommended action, estimated effort (qualitative), confidence.

**FR-9 — Evidence traceability**
Every Risk and every Brief must link back to the raw findings and tool output that produced it.

**FR-10 — Scan history**
Users can see prior scans, resolved risks, and re-opened risks over time per project.

---

## 7. Non-Functional Requirements

- **Explainability over automation:** every score, correlation, and recommendation must be traceable to explicit inputs. No opaque "AI magic number."
- **Extensibility:** adding a new scanner should only require a new adapter into the `Finding` schema, not changes to correlation/risk logic.
- **Reliability of scanning:** scan jobs must be idempotent and safely retryable (workers can fail/restart without corrupting state).
- **Security of the platform itself:** Verion handles sensitive data (source code context, vulnerability details) and must be built to the same standard it recommends — see Section 11.
- **Reasonable performance:** a scan + brief generation for a typical small/medium repo should complete within a few minutes, not hours.
- **Auditability:** all resolved/dismissed risks must retain a permanent history (who, when, why).

---

## 8. MVP Scope

**Core**
- Auth, users, projects, repositories
- Security Context capture
- Scans (manual + CI-triggered)
- Findings (ingestion, normalization, deduplication)
- Evidence storage
- Basic Correlation Engine
- Risk / Decision Engine
- Security Brief (AI-generated explanation layer)
- Scan history

**Integrations**
- GitHub (repo connection, CI trigger)
- Semgrep (SAST)
- Trivy (SCA / container)
- OWASP ZAP (DAST)

**Infrastructure**
- Docker, PostgreSQL, Redis, background workers, GitHub Actions

**Security**
- Threat model documented
- RBAC
- Rate limiting
- SSRF protection (relevant given DAST targets are user-supplied URLs)
- Secure secrets management
- Audit log
- Security headers
- Dependency scanning on Verion's own codebase (dogfooding)

**Quality**
- Unit, integration, and E2E tests
- CI pipeline
- Documentation
- Deployment setup

---

## 9. Out of Scope for MVP (V2 candidates)

- AI-driven automated remediation (auto-generated PRs)
- Advanced attack graph / attack path modeling
- LLM / MCP security scanning
- Cloud misconfiguration integration (CSPM-style)
- Runtime telemetry ingestion
- Additional scanners beyond Semgrep/Trivy/ZAP
- Team collaboration features (comments, assignment workflows)
- Jira / Slack integrations
- Advanced analytics / trend dashboards
- Fix-effort prediction as a first-class scored dimension (kept as an informal, non-authoritative signal in MVP)

Rationale: MCP/LLM security in particular is an active, fast-moving space (see StackHawk's positioning) but including it now would blow up MVP scope before the core correlation/decision thesis is proven.

---

## 10. Success Metrics

Since this is a portfolio/CV project rather than a funded product, success is measured primarily by **what it demonstrates**, secondarily by **product quality signals**:

**Demonstration goals**
- End-to-end working pipeline: repo → scan → normalized findings → correlated risk → explained, verifiable brief.
- At least one clear, demonstrable case where correlation across 2+ tools produces a materially better prioritization than looking at raw tool output.
- Clean, defensible architecture and code quality (tests, CI, docs) suitable for technical interviews.

**Product-quality signals (even without real users)**
- Noise reduction: ratio of raw findings to surfaced Risks on a representative test repo.
- Explainability: 100% of surfaced Risks have traceable evidence and a non-opaque priority reason.
- Time-to-brief: time from scan trigger to Security Brief availability for a representative repo.

---

## 11. Security Principles

1. **Threat model first.** Document Verion's own attack surface before writing scanning/orchestration code (it executes/proxies against user-supplied targets — SSRF and injection risk is real, not theoretical).
2. **Least privilege by default.** GitHub App / API tokens scoped to the minimum required; RBAC enforced at the project level.
3. **Secrets never touch application logs or the database in plaintext.**
4. **SSRF protection is mandatory** for any component that triggers DAST scans against user-provided URLs.
5. **Everything auditable.** Every risk state change (opened, dismissed, resolved) is logged with actor and timestamp.
6. **Dogfooding.** Verion should scan its own repository as part of CI, using itself as the first proof point.
7. **Inbound events are verified before they are trusted.** Any endpoint accepting provider-originated events (GitHub push/PR today) verifies the payload signature over the *raw* request body before any use case runs, and deduplicates redeliveries. An unauthenticated endpoint that triggers real work — cloning a repo, running scanners — is otherwise a spoofing and free-work surface. See ADR-014. *(Appended as 7 rather than inserted: `§11.1` and `§11.5` are cited by ADR-011 and ADR-014, so renumbering would break them.)*

---

## 12. Architecture Principles

- **Modular monolith, not microservices.** FastAPI + PostgreSQL + Redis + background workers is sufficient; premature service decomposition adds operational cost without benefit at this scale.
- **Adapter pattern for scanners.** Each tool integration (Semgrep, Trivy, ZAP, future tools) implements a normalization adapter into the common `Finding` schema — correlation and risk logic never depend on tool-specific formats.
- **Evidence-first data model.** Risks are never stored without a link back to the Findings/Evidence that produced them.
- **Idempotent, retryable workers.** Scan orchestration must tolerate partial failure (e.g., ZAP times out but Semgrep succeeds) without corrupting project state.
- **Explainable scoring, not black-box ML.** Risk scoring in MVP is a documented, inspectable function of explicit signals — not a trained model with hidden weights. This keeps the "why" answerable, which is core to the product's value proposition.

---

## 13. Initial Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Frontend | Next.js | Dashboard, Security Brief UI |
| Backend / API | FastAPI | Core API, orchestration |
| Database | PostgreSQL | Projects, findings, risks, history |
| Cache / Queue | Redis | Job queue for scan workers |
| Background processing | Python workers | Scan orchestration, normalization, correlation |
| SAST | Semgrep | |
| SCA / Container | Trivy | |
| DAST | OWASP ZAP (Automation Framework) | |
| Source integration | GitHub API / GitHub Actions | Repo connection, CI-triggered scans |
| Containerization | Docker | |
| CI/CD | GitHub Actions | |

---

## 14. Next Steps

1. `ARCHITECTURE.md` — data model, service boundaries within the monolith, sequence diagrams for the scan → brief pipeline.
2. Data model design (Finding, Risk, Evidence, Security Context schemas).
3. 16-week roadmap broken into milestones and issues for implementation (Claude Code-ready).
