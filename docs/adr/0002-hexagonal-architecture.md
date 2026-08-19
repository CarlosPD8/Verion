# ADR-002: Hexagonal architecture (ports & adapters) at the module level

## Status

Accepted

## Context

Two hard requirements from `PRODUCT_SPEC.md` drove this decision. First, adding a new scanner (Semgrep, Trivy, ZAP, and future tools) must only require a new adapter — correlation and risk-scoring logic must never change to accommodate a new tool's output format (`PRODUCT_SPEC.md` §7, extensibility). Second, the Risk Engine and Correlation Engine — the product's core differentiators — must stay explainable and unit-testable in complete isolation from FastAPI, PostgreSQL, Redis, or any specific scanner's output format, with no infrastructure required to run their tests. A conventional layered architecture (routes → services → models) doesn't structurally prevent business logic from depending on a specific database ORM or a specific scanner's JSON shape; it just relies on discipline not to do that, which erodes over time without something to enforce it.

## Decision

Each module is structured as its own hexagon: `domain/` (entities, value objects, pure business logic), `application/` (use cases, orchestrating domain through ports), `ports/` (inbound and outbound interfaces), and `adapters/` (inbound: REST routers; outbound: Postgres repositories, scanner CLIs, the LLM provider, etc.). Dependencies point inward only — `domain/` has zero imports from `adapters/` or any third-party framework; `application/` depends on ports, never on concrete adapters. A scanner integration is a `ScannerPort` implementation (`SemgrepAdapter`, `TrivyAdapter`, `ZapAdapter`); the LLM explanation layer sits behind `ExplanationProviderPort`. This is enforced mechanically, not just by convention — see ADR-007 (import-linter).

## Consequences

This makes the two things the product spec requires straightforward: adding `ZapAdapter` or a future scanner is additive (new adapter, new port implementation), and the Risk Engine/Correlation Engine can be unit-tested with in-memory fakes of their ports — no database, no network, fast tests, per `CLAUDE.md`'s testing requirements.

It makes small, throwaway features slower to build — even a trivial endpoint requires touching four layers (route → use case → domain → port/adapter) instead of one file. It also means the boundary rules only hold as long as they're enforced; without a mechanical check (ADR-007), the discipline degrades exactly the way conventional layered architectures do. And structuring every module identically, whether or not that module ends up having complex domain logic (e.g. `identity` versus `risk_engine`), adds boilerplate to the simpler modules for the sake of uniformity.

## Alternatives considered

**Conventional layered/MVC architecture** (routes → services → ORM models directly). Rejected: nothing in that structure stops a scanner's raw output format or a specific ORM model from leaking into correlation/risk logic — the extensibility and explainable-testability requirements from `PRODUCT_SPEC.md` §7 would depend entirely on developer discipline rather than the architecture itself.

**Hexagonal architecture at the application level only** (one big hexagon for the whole app, not one per module). Rejected: this doesn't give the same module-to-module isolation — `correlation` could still end up depending on `scanning`'s internals directly rather than through a published port, which is exactly what ADR-001's modular-monolith decision depends on to keep modules independently reasoned-about.
