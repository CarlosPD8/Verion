# ADR-001: Modular monolith over microservices

## Status

Accepted

## Context

Verion needs a backend that supports independently evolvable modules (identity, projects, scanning, normalization, correlation, risk engine, brief, history) without those modules turning into a tangled ball of mud. The team building it is a single developer working a 12–16 week MVP timeline. Microservices are the conventional answer to "independently evolvable modules," but they come with real operational cost: network boundaries between every module, distributed transactions or eventual consistency, service discovery, per-service deployment pipelines, and multiplied infrastructure to run and monitor. None of that cost buys anything at this team size or timeline — there's no scaling requirement, no independent-team-ownership requirement, and no proven need to deploy or scale any one module independently of the others.

## Decision

Verion is built as a single deployable unit — one FastAPI application, one PostgreSQL database, one Redis instance, backed by background workers — with module boundaries enforced *in-process* rather than by network calls. Each module (identity, projects, scanning, normalization, correlation, risk_engine, brief, history) owns its own `domain/`, `application/`, `ports/`, and `adapters/`, and modules only depend on each other through published ports, never through direct imports of another module's internals (see ADR-002, ADR-007).

## Consequences

This makes local development, testing, and deployment simple: one process to run, one database to migrate, no distributed tracing needed to debug a request that crosses module boundaries. It also keeps the MVP timeline realistic — there's no service-mesh or infra work competing with actual product logic.

It makes some things harder later: if a specific module (most likely `scanning`, given it does CPU/IO-heavy work running scanner tools) ever needs to scale independently of the rest of the app, that will require carving it out — a nontrivial migration, not a config change. It also means a bug or crash in one module's code runs in the same process as every other module, so there's no hard fault-isolation between modules the way there would be between services.

This decision does not rule out extraction later. Because module boundaries are already enforced at the code level (ports, not direct imports — see ADR-002), extracting a module into its own service later means moving its hexagon into a new deployable unit and turning its in-process port calls into network calls, not rewriting its internals from scratch.

## Alternatives considered

**Microservices from the start.** Rejected: the operational cost (per-service CI/CD, service discovery, distributed data consistency) is significant and buys nothing at this team size (one developer) and timeline (12–16 weeks). It would also slow down the actual differentiator work (correlation, risk scoring) in favor of infrastructure plumbing.

**A single undifferentiated monolith with no internal module boundaries.** Rejected: without enforced boundaries, correlation/risk-engine logic would likely end up coupled to scanner-specific formats or persistence details, undermining the extensibility and explainability requirements the product depends on (see ADR-002, ADR-003).
