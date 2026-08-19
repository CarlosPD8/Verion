# ADR-008: Explicit `Depends()`-based DI wiring instead of a DI framework

## Status

Accepted

## Context

`ARCHITECTURE.md` §11 notes that `platform/` wires ports to adapters via dependency injection at startup. There's a real choice in how to do that: a DI framework (e.g. `dependency-injector`) that manages a container, providers, and often reflection/autowiring to resolve dependencies automatically; or explicit wiring using FastAPI's own native `Depends()` mechanism plus plain factory functions. The product's stated architectural principle, restated in ADR-002 and ADR-003, is "explainable, not black-box" — that principle was written with risk scoring and the LLM layer in mind, but it applies just as directly to how the codebase itself is assembled: a reader should be able to find out which concrete adapter backs a given port by reading code, not by tracing a container's registration logic or relying on reflection-based autowiring to have picked the right implementation.

## Decision

No DI framework is used. Wiring lives in `platform/di.py` as plain, `@lru_cache`-decorated factory functions (e.g. `get_clock() -> ClockPort`, `get_id_generator() -> IdGeneratorPort`) paired with `Annotated[Port, Depends(factory)]` type aliases that endpoints consume via FastAPI's native dependency injection. The pattern was proven with a real (not placeholder) port/adapter pair during M0.3: `ClockPort`/`IdGeneratorPort`, defined as `Protocol`s in `shared_kernel/ports.py` (see note below on why they live there rather than in a module), with concrete adapters `SystemClock`/`UuidIdGenerator` in `platform/`.

As a related, smaller convention established alongside this: ports with no single owning module (like `ClockPort`/`IdGeneratorPort`) are defined in `shared_kernel/` as `Protocol`s; their concrete adapters live in `platform/`. This is now documented in `ARCHITECTURE.md` §5.2 as well as here.

## Consequences

Every port-to-adapter resolution is one `grep`-able function away — `get_clock`, `get_id_generator`, and so on — with no container configuration, registration order, or autowiring resolution rules to understand first. It costs nothing extra to onboard someone to "how is X wired," which matters for a project meant to demonstrate engineering discipline as much as to ship a product. It also means there's no framework-specific DI vocabulary or lifecycle model (singleton/scoped/transient providers, container graphs) layered on top of what FastAPI already provides natively.

It costs some boilerplate as the number of ports grows — each new port/adapter pair needs its own explicit factory function and `Annotated` alias, where a DI framework might resolve a new binding with one registration line and rely on autowiring for the rest. It also doesn't give you some conveniences a real DI framework provides out of the box, like automatic scoped-lifetime management tied to request boundaries beyond what `Depends()` already offers, or declarative override mechanisms beyond FastAPI's own `dependency_overrides` (which is being relied on, so this gap is more theoretical than practical for now).

## Alternatives considered

**A DI framework** (e.g. `dependency-injector`), using a container with declarative provider bindings and constructor injection. Rejected: this is a defensible choice for a larger team or a codebase with many more ports, but reflection/autowiring-based resolution is exactly the kind of "how did this get wired to that" opacity that ADR-002 and ADR-003 both explicitly reject for the rest of the codebase — applying a different standard to the wiring layer than to the domain/risk-scoring layers would be an inconsistency worth avoiding, not a neutral tooling choice.

**FastAPI's `Depends()` with ad-hoc inline lambdas at each usage site**, rather than named factory functions in `platform/di.py`. Rejected: this scatters the wiring decisions across every endpoint that needs a port, instead of keeping "what implements this port right now" answerable by reading one file — a smaller, more diffuse version of the exact opacity problem this ADR exists to avoid.
