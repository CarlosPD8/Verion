# Architecture Decision Records

Each ADR documents one consequential architectural or process decision: the situation that prompted it, what was decided, the honest trade-offs, and what alternatives were rejected and why. See `CLAUDE.md`'s working-style rule for when a new ADR is warranted.

`0005` is intentionally reserved (not yet created) for the future risk-scoring-model ADR, per `docs/ROADMAP.md` M6.1.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith over microservices | Accepted |
| [0002](0002-hexagonal-architecture.md) | Hexagonal architecture (ports & adapters) at the module level | Accepted |
| [0003](0003-explainable-scoring.md) | Explainable risk scoring over black-box ML | Accepted |
| [0004](0004-llm-downstream-of-scoring.md) | LLM explanation layer strictly downstream of risk scoring | Accepted |
| [0006](0006-src-layout.md) | `src/verion/` layout instead of a flat repo-root package | Accepted |
| [0007](0007-import-linter.md) | import-linter for mechanical architecture enforcement | Accepted |
| [0008](0008-manual-di-wiring.md) | Explicit `Depends()`-based DI wiring instead of a DI framework | Accepted |
| [0009](0009-dependency-verification-protocol.md) | Verify dependency-safety claims against primary sources before acting | Accepted |
| [0010](0010-allow-indirect-imports.md) | `allow_indirect_imports` for cross-module contracts | Accepted |
