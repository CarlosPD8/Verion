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
| [0011](0011-subprocess-execution-safety.md) | Subprocess execution safety pattern | Accepted |
| [0012](0012-trivy-vulnerability-db-freshness.md) | Trivy vulnerability database defaults to a live refresh in production | Accepted |
| [0013](0013-zap-target-url-ssrf-validation.md) | ZapAdapter target-URL SSRF validation | Accepted |
| [0014](0014-github-webhook-verification.md) | GitHub webhook signature verification and delivery handling | Accepted |
| [0015](0015-mypy-strict-type-checking-gate.md) | mypy `--strict` as the CI type-checking gate, scoped to `src/` | Accepted |
| [0016](0016-multi-scanner-dispatch.md) | Multi-scanner dispatch, partial-failure semantics, and per-project scanner configuration | Accepted |
| [0017](0017-normalization-trigger-and-pipeline-progress.md) | Normalization trigger, and where pipeline progress lives | Accepted (amended M4.1, M4.3, M4.4) |
| [0018](0018-normalized-severity-and-shared-kernel-scope.md) | Normalized severity, unsourced fields, and what `shared_kernel/` takes | Accepted (amended M4.2) |
| [0019](0019-finding-identity-and-deduplication.md) | `Finding` identity, deduplication, and what the hash is over | Accepted (amended M4.3, M4.4) |
| [0020](0020-finding-upsert-semantics.md) | How the `Finding` upsert stays equal to `merge_observation` | Accepted |
| [0021](0021-normalization-job-execution.md) | Normalization job execution: scheduling, state machine, and failure semantics | Accepted |
