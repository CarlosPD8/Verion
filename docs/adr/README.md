# Architecture Decision Records

Each ADR documents one consequential architectural or process decision: the situation that prompted it, what was decided, the honest trade-offs, and what alternatives were rejected and why. See `CLAUDE.md`'s working-style rule for when a new ADR is warranted.

**Every number from `0001` is now a file.** `0005` was reserved at M0 for the risk-scoring-model ADR and left uncreated; it was written at **M6.1, 2026-09-16**. Until that commit this line read *"One number is reserved and not yet created, claimed by a roadmap entry rather than by a file: `0005` for the risk-scoring-model ADR (`docs/ROADMAP.md` M6.1)."* — a sentence its own subject falsified, and which no check saw: `check_adrs_are_indexed` requires the table row below and reads no prose.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith over microservices | Accepted |
| [0002](0002-hexagonal-architecture.md) | Hexagonal architecture (ports & adapters) at the module level | Accepted |
| [0003](0003-explainable-scoring.md) | Explainable risk scoring over black-box ML | Accepted (amended M6.1, corrected M7.1, amended M8.5) |
| [0004](0004-llm-downstream-of-scoring.md) | LLM explanation layer strictly downstream of risk scoring | Accepted (amended M6.2, M7.1) |
| [0005](0005-risk-scoring-model.md) | The risk scoring model: what a Risk is, the function over it, and what a score may not claim | Accepted (amended M6.2, M8.5) |
| [0006](0006-src-layout.md) | `src/verion/` layout instead of a flat repo-root package | Accepted |
| [0007](0007-import-linter.md) | import-linter for mechanical architecture enforcement | Accepted (amended M5→M6 boundary, M8.3 early start) |
| [0008](0008-manual-di-wiring.md) | Explicit `Depends()`-based DI wiring instead of a DI framework | Accepted (amended M8.8) |
| [0009](0009-dependency-verification-protocol.md) | Verify dependency-safety claims against primary sources before acting | Accepted (amended M8.3 early start) |
| [0010](0010-allow-indirect-imports.md) | `allow_indirect_imports` for cross-module contracts | Accepted |
| [0011](0011-subprocess-execution-safety.md) | Subprocess execution safety pattern | Accepted (amended M3.5) |
| [0012](0012-trivy-vulnerability-db-freshness.md) | Trivy vulnerability database defaults to a live refresh in production | Accepted |
| [0013](0013-zap-target-url-ssrf-validation.md) | ZapAdapter target-URL SSRF validation | Accepted (amended 2026-08-27, M5→M6 boundary) |
| [0014](0014-github-webhook-verification.md) | GitHub webhook signature verification and delivery handling | Accepted |
| [0015](0015-mypy-strict-type-checking-gate.md) | mypy `--strict` as the CI type-checking gate, scoped to `src/` | Accepted (amended M8.3 early start) |
| [0016](0016-multi-scanner-dispatch.md) | Multi-scanner dispatch, partial-failure semantics, and per-project scanner configuration | Accepted (amended 2026-08-27, M5→M6 boundary, M8.8) |
| [0017](0017-normalization-trigger-and-pipeline-progress.md) | Normalization trigger, and where pipeline progress lives | Accepted (amended M4.1, M4.3, M4.4, M8.8) |
| [0018](0018-normalized-severity-and-shared-kernel-scope.md) | Normalized severity, unsourced fields, and what `shared_kernel/` takes | Accepted (amended M4.2, M5.1, M6.1, M8.5) |
| [0019](0019-finding-identity-and-deduplication.md) | `Finding` identity, deduplication, and what the hash is over | Accepted (amended M4.3, M4.4, M5.1) |
| [0020](0020-finding-upsert-semantics.md) | How the `Finding` upsert stays equal to `merge_observation` | Accepted (amended M4.5, M8.1) |
| [0021](0021-normalization-job-execution.md) | Normalization job execution: scheduling, state machine, and failure semantics | Accepted (amended M4.5, M8.8) |
| [0022](0022-findings-read-api-surface.md) | The findings read surface: evidence exposure, cross-module authorization, and what a response says about its own completeness | Accepted (amended M8.8) |
| [0023](0023-correlation-match-key.md) | How `correlation` names the type it correlates: a match key it owns | Accepted (amended M5.1, 2026-08-25, M5.8, M5.6, M6.1) |
| [0024](0024-active-scanning-consent-and-scan-policy.md) | Where active-scanning consent lives, what it is bound to, and the bounds on the `activeScan` job | Accepted (amended M5.4, M5.9) |
| [0025](0025-candidate-risk-persistence-and-read-surface.md) | Whether a candidate Risk is stored, how it is addressed, and what a Risk read returns | Accepted (amended M7.2, M8.1) |
| [0026](0026-fixture-shape-conformance-check.md) | Checking a hand-written fixture's shape against the committed corpus | Accepted (amended 2026-08-27) |
| [0027](0027-standing-the-demo-target-up-and-what-an-active-scan-run-proves.md) | How M5.9 stands the demo target up, where the active capture lives, and what a green active-scan run proves | Accepted (amended M5.9, M5.6) |
| [0028](0028-declaring-that-the-scanned-url-serves-the-scanned-tree.md) | Declaring that the scanned URL serves the scanned tree: where the record lives, what voids it, and what it does not assert | Accepted (amended M5.5, M5→M6 boundary) |
| [0029](0029-route-extractor-placement-re-derivation-and-key-entry.md) | Where the route extractor lives, what its route map is re-derived against, and how a derived location enters the match key | Accepted (amended M5.6, M8.5) |
| [0030](0030-scored-risk-read-surface.md) | The scored Risk read surface: where ranking lives, what a response must carry to be re-derivable, and what the first measurement of a scored request does not show | Accepted (amended M8.5) |
| [0031](0031-frontend-token-holding-transport-and-npm-dependency-scope.md) | The frontend's token holding, its transport to the API, and what ADR-0009 covers in an npm tree | Accepted (decision 2 confirmed by P1, 2026-09-16) |
| [0032](0032-explanation-provider-port-openai-adapter-and-prompt-boundary.md) | The Explanation Layer's port, its OpenAI adapter, and where the prompt's input ends | Accepted (amended M7.2, M7.3) |
| [0033](0033-security-brief-address-read-surface-and-authorization.md) | How a Security Brief refers to its Risk, what it stores, how it is read, and who may generate one | Accepted (amended M7.3, M8.5) |
| [0034](0034-what-happened-typed-members-two-calls-and-the-prompt-input-boundary.md) | *What happened*: typed member fields, two provider calls, and the prompt's input boundary | Accepted (amended M7.3) |
| [0035](0035-a-route-that-starts-a-scan.md) | A route that starts a scan: who may start one, what the caller gets back, and when the job may run | Accepted |
| [0036](0036-dismissing-a-risk-snapshot-identity-and-the-event-log.md) | Dismissing a Risk: what a dismissal attaches to, the event log, and who may write it | Accepted (amended M8.1) |
| [0037](0037-a-risks-confidence-grouping-provenance-and-what-it-may-not-claim.md) | A Risk's confidence: grouping provenance, where it is computed, and what it may not claim | Accepted (implemented M8.5) |
| [0038](0038-brief-generation-as-a-job-and-what-the-poll-reports.md) | Brief generation as a job: the generation record, where authorization lands, and what the poll reports | Accepted |
| [0039](0039-one-repository-and-one-security-context-per-project.md) | One repository and one Security Context per project: what a second write does, and what the constraint does not reach | Accepted |
