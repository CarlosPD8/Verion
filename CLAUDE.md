# CLAUDE.md — Project Context for Claude Code

This file is read automatically by Claude Code at the start of every session. It exists so the project's intent, architecture, and conventions don't need to be re-explained. Keep it in sync as the project evolves — if a rule here stops being true, fix this file in the same PR that changed the reality.

---

## Compact Instructions

When this conversation is compacted (auto-summarized as it approaches the context limit), always preserve:

- Which roadmap issue (M#.#) is currently in progress and its exact scope, including anything explicitly marked out-of-scope.
- Any architectural decision made this session not yet written as an ADR or a CLAUDE.md rule.
- The full list of files created/modified/staged this session.
- Verification/test commands run and their pass/fail results.
- Any dependency added, rejected, or flagged for ADR-009 verification this session, with the outcome.
- Any open question or pending decision the user hasn't resolved yet — don't let compaction silently drop something awaiting an answer.

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

This project uses **Hexagonal Architecture (Ports & Adapters)** inside a **modular monolith**. Rules 1–3 are mechanically enforced by CI (import-linter); most of the rest are not, and hold by review alone — see *How these rules are enforced* below for exactly which is which, and don't assume a green CI run means a change is compliant. Numbered 1–15 below; numbers are stable and never get reassigned (they're referenced by ADRs, code comments, and tests) — the subheadings are purely for scanning, not a renumbering.

### Hexagonal boundaries

1. `domain/` code has **zero imports** from `adapters/`, FastAPI, SQLAlchemy, or any third-party framework. Pure Python only.
2. `application/` (use cases) orchestrates `domain/` through **ports** (interfaces), never through concrete adapters.
3. A module never imports another module's `domain/` or `adapters/` directly — only its published ports.
4. Every new external integration (a scanner, an LLM provider, a VCS) is added as an **adapter implementing an existing or new port** — never by special-casing it inside application/domain logic.

### Product-specific principles

5. The **Risk/Decision Engine's scoring must stay traceable to explicit inputs.** Do not introduce a black-box ML model or an unexplained numeric score. If you're tempted to, stop and flag it — this breaks the product's core value proposition.
6. **The LLM (Explanation Layer) narrates decisions already made by the Risk Engine — it never determines priority.** Structured scoring happens first and is persisted; the LLM call only turns that structured result into readable text.

### Persistence & async

7. **All outbound I/O-bound ports (`*RepositoryPort`, and any future port doing network/disk I/O) are async by default**, per `ARCHITECTURE.md`'s minimize-blocking-I/O NFR. This is the default assumption for every module's ports going forward, established when identity's ports were converted to async in M1.2.
8. **Every SQLAlchemy ORM model imports `Base` from `platform/db.py` — never define a second `DeclarativeBase()`.** Alembic's `env.py` only sees tables registered against that one `Base.metadata`; a second declarative base means its tables silently never get a migration.
9. **Entity IDs are plain strings end-to-end** — `IdGeneratorPort.new_id() -> str` (UUID-formatted, not a `uuid.UUID` value), matching ORM column is always `String`, never a Postgres `UUID` type. Keeps ID handling identical across every module and avoids str/UUID conversion bugs at module boundaries.

### API safety

10. **Inbound API adapters never return a domain entity directly** — always a dedicated Pydantic response schema local to that adapter, even when it would just mirror the entity's fields. This is what stands between an added-later sensitive field (a password hash, a token, a secret) and an accidental HTTP response leak.

### Secrets & leakage

11. **Any setting with a known-insecure default (a dev secret, a placeholder credential) must fail fast at startup outside `app_env='local'`** — never let the app silently boot with a publicly-visible default in a real deployment. See `Settings._reject_dev_secrets_outside_local` in `platform/settings.py` (a single validator checking a `{field_name: dev_placeholder}` dict, covering `jwt_secret_key` and `github_client_secret` today) as the reference pattern — add new sensitive fields to that dict rather than writing a new validator.
12. **No credential/token/secret/hash field may appear in an API response, exception message, or log beyond what's explicitly designed to expose it** (extends `PRODUCT_SPEC.md` §11's "secrets never touch logs/DB in plaintext" to response bodies and error messages too). Any module handling such a field ships an explicit test asserting this, colocated with that module's other security-relevant tests (e.g. identity's plaintext-non-leakage tests) — not a standalone file that's easy to lose track of or skip in a future refactor.
13. **Any HTTP redirect (OAuth callbacks, or any future redirect-based flow) must never carry a credential, token, or secret in the Location header's URL or query string** — success/failure is signaled generically. This applies to every current and future OAuth-style integration, not just GitHub. A separate leak class from rule 12: a token in a `Location` header can end up in proxy logs, browser history, and a downstream page's `Referer` header, none of which rule 12's log/exception/response-body scope covers.

### Time

14. **All timestamps are UTC, always via `ClockPort`** — never a naked `datetime.now()`/`datetime.utcnow()` call, and every `DateTime` ORM column is `timezone=True`. `SystemClock` is the only place wall-clock time gets read.

### Dependency injection

15. **`platform/di.py` factories follow one shape**: `get_<port_name>()` paired with `<PortName>Dep = Annotated[Port, Depends(get_<port_name>)]`. `@lru_cache` only factories with no per-request dependency (stateless singletons like `get_clock`) — never one that depends on `DbSessionDep` or anything else request-scoped, or you'll leak a stale session across requests.

If a requested change would violate one of these, say so explicitly before implementing it, rather than working around it silently.

---

## How these rules are enforced

Two tiers. Both are binding; only one fails the build. Know which is which before treating a green CI run as proof a change is compliant.

### Tier 1 — mechanically enforced

CI rejects the change in about two minutes, without a reviewer. Every row below is a step that exists in `.github/workflows/ci.yml`:

| CI step | What it actually covers |
|---|---|
| `uv run lint-imports` (17 contracts, ADR-007 / ADR-010) | Rules 2 and 3 fully. Rule 1's `adapters/` clause fully; its "any third-party framework" clause **only for the packages named** in the `framework-isolation` contract — a new integration importing an unlisted library into `domain/` passes. |
| `uv run mypy` (`--strict`, `src/` only, ADR-015) | Port/adapter Protocol conformance — but only where an adapter meets a port-annotated site (a `di.py` factory's return type, or an explicit annotation). An adapter constructed into an `Any` is unchecked. |
| `uv run pytest` | Rule 12 — but only because the rule requires each module to ship its own non-leakage test. Nothing verifies that a *new* module actually did. |
| `uv run ruff check` / `ruff format --check` | Style only. No security or architecture rules — bandit (`S`) is not in the selected rule set, so `shell=True` is not caught. |
| `uv run alembic upgrade head` | That migrations apply cleanly. **Not** rule 8 — a model on a second declarative base silently gets no migration and this step still passes. |
| `uv run python scripts/check_claims.py` | No numbered rule — it keeps *this table* honest, plus the other doc↔artifact claims listed in the script. Every gate above must appear both here and in `ci.yml`, or the build fails. |

Rule 4 is partly covered: the layers contract blocks its most common violation (importing a concrete adapter from `application/`), but "add the integration as an adapter behind a port" is a design requirement no linter can check.

Rules **5, 6, 7, 8, 9, 10, 11, 13, 14, 15** have no mechanical check at all. They hold because this file and reviewers hold them.

### Tier 2 — documented judgment, enforced only by review

Equally binding in practice, and invisible to CI: a change violating one of these ships green. `docs/adr/` (indexed in `docs/adr/README.md`) is the second rulebook — read it before writing an adapter, not after.

- **ADR-011 — subprocess execution safety.** Nine mandatory points for *every* subprocess call: argument-list only and never `shell=True`; validate untrusted input before it reaches an argument; a hard timeout *with* an explicit kill, since `wait_for` alone does not terminate the child; credentials via env, never argv or a URL; guaranteed temp cleanup on every exit path; redact captured output before it reaches a log or exception; disable interactive prompting up front; `docker kill <name>` in the timeout handler; `chmod 0777` on bind-mounted temp dirs.
- **ADR-013 — SSRF validation.** Both gates run as the literal first lines of the adapter's `run()`, before any network or subprocess call. `allow_private_targets` is a test-only escape hatch and must never be `True` in production wiring.
- **ADR-008** (DI factory shape — rule 15's naming and `@lru_cache` restrictions), **ADR-009** (verify dependency-safety claims against primary sources *before* adding a dependency), **ADR-012** (Trivy vulnerability-DB freshness default).
- **ADR-016 — multi-scanner dispatch.** Four decisions M4/M5 are built on, none of them mechanically checkable. The two most load-bearing, because both are natural-looking "optimizations" that would break something invisible: **one job per `Scan`, one checkout, every scanner against that same tree** — fan-out per `(scan, tool)` would let different tools scan different commits, which makes M5's cross-tool correlation unsound with nothing recording that it happened; and **a retry re-runs every enabled scanner**, not just the failed ones, for the same reason. Also: per-tool outcome lives on `ScanResult` and **M4 reads `get_succeeded_by_scan_id`, never `Scan.status`** (a derived summary must not become a pipeline's input); and dispatch routes by `ScannerPort.target_kind`, never by a `tool == "zap"` branch (rule 4).

When a Tier 2 rule becomes mechanically checkable, move it to Tier 1 and say so here — that migration is the point of keeping the two lists side by side.

---

## Testing requirements (definition of done)

No issue is complete without:

- **Unit tests** for any `domain/` or `application/` code, using **in-memory fakes of the relevant ports** — no real DB/network/LLM calls in unit tests.
- **Integration tests** for any new adapter, against the real dependency (Postgres, Redis, or the actual tool CLI/API), using `docker-compose` services.
- For `correlation` and `risk_engine` specifically: tests must cover both positive cases (should correlate / should score high) and negative cases (should NOT correlate / should score low) — these two modules are the product's core differentiator and deserve disproportionate test rigor.
- Passing CI (lint, type check, import-linter architecture check, unit + integration tests) before considering an issue done.
- Async integration tests sharing a session-scoped fixture (e.g. a DB engine) require a session-scoped event loop — `asyncio_default_fixture_loop_scope`/`asyncio_default_test_loop_scope = "session"` in `pyproject.toml`. Without it, asyncpg connections created in one test's loop get reused in another's and fail with `InterfaceError`. Don't remove these two settings.
- **Full-suite runtime is a tracked number with a threshold, measured in CI** — specifically the duration of the `Tests (pytest …)` step, **not** total job time, which also carries image pulls and tool installs and is noisier (the ZAP pull alone has ranged 26–35s). Measure in CI, not locally: local runtime varies by OS and by which tool binaries are installed, and the CI step is currently *faster* than a Windows local run despite running more tests. Baseline **45s** (2026-08-20), having grown 14s → 15s → 44s → 45s across M3.3 → M3.4 → M3.6 → 2026-08-20. **M3.7's baseline is not yet measured** — it adds a third container-bound ZAP test (`test_multi_scanner_dispatch.py`, the only test covering real heterogeneous `REPO_PATH`/`URL` dispatch) and is expected to land near **58-60s**; the local full-suite run was 81s, but local runtime is not comparable and must not be recorded here. Replace this sentence with the real figure from the first green CI run. **Treat it as approximate:** consecutive runs have varied by roughly ±8s (a 37s run followed a 45s one *with three more tests*), because the step contains network-bound work. Compare against the trend, not a single reading. The driver is overwhelmingly a handful of container-bound tests, not test count: in CI, `ZapAdapter`'s two take 26.5s of a 37.3s run — **71% of the suite in 2 tests out of 245** — with the third-slowest at 2.6s and the remaining 243 summing to ~11s. The practical consequence is that **120s will not be reached by ordinary test growth; it will be reached by adding container-bound scanner tests and almost nothing else**, which makes the mitigation surgical rather than broad: a separate CI job for those tests, ahead of `pytest-xdist` across the whole suite. Thresholds: above **120s**, that split becomes a scheduled roadmap issue in the *next* milestone; above **300s** it blocks the current issue rather than being deferred again. Any single test exceeding **30s** justifies itself in its docstring. `--durations=10` is in `addopts` so the top offenders appear in every CI log rather than being discovered late.
- **Type-suppression count is tracked, reported by `check_claims.py` on every CI run, and deliberately does not block. Baseline: zero** — no `# type: ignore` or `# noqa` in `src/`, and no `disable_error_code` / `ignore_missing_imports` / `[[tool.mypy.overrides]]` in `pyproject.toml`. This is the only metric that detects the `mypy --strict` gate being *bypassed* rather than satisfied — the failure where a mechanical check decays into theatre while still reporting green — which is why it's tracked and why suite size, ADR count, rule count and total CI job time are not: none of those would change a decision at any value. Zero is a uniquely strong baseline, so any increase is arguable rather than lost in noise. Adding a suppression is allowed; put a one-line reason on the same line. It doesn't block because a hard zero pushes people toward the `pyproject.toml` escapes instead, which are worse — they suppress silently and are invisible at the call site. Those are counted too.
- **`pre-commit`'s result on a change containing new files is only meaningful after `git add`.** It only sees tracked/staged files, so a change that adds an untracked file gets a fully green report from hooks that never read it. Stage first, or run the underlying tools directly (`uv run ruff check .`, `uv run mypy`) — otherwise the hooks report on a file set that excludes exactly the code you just wrote.

---

## Working style

- Work **one roadmap issue at a time** (see `ROADMAP.md`). Don't bundle unrelated changes into one PR.
- Before implementing, restate which module and which port(s)/entities are involved, so we can catch architecture drift before writing code, not after.
- Prefer small, reviewable diffs over large ones — this project is meant to demonstrate engineering discipline, and that includes commit/PR hygiene.
- When a decision has real trade-offs (e.g., how to weight a signal in the Risk Engine, how to structure a correlation rule), surface the trade-off and a recommendation rather than silently picking one — these are exactly the decisions worth documenting in an ADR.
- If you add a new architectural decision of consequence, propose an ADR entry in `docs/adr/` rather than only writing code.
- At each milestone boundary, run the **Milestone-boundary review** in `ROADMAP.md` (~45 min, five steps, every step produces a written artifact even when that artifact is "checked, no change"). That section holds the checklist, the cadence, and the exit ramp for dropping to every other milestone; this is a pointer to it, not a copy.
- When you find a real gap but decide not to fix it now, record it in `ROADMAP.md`'s **Deferred gaps** register rather than only in a commit message — including what it would break if left, which is the field that actually matters. At three confirmations it must be assigned or explicitly justified, and CI enforces that. The register holds the rules; this is a pointer to them, not a copy.

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
