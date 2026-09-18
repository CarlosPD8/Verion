# ADR-007: import-linter for mechanical architecture enforcement

## Status

Accepted

## Context

ADR-002 establishes the hexagonal architecture and its dependency rules (`domain/` never imports `adapters/` or frameworks; `application/` orchestrates through ports, never adapters directly; a module never imports another module's `domain/` or `adapters/` directly). Rules like these hold only as long as something enforces them — without a mechanical check, a single convenient-seeming import (e.g. `correlation` reaching directly into `scanning.adapters` instead of going through a port) silently erodes the architecture, and nothing in a normal test suite or code review process reliably catches it at scale. `CLAUDE.md` requires these rules be "enforced by CI (import-linter), not just convention."

## Decision

`import-linter` enforces the dependency rules in CI, configured via `[tool.importlinter]` in `pyproject.toml` (TOML-native config, avoiding a separate `.importlinter` ini file). It runs as a `uv run lint-imports` step in the CI pipeline (`.github/workflows/ci.yml`), between lint and test. The configuration is 17 contracts:

- **8 per-module `layers` contracts** — one per module (`identity`, `projects`, `scanning`, `normalization`, `correlation`, `risk_engine`, `brief`, `history`), each declaring the order `adapters → application → ports → domain` (higher layers may depend on lower ones, never the reverse). This mechanically enforces ADR-002's per-module dependency rule.
- **8 `forbidden` contracts for cross-module independence** — one per module, forbidding that module (as a whole, all its layers) from importing any other module's `domain` or `adapters` subpackages directly. Each module's `ports` stay reachable, since that's the sanctioned cross-module surface per `ARCHITECTURE.md` §3.
- **1 `forbidden` contract for framework isolation** — every module's `domain` and `application` packages (16 source packages) are forbidden from importing `fastapi`, `sqlalchemy`, `redis`, or `uvicorn`.

The contracts were verified to actually catch violations, not just parse successfully: during M0.2, a throwaway `import fastapi` was added to `identity/domain/__init__.py` and a throwaway cross-module import was added to `identity/application/__init__.py`; both were caught by `lint-imports` with a clear violation report, then reverted.

## Consequences

This turns ADR-002's architecture rules from something a reviewer has to notice into something CI fails on automatically, which is the whole point — the rules stay true as the codebase grows well past what one person can review by eye. It also gives new/future contributors (or a future session of this same project) a fast, explicit failure message pointing at exactly which import broke which rule, rather than a vague architecture-review comment.

It costs real config verbosity — 17 largely repetitive contract blocks, since import-linter's TOML config has no loop or template construct, and each of the 8 modules needs its own near-identical layers and forbidden-cross-module blocks. Adding a 9th module later means hand-adding 2 more contract blocks (one layers, one forbidden), not a one-line change. It also only catches what's expressed as a contract — a new kind of violation not anticipated by the current 17 (e.g., a future rule about `shared_kernel` purity) would need its own new contract, not something the existing set generalizes to automatically.

## Amendments

- **2026-09-15 (M5→M6 boundary review): the Decision's framework list is qualified, and the contract is not.** It names four packages — `fastapi`, `sqlalchemy`, `redis`, `uvicorn` — while `pyproject.toml`'s framework-isolation contract forbids five. `arq` was added to that contract at M3.1 (`421b64b`), the day after this ADR was written (`4236543`), and this sentence was never updated. The contract is the list; read the sentence as its M0.2 state.
- **2026-09-16 (M8.3 started early, ADR-0031): *Alternatives considered* calls this "a pure-Python project", which stops being true when `frontend/` is created.** ADR-0031 decides a `frontend/` that brings npm and `node_modules` into the repository; the commit that builds the screen creates it. The dependency-cruiser rejection stands on its other ground, unchanged: a JS tool would add a toolchain to CI for no benefit over a native Python tool that does the same job. What changed is only that the repository is no longer pure-Python. It is still true that no JS tooling enters the Python gates.
- **2026-09-18 (post-M7 boundary review): the Decision's *"This mechanically enforces ADR-002's per-module dependency rule"* claims more than the contracts do, and is qualified.** The contracts are a deny-list over named modules, and `lint-imports` is green on anything they do not name. So they enforce an enumeration, not the rule. Stated in the form ADR-0025 decision 5 uses, about every item named and every item left out:
  - **About every item they name.**
    - Inside each of the eight modules in a `layers-*` contract's `containers`, `adapters → application → ports → domain` holds.
    - No module in a `cross-module-*` contract's `source_modules` directly imports another listed module's `.domain` or `.adapters` (ADR-010).
    - None of the 16 `domain` and `application` packages listed in `framework-isolation` imports `fastapi`, `sqlalchemy`, `redis`, `arq` or `uvicorn`.
  - **About every item they leave out: nothing.** Six holes of one class, each verified at `7e1bc62`:
    1. Another module's `.application` is in no `forbidden_modules` list (**G35**).
    2. A `domain/` importing another module's `ports/` is outside every contract, because each `layers-*` contract is scoped to its own container (**G77**). `brief/domain/security_brief.py` does it today.
    3. `shared_kernel/` and `platform/` appear in no contract.
    4. `history/` holds no non-`__init__` file, so `layers-history` and `cross-module-history` are green over nothing (ADR-0023's 2026-09-18 amendment).
    5. A new module appears in no contract at all (**G83**). `.claude/skills/new-module/SKILL.md` never says to add one. Its one import-linter step runs `lint-imports` to confirm the new module violates nothing, which is green by construction. The Consequences' *"hand-adding 2 more contract blocks"* also undercounts: the eight other `cross-module-*` lists and `framework-isolation`'s sources each need the module too.
    6. Only five frameworks are named, so a `domain/` importing `pydantic`, `pyjwt`, `argon2` or `httpx2`, all installed at runtime, passes.

## Alternatives considered

**dependency-cruiser.** Rejected: it's a mature, capable tool, but it's a Node.js/JS-ecosystem tool — adopting it would mean pulling an entire JS toolchain (npm, node_modules) into a pure-Python project for a single tool's sake, adding install/CI complexity with no corresponding benefit over a native Python tool that does the same job.

**No mechanical enforcement, rely on code review discipline.** Rejected per `CLAUDE.md`'s explicit requirement, and for the reason stated in Context: review discipline is exactly what erodes over time on a single-developer project without an automated backstop.
