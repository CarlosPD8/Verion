# ADR-010: `allow_indirect_imports` for cross-module contracts

## Status

Accepted

## Context

ADR-007's 8 cross-module-independence `forbidden` contracts (one per module) defaulted to checking indirect reachability, not just direct imports — import-linter's `forbidden` contract type checks transitive import chains unless told otherwise. That default was never exercised until M1.4: once both `identity`'s and `projects`' inbound routers depended on the shared `platform/di.py` composition root (`identity`'s router for its existing auth/use-case wiring, `projects`' router newly for `CurrentUserIdDep`), `lint-imports` started failing both modules' cross-module contracts. Neither module's own code imported the other directly — the reported chain was `projects.adapters.inbound.api.router → platform.di → identity.domain.exceptions` (and the symmetric case for `identity`). This is structurally unavoidable under the single-composition-root pattern established in ADR-008/CLAUDE.md rule 14: `platform/di.py` is *supposed* to know about every module's adapters and use cases in order to wire them, and any inbound adapter that needs a `di.py`-provided dependency (which is all of them, by design) is transitively "reachable" from every other module `di.py` also wires.

## Decision

Add `allow_indirect_imports = true` to all 8 cross-module-independence contracts in `pyproject.toml`. This matches CLAUDE.md rule 3's literal scope — "a module never imports another module's `domain/` or `adapters/` directly" — which is a statement about direct imports, not about everything transitively reachable through the one shared file every module is expected to depend on. Direct imports stay fully forbidden and mechanically enforced; only the indirect/transitive check is relaxed.

Verified this wasn't a config change taken on faith: reverted the flag on all 8 contracts to reproduce the original failure (confirmed both `cross-module-identity` and `cross-module-projects` break, tracing exclusively through `verion.platform.di`), restored it, then injected a genuine direct cross-module import (`projects/domain/project.py` importing `identity.domain.user.User`) and confirmed `lint-imports` still caught it immediately, with a clean violation report, before reverting the injected import. `architecture-guardian` independently repeated this same verification during M1.4's pre-staging review rather than accepting the reasoning as given.

## Consequences

Any module reachable from another only via `platform/di.py`'s composition root no longer trips these 8 contracts — intentional, and exactly how the DI pattern established in ADR-008 is meant to work: `platform/` is the one place allowed to know about everything. Without this change, `di.py` could never wire more than one module together without breaking cross-module-independence, which would have made the single-composition-root pattern unworkable the moment a second module needed HTTP routes.

The trade-off is real, not just textual: these 8 contracts no longer catch a hypothetical future case where two modules end up transitively coupled through some other shared file *besides* `di.py` — an indirect path through, say, a shared utility module would now pass silently where it previously would have failed loudly. That's judged an acceptable narrowing given `di.py` is already the sanctioned, sole wiring point (per ADR-008 and CLAUDE.md's "Third-party skills" section: "all wiring goes through named factory functions in `platform/di.py`"), so a new indirect coupling through some other shared file would itself be a sign of an undocumented second wiring path — a problem this ADR doesn't claim to solve, but one the project's existing conventions already discourage.

## Alternatives considered

**Split `platform/di.py` into one file per module** (e.g. `platform/di/identity.py`, `platform/di/projects.py`), so each module's router only imports its own slice and never transitively touches another module's wiring. Rejected: this directly contradicts CLAUDE.md rule 14's single-composition-root convention, established just one milestone earlier (M1.2/M1.3) specifically to keep every port-to-adapter resolution readable from one file. It also doesn't remove the real dependency driving the original failure — `projects` genuinely needs identity's JWT-decoding machinery for `CurrentUserIdDep` — it would only relocate that dependency across more files, with no actual gain in decoupling, for a real cost in violating an already-established rule.
