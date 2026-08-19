# ADR-006: `src/verion/` layout instead of a flat repo-root package

## Status

Accepted

## Context

`ARCHITECTURE.md` §7 originally specified a flat project structure with `modules/`, `shared_kernel/`, and `platform/` sitting directly at the repository root as top-level importable packages, alongside `docs/`, `tests/`, and `infra/`. While scaffolding this during M0.1, a problem surfaced: `platform` is also the name of a Python standard-library module, one that `uvicorn` and `fastapi` (among others) import internally. If the repository root ever lands on `sys.path` — which is the default outcome of running `pytest`, `uvicorn`, or any `python -m` invocation from the repo root — an empty top-level `platform/` package would shadow the real stdlib module for every piece of code in the process, including deep inside third-party libraries that have no awareness of Verion's module layout. This isn't a hypothetical edge case; it's the default behavior of the exact tools (`pytest`, `uvicorn`) this project runs constantly.

## Decision

All application code is wrapped under `src/verion/`, so `modules/`, `shared_kernel/`, and `platform/` become subpackages of `verion` (`verion.modules`, `verion.shared_kernel`, `verion.platform`) rather than top-level packages. The real import path for the platform module is `verion.platform`, never bare `platform`. `docs/`, `tests/`, and `infra/` remain at the true repository root, unchanged from the original diagram. `ARCHITECTURE.md` §7 was updated in the same change (M0.1) to reflect this, including a one-line note explaining why.

## Consequences

This closes off an entire class of import-shadowing bugs before any code was written to trigger it — the collision is structurally impossible now, not just avoided by convention. It also happens to follow a standard, well-understood Python packaging pattern (`src/`-layout), which most contributors and tooling (build backends like `hatchling`) already understand without extra configuration; `hatchling` auto-detected the `src/verion` layout with no explicit `packages =` configuration needed.

It makes every module's import path one segment longer (`verion.modules.identity.domain` instead of `modules.identity.domain`) and means the repository's on-disk structure no longer matches `ARCHITECTURE.md`'s original diagram exactly — anyone reading the architecture doc casually needs to know about this deviation, which is why it's called out explicitly in both `ARCHITECTURE.md` §7 and here rather than left implicit.

## Alternatives considered

**Rename just the colliding module** (e.g. `platform_layer/`, `app_platform/`) and keep everything else flat at the repo root. Rejected: this is a smaller textual diff, but it permanently diverges the module's name from the vocabulary `ARCHITECTURE.md` already used elsewhere (ports catalog, deployment view, etc.) for no benefit beyond avoiding one extra path segment — and it does nothing to prevent the same class of collision if some other module name later happens to match a stdlib or widely-used third-party module.

**Leave it as `platform/` at the repo root and accept the risk.** Rejected outright: the collision is not a remote possibility, it is the default outcome of running `pytest` or `uvicorn` from the repo root, which happens on effectively every development and CI invocation.
