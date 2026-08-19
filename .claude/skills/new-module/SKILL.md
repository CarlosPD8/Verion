---
name: new-module
description: Scaffold a new hexagonal module (domain/application/ports/adapters) under src/verion/modules/, following the exact structure defined in docs/ARCHITECTURE.md §7. Use when starting a new module from docs/ROADMAP.md, or when asked to scaffold, create, or bootstrap a Verion module.
argument-hint: [module_name] [extra_outbound_adapter_subdir?]
arguments: [module_name, extra_adapter]
disable-model-invocation: false
allowed-tools: Bash(mkdir *) Bash(touch *) Read Write
---

## What this does

Creates the empty hexagonal skeleton for a new module, matching the exact shape of the `identity` module already scaffolded in M0.1, per `docs/ARCHITECTURE.md` §7. This is structure only — no domain logic, no ORM models, no route handlers. Business logic for the module is a separate roadmap issue, not this skill's job.

## Before creating anything

1. Read `docs/ARCHITECTURE.md` §3 and §7 to confirm `$module_name` is one of the eight defined modules (`identity`, `projects`, `scanning`, `normalization`, `correlation`, `risk_engine`, `brief`, `history`) or a deliberate, justified addition. If it isn't in that list and there's no clear justification in the conversation, stop and ask before creating anything — don't silently expand the module list.
2. Check `src/verion/modules/$module_name/` doesn't already exist. If it does, stop and report that instead of overwriting anything.

## Structure to create

Under `src/verion/modules/$module_name/`:

```
$module_name/
├── __init__.py
├── domain/
│   └── __init__.py
├── application/
│   └── __init__.py
├── ports/
│   └── __init__.py
└── adapters/
    ├── __init__.py
    ├── inbound/
    │   ├── __init__.py
    │   └── api/
    │       └── __init__.py
    └── outbound/
        ├── __init__.py
        └── db/
            └── __init__.py
```

Every `__init__.py` is empty except for a one-line module docstring naming the layer, e.g.:

```python
"""Domain layer for the {module_name} module. No framework or adapter imports allowed here — see CLAUDE.md rule 1."""
```

Use the matching layer name in each docstring (`domain`, `application`, `ports`, `adapters`).

If `$extra_adapter` is provided (e.g. `scanners` for `scanning`, `explanation` for `brief`), also create `adapters/outbound/$extra_adapter/__init__.py` with the docstring `"""Outbound adapters: {extra_adapter} implementations of $module_name's ports."""`. Do not create adapter implementation files inside it (e.g. no `semgrep_adapter.py`) — those belong to their own later roadmap issue, per M0.1's precedent of "empty skeleton, no business logic yet."

## After creating

1. Run `uv run lint-imports` to confirm the new module doesn't violate any import-linter contract from `pyproject.toml` (it shouldn't, since everything is empty, but this catches a typo'd path before it becomes someone else's problem later).
2. Run `uv run pytest` to confirm nothing broke.
3. Print the resulting tree for `src/verion/modules/$module_name/` so the user can see exactly what was created.
4. Do not create a git commit — per project convention (see `CLAUDE.md`), only commit when explicitly asked, after the user reviews the result.

## Out of scope

Domain entities, use cases, port interfaces (protocols/ABCs), adapter implementations, tests beyond the existing smoke test, and any FastAPI router wiring. This skill only produces the empty hexagon — filling it in is the corresponding module's own roadmap issue (see `docs/ROADMAP.md`).
