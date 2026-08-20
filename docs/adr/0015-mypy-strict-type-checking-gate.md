# ADR-015: mypy `--strict` as the CI type-checking gate, scoped to `src/`

## Status

Accepted

## Context

`ARCHITECTURE.md` §10 ("Enforcing the Architecture") has listed "port interfaces defined with Python `Protocol` / ABCs, adapters type-checked against them" as a real enforcement mechanism since the architecture was written. No type checker existed. The claim was aspirational, and it was stated alongside mechanisms (import-linter) that genuinely do run in CI, which made it read as equally load-bearing.

That gap had a concrete cost, twice:

- **M2.1** shipped `VcsProviderPort` with four method signatures that `GitHubAdapter` did not implement, reasoning explicitly that this was "confirmed harmless: structural Protocol (not `@runtime_checkable`), zero `isinstance()` checks, `di.py`'s type hint isn't runtime-enforced, and CI has no type-checking step that would flag it either." The gap was closed in M2.2, but the deliberate reliance on nothing catching it is the pattern this ADR ends.
- **M3.5** generalized `ScannerPort.run`'s parameter `repo_path` → `target`, reasoning "verified zero-behavior-change rename — Python Protocols match structurally, confirmed no call site used the old name as a keyword arg." True at runtime today. But `SemgrepAdapter` and `TrivyAdapter` kept `repo_path`, so the adapters stopped matching the port they implement, and the divergence becomes a genuine runtime failure the moment a caller invokes `scanner.run(target=...)` as a keyword — precisely what a multi-scanner dispatcher (M3.7) is likely to do.

The cost of adopting a checker was measured, not estimated, before this decision (`src/`, 158 files):

| Tool | Errors | Files | Time |
|---|---|---|---|
| mypy, default mode | 16 | 4 | 13.6s cold / 3.0s warm |
| mypy `--strict` | 21 | 8 | same |
| pyright, basic mode | 15 | 3 | 4.0s |

`--strict` costs only five errors more than default mode, because `src/` was already essentially fully annotated: zero missing return annotations and one unannotated parameter across 218 functions. There is no annotation backlog to amortize, so the usual argument for adopting a checker gradually does not apply here.

Protocol conformance was verified as genuinely checkable rather than assumed, using a probe that asserted each adapter against its port alongside three deliberate control breaks. Both checkers correctly rejected all three controls (wrong return type, missing method, sync-instead-of-async).

## Decision

**mypy `--strict`, scoped to `src/`, as a blocking CI step.**

Configuration lives in `pyproject.toml`'s `[tool.mypy]` (`python_version`, `files = ["src"]`, `strict = true`) so `uv run mypy` needs no arguments and CI and local runs cannot diverge.

**The `repo_path` → `target` divergence is fixed by renaming the adapters, not by choosing a checker that detects it.** This matters, because it is the one place the two candidates differed: pyright reports the parameter-name mismatch, mypy accepts it silently. The rename closes the divergence class by construction and finishes work M3.5 started, rather than installing a permanent second tool whose only marginal value is detecting an inconsistency that no longer exists.

**`tests/` is deliberately out of scope.** It is the opposite of `src/`: 249 missing return annotations and 517 unannotated parameters across 388 functions, plus a duplicate `conftest` module name that halts mypy before it checks anything. Widening scope later is a deliberate decision to be made on its own merits, not an oversight to be quietly corrected.

**`platform/worker.py` annotates its adapters at construction.** arq's `ctx` is `dict[str, Any]`, so anything stored in it is invisible to the checker. Every other adapter in the project gets conformance checking for free from `platform/di.py`'s port-annotated factories; the scanner family was the sole exception, and it is the exact surface M3.7 will rewrite.

## Consequences

`ARCHITECTURE.md` §10's "adapters type-checked against them" becomes accurate rather than aspirational. `CLAUDE.md`'s enforcement tiers can list a second genuinely mechanical check next to import-linter.

Conformance is only verified where an adapter meets a port-annotated site — a construction annotated as the port, or a `di.py` factory declaring the port as its return type. An adapter constructed into an `Any` is still unchecked. This is a property of structural typing, not a configuration mistake, and it is the reason the `worker.py` annotations above are load-bearing rather than cosmetic.

Adopting `--strict` immediately means future code is held to it from the first line, rather than accruing a backlog that makes tightening the setting progressively harder to justify.

The gate surfaced two genuine defects that were not annotation noise, both fixed in the adopting commit:

- `PostgresScanRepository.update` and `PostgresSecurityContextRepository.update` dereferenced a possibly-missing row with no `None` guard, where their sibling read methods guard theirs. The scan case is the worse of the two: `RunScanUseCase`'s failure path calls `update()` to persist `FAILED` and `failure_reason`, so a missing row would raise an opaque `AttributeError` *from inside the failure handler*, masking the original exception — defeating the persisted-failure visibility M3.3 was specifically built to provide.
- `GitHubAdapter.__init__` annotated `transport` as `httpx2.BaseTransport`, but passes it to `AsyncClient`, which accepts only the unrelated `AsyncBaseTransport`. Masked entirely by luck: `MockTransport` subclasses both, and production passes `None`.

Three sites where the checker wanted a type assertion were hardened with runtime narrowing instead of `cast`, on a consistent rule: **where the value flows into a security control, narrow it; a `cast` is an assertion that holds by our own convention today, and narrowing holds regardless of a future dependency change or an upstream bug.**

- `SystemDnsResolver` — typeshed widens `sockaddr[0]` to `str | int`. `AF_UNSPEC` over a hostname cannot produce the `int` variant, but the list feeds ADR-013's SSRF gate, so a non-`str` is now dropped rather than reaching `validate_resolved_ips_are_public` and failing its parse.
- `JwtAccessTokenIssuer.decode` and `GitHubOAuthStateSigner.verify` — `jwt.decode` is typed `dict[str, Any]`. This `sub` becomes the `user_id` every downstream permission check resolves against, which puts it in the same category.

The JWT sites came with a finding worth recording, because it changes what the guard is actually for. **PyJWT 2.13 already rejects a non-`str` `sub` itself** (`InvalidSubjectError`, a subclass of the `InvalidTokenError` both methods already catch), so that half of the guard is unreachable with a real token and is defense-in-depth only — it exists so the invariant does not depend on a third party continuing to validate a claim it is not contractually required to. What *is* reachable is the missing-`sub` case: PyJWT validates the claim only when present, so a validly-signed token carrying no `sub` previously raised `KeyError` — an unhandled 500 rather than a 401. The distinction is explicit in the tests: the reachable case is driven end to end with a real token, and the defense-in-depth case can only be exercised by stubbing `jwt.decode` out, which its test says in its name.

Both were confirmed load-bearing by mutation: with the guards temporarily removed, all four new tests fail and the pre-existing seven still pass.

## Alternatives considered

**pyright.** Rejected despite being the only checker that empirically caught the `repo_path`/`target` divergence — an advantage that disappears once the adapters are renamed. Its CI story is the deciding factor: it needs either a node toolchain in the workflow or the PyPI wrapper, which downloads a node binary at runtime. That is exactly the supply-chain surface ADR-009 exists to scrutinize, against mypy being pure-Python and arriving via `uv sync --locked` alongside every other dev dependency.

**Both** — mypy as the blocking gate, pyright as a documented local/editor checker. Rejected deliberately: two checkers means two configurations, two suppression sets, and the real possibility that they disagree. A mechanical gate's value is that it returns one unarguable answer; a second tool that can dissent undermines what the gate is for.

**Default (non-strict) mode, tightening later.** Rejected: it would save five errors today and cost the discipline permanently. The measured gap between default and `--strict` is small precisely because the codebase is already annotated to that standard — adopting the weaker setting would let that erode, and every later attempt to tighten it would face a larger backlog than exists right now.

**Neither — correct `ARCHITECTURE.md` §10 to say no checker exists.** Rejected because the measured cost of making the claim true (21 errors, three distinct root causes, ~6 lines of configuration, ~13s of CI) was lower than the ongoing cost of a documented enforcement mechanism that does not enforce anything.
