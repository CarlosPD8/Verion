# ADR-013: ZapAdapter target-URL SSRF validation

## Status

Accepted

## Context

`ZapAdapter` (M3.5) is the first scanner in this codebase whose target is a live, arbitrary, user-supplied URL rather than a GitHub-validated repo (`SemgrepAdapter`/`TrivyAdapter` both scan a local checked-out path) or a URL string this codebase itself constructs. Per `PRODUCT_SPEC.md` §11 ("SSRF protection is mandatory for any component that triggers DAST scans against user-provided URLs"), this is the first place that principle applies to code being written, not deferred narrative. ADR-0011 documents this as a related but distinct concern, explicitly out of its own scope.

Two sub-problems, not one: a target URL can be rejected on syntax alone (bad scheme, an obviously local/private hostname or IP literal), and a target URL that looks external can still resolve to an internal address — DNS rebinding, where a hostname is deliberately configured to resolve to a public IP during validation and an internal one at request time. Only checking the hostname string, once, is not sufficient; the actually-resolved IP has to be checked immediately before use.

Per ADR-009, a third-party SSRF-validation library was researched before hand-rolling one. The one concrete PyPI candidate found (`oomnitza-ssrf-protection`) could not be verified as actively maintained — its PyPI page did not return enough content to confirm release history or maintainer identity, and the package's obscurity is itself a yellow flag. No other established, widely-adopted Python SSRF-validation library was found. Conclusion: hand-roll against stdlib only (`ipaddress`, `urllib.parse`), the same posture `parse_github_clone_url` (`scanning/domain/repo_url.py`) already takes for repo-URL validation — not importing a URL-parsing library there either.

## Decision

The SSRF gate is two functions, split along the same pure/impure boundary `parse_github_clone_url` (pure) vs. `git clone` (impure I/O) already established:

- `scanning/domain/target_url.py::validate_target_url_syntax(url)` — pure, zero I/O. Rejects any scheme other than `http`/`https`, userinfo-in-URL, `localhost`/`localhost.`, and a hostname that is itself a literal IP (v4 or v6, including the bracketed `[::1]` URL form) in a private/loopback/link-local/reserved/multicast range.
- `scanning/domain/target_url.py::validate_resolved_ips_are_public(ips)` — the DNS-rebinding gate. Applies the identical range check to already-resolved IPs. A hostname that passes the syntax check is not yet trusted; it still has to be resolved, and the resolved IP checked, immediately before the target is used.

DNS resolution is genuine I/O and does not belong in `domain/` (this project's domain unit tests use in-memory fakes, never real network calls). It's exposed as `scanning/ports/dns_resolver.py::DnsResolverPort` (`async def resolve(hostname) -> list[str]`), with `scanning/adapters/outbound/dns/system_dns_resolver.py::SystemDnsResolver` as the production implementation, using `asyncio.get_running_loop().getaddrinfo(...)` (async-native, not a hand-rolled `to_thread` wrapper). Kept as a real `Protocol`, not a bare callable, even though it currently has exactly one caller and one production implementation — matching this codebase's existing precedent (`ClockPort`/`IdGeneratorPort` in `shared_kernel/ports.py` are Protocols under the same conditions), and giving `ZapAdapter`'s unit tests a fakeable seam (`FakeDnsResolver`) for asserting the gate's call order without a real DNS lookup.

Both checks run as the literal first lines of `ZapAdapter.run()`, before any subprocess/Docker call — mirroring `GitRepoCheckout.checkout()` calling `parse_github_clone_url` as its own first line (ADR-0011 point 2). This is a structural gate: any future caller of `ZapAdapter` gets it automatically, it can't be forgotten at a call site.

`ZapAdapter` takes an `allow_private_targets: bool = False` constructor flag, mirroring `TrivyAdapter.skip_db_update`'s "safe production default, explicit test-only override" shape (ADR-0012). Production code must never set it `True`. It exists because a real integration test needs a target ZAP can actually attack, and no CI-reachable target exists outside a locally-bound fixture server — there is no way to exercise the real Docker/ZAP path against a genuinely public target in CI. When `True`, both checks are skipped entirely, including DNS resolution (the resolver is never even consulted).

## Consequences

The SSRF gate is fully unit-testable without a real network call: `validate_target_url_syntax`/`validate_resolved_ips_are_public` need no fakes at all, and `ZapAdapter`'s call-order tests (private IP rejected before any subprocess spawn; public IP allowed through; `allow_private_targets=True` skipping the resolver entirely) use `FakeDnsResolver` plus a monkeypatched `asyncio.create_subprocess_exec`. The one path this can't cover in CI is a real DAST scan against a genuinely public target — the integration test necessarily uses the `allow_private_targets=True` escape hatch against a local fixture server, which is a deliberate, documented gap, not an oversight.

No new third-party dependency was added for this — the entire gate rests on stdlib `ipaddress`/`urllib.parse` plus this codebase's own `Protocol`-based port pattern, keeping M3.5 consistent with `repo_url.py`'s precedent of hand-rolling URL validation rather than reaching for a library to do it.

## Amendments

- **2026-08-27: the Decision's *"Both checks run as the literal first lines of `ZapAdapter.run()`"* is struck. It is false as written, and it contradicts this ADR's own Consequences, which already records the escape hatch correctly.** The first statement of `run()` is the `allow_private_targets` conditional and both gates are nested inside it, so neither runs when the flag is `True`. Left uncorrected: `validate_zap_target_url`'s docstring in `projects/domain/scanner_config.py`.
- **Restated: both gates run before the target is contacted and before any subprocess is spawned, in that order.** Not *"before any network call"* — the only I/O between them is the DNS resolution the second gate exists to check, which this ADR's own Decision calls genuine I/O. Between `validate_resolved_ips_are_public` and the `docker run` spawn there are five statements — `tempfile.mkdtemp`, `os.chmod`, the container-name f-string, the `try:`, and the plan write — none of which touches the network or starts a process; that is a reading of the source, not a timing measurement. `tests/unit/test_zap_adapter_ssrf_gate.py::test_rejects_a_private_resolved_ip_before_spawning_any_subprocess` pins the subprocess half by asserting nothing was spawned; the five intervening statements are pinned by nothing. The structural-gate claim is unaffected — it rested on the gates being inside `run()`, not on their being its first lines.

## Alternatives considered

**A single function combining syntax check and DNS resolution**, rather than two. Rejected: it would force `domain/target_url.py` to either perform real I/O (violating the project's "domain unit tests use in-memory fakes, no real network" testing rule) or take a port dependency directly in `domain/` (violating the layering convention that only `application/`/`adapters/` orchestrate through ports). Splitting them keeps the syntax check trivially unit-testable and puts the I/O-dependent orchestration where it belongs — inside `ZapAdapter.run()`, an adapter.

**A bare `Callable[[str], Awaitable[list[str]]]` instead of `DnsResolverPort`.** Rejected: loses the self-documenting name at construction/DI call sites, is less discoverable via the `ports/` directory than `ZapAdapter`'s sibling ports, and this codebase already has precedent for single-implementation Protocols (`ClockPort`, `IdGeneratorPort`).

**A third-party SSRF-validation library** (`oomnitza-ssrf-protection`, the only concrete candidate found). Rejected per ADR-009: could not be confirmed as actively maintained from primary sources within this research pass, and no other established alternative was found.
