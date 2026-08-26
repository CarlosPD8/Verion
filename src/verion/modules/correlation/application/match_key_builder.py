from verion.modules.correlation.domain.match_key import MatchKey


def build_match_key(*, project_id: str, package: str | None, url: str | None) -> MatchKey:
    """Build a `MatchKey` from one finding's values. **The single conformance site.**

    ADR-0023's Decision puts key construction in `application/` and says why: this is the
    one place `mypy` compares correlation's description of `Finding` against the real one.
    A caller passes `finding.project_id`, `finding.location.package` and
    `finding.location.url` — values whose types come back through
    `FindingRepositoryPort`'s return annotation — into the parameters below, so a renamed,
    removed or re-typed source field fails the build here, at one site, with no test
    needed.

    **Scalars rather than a `Finding` parameter, and that is forced rather than chosen.**
    A parameter must be annotated under `mypy --strict`, and the annotation a `Finding`
    parameter would need is exactly the name `cross-module-correlation` forbids. Passing
    the three values keeps the comparison — `str` into `str`, `str | None` into
    `str | None` — without naming the type they came off.

    **That guarantee is bounded, and the bound is ADR-015's**, restated here because the
    check is easy to over-read: conformance holds only while the caller's value has a real
    type rather than `Any`. It does today, because it comes back from the port. It also
    does not detect an ADDED `Finding` field that should have been a signal, or a semantic
    change behind an unchanged signature — ADR-0023 section (c) lists both.

    A function rather than a `MatchKey(...)` call inlined in the use case, so that this stays
    ONE site when a second consumer arrives. *(That consumer was expected to be M5.2, and was
    not: ADR-0025 makes the Risk listing compose `CorrelateFindingsUseCase` rather than build
    keys of its own, so this is still the single caller. The reason to keep it a function is
    unchanged — two construction sites would be two places for the annotations to meet, and
    section (b)'s argument is about there being one.)*
    """
    return MatchKey(project_id=project_id, package=package, url=url)
