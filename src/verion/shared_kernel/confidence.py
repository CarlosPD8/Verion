from enum import StrEnum


class Confidence(StrEnum):
    """How a Risk's membership was established — its GROUPING PROVENANCE. M8.5, ADR-0037.

    Shared between the module that *produces* the value (`correlation`, where
    `build_match_key` knows which branch placed each finding) and the module that
    *compares and folds* it (`risk_engine`, where a surface's own value is derived from its
    members'). Neither may import the other's `domain/` (rule 3), which is the situation
    ADR-0018 decision 2's criterion exists for:

    > `shared_kernel/` takes **closed vocabularies** — enumerations — that two or more
    > modules must **compare or order**, not merely **transport**.

    It is this package's **third enum**, and the first thing the criterion has admitted
    since it was written: `Severity` was admitted in the act of stating it, `ScannerTool`
    predates it, and every application since has been a refusal (ADR-0018's 2026-09-20
    amendment lists the five). The two alternatives were rejected on the record — one enum
    per module held equal by a test is **G33**'s shape, two declarations kept in agreement
    by nothing else; and a bare `str` crossing would let `"inferrd"` type-check on a frozen
    domain type feeding three routes.

    **What this value is NOT, and the API says so too.** It is not a statement that a
    finding is real, and not a statement that two scanners agree or found the same
    vulnerability. `correlation` owns that text as `CONFIDENCE_DEFINITION` and every
    response carrying a value carries the definition with it, because **no prompt receives
    this value** (ADR-0037 decision 9) — so nothing else would tell a reader what it means.

    **Note the name collision, which is deliberate on the API side and a trap on the input
    side.** `Finding.confidence` — a per-finding value only ZAP supplies — is a different
    thing, an *input*, declined by ADR-0005 decision 4 with its re-propose condition still
    unmet (**G94**). This is a per-Risk *output*.

    **Crossing a boundary loses the type**, per decision 2's own asymmetry note: a value
    read back from a `String` column or a JSON body is a `str`, and `Confidence("...")`
    reconstructs it before anything compares it. `brief`'s repository is where that bites.
    """

    UNGROUPED = "ungrouped"
    """The key carried no signal, so nothing could be grouped on and the finding stands alone.

    Exactly `not MatchKey.has_signal`. `group_by_match_key` makes such a finding a singleton,
    so this value only ever describes a surface of one — but the converse does not hold, and
    that is why the scale is keyed on the signal rather than on the member count: a Trivy
    package surface with one CVE was keyed on a real signal and would have absorbed a second
    finding on that package, so it is `REPORTED`.
    """

    REPORTED = "reported"
    """Every member attached through a field its own scanner reported.

    A ZAP alert keyed on its own `Location.url`'s path, or a Trivy finding keyed on its own
    `Location.package`. Nothing was inferred.
    """

    INFERRED = "inferred"
    """At least one member was placed here by Verion, not by the scanner that found it.

    A Semgrep finding carries no `Location.url`, so it reaches a route-path surface only by
    `build_match_key` matching its file and line against the project's route map — and only
    while the serving declaration is in force (ADR-0029 decision 4). A surface is `INFERRED`
    if **any** member arrived that way, because the claim it qualifies is about the group.

    **It does not mean the grouping is wrong**, and it does not mean a `REPORTED` grouping is
    substantive: on `/calculate`, the one cross-tool surface either corpus exhibits, the
    members carrying `REPORTED` are the coincidental header alerts and the `INFERRED` one is
    the finding the product exists to find (**G62**, ADR-0037 decision 11).
    """
