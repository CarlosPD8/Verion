from typing import Protocol

from verion.modules.correlation.domain.exceptions import CorrelationError
from verion.modules.correlation.domain.matching import MatchGroup

# What a Risk's `confidence` means, in the words a reader receives. M8.5, ADR-0037
# decision 10.
#
# **Declared in `ports/` rather than beside `build_match_key`, and the difference from
# `CORROBORATION_DEFINITION` is the reason.** That constant rides a per-item carrier
# (`ExplainableSignal.definition`) and so can live in `risk_engine/domain/`. This one is
# ONE CONSTANT PER RESPONSE — on `/scored-risks`' envelope beside the thresholds, on a
# Brief's item — so consumers import it by name instead, and a port module is the only
# place in this module they may name (`cross-module-risk-engine` and `cross-module-brief`
# forbid `correlation.domain` and `.adapters`, not `.ports`). Beside `build_match_key` in
# `application/` it would be unreachable to both without the rule-3 violation no contract
# catches (**G35**). One declaration, two readers, no copy — asserted byte-identical across
# both placements, which is what makes "one owner" a claim rather than a convention.
#
# **It names all three values and defines each**, so the text and the enum cannot drift:
# a value added without extending this string fails a test. Its last sentence is
# `CORROBORATION_DEFINITION`'s own, because the thing a reader must not conclude is the
# same thing (**G62**) — and on the one cross-tool surface either corpus exhibits, the
# label points the opposite way to how it reads (ADR-0037 decision 11).
CONFIDENCE_DEFINITION = (
    "How this Risk's membership was established. 'reported' means every finding was placed "
    "on this surface by a field its own scanner reported. 'inferred' means at least one was "
    "placed there by Verion matching its file and line against a route map built from the "
    "project's source. 'ungrouped' means the finding carried no signal to group on and "
    "stands alone. It is not a statement about whether any finding is real. It does not mean "
    "the scanners agree, confirm each other, or found the same vulnerability."
)


class CandidateRiskAccessDenied(CorrelationError):
    """The caller may not read this project's candidate Risks.

    **Declared in `ports/` rather than in `domain/`, and that placement is the whole
    reason this class exists separately from `domain.exceptions.ProjectAccessDenied`.**
    `cross-module-risk-engine` forbids `verion.modules.correlation.domain` and
    `verion.modules.correlation.adapters` and says nothing about `ports` — which is the
    mechanism that lets another module consume this port at all. A published port that
    can DENY must therefore carry its denial where its consumer is allowed to name it;
    otherwise the consumer's inbound adapter (M6.3's route) can only handle the denial by
    importing `correlation.domain`, which rule 3 forbids and no contract would catch
    (**G35**). Raising the domain exception through the port would have made the port
    look legal while leaving its only possible consumer a violation.

    Carries no detail beyond the message `correlation` already produces, which names the
    project id the caller itself supplied. Like `ProjectAccessDenied`, it does not
    distinguish "no such project" from "not a member" — the port beneath it cannot.

    **Subclasses `CorrelationError` rather than `Exception`**: it is one of this module's own
    failures, so `except CorrelationError` must catch it. Inheriting from the domain base is
    not the leak this class exists to avoid — that leak is a *consumer* having to NAME
    `correlation.domain`, and a consumer catching this type never does.
    """


class CandidateRiskPort(Protocol):
    """A project's candidate Risks — `correlation`'s first published port.

    Decided at M6.1 (ADR-0005 decision 2); shipped at M6.2.

    **Why this exists rather than `risk_engine` calling `CorrelateFindingsUseCase`
    directly.** The only producer of candidate Risks is that use case, in
    `correlation/application/`, and importing another module's `application/` is what rule
    3 forbids in words while no import-linter contract forbids it in CI — **G35**, whose
    second trigger this port answers. ADR-0005 decision 2 chose to publish a port rather
    than take that hole, so the eight contracts are left untouched and G35 stays open with
    its own fix still unclaimed.

    **What crosses, and what does not.** This returns `correlation`'s own `MatchGroup`s.
    The consumer takes them **by inference** off this annotation and never names the type,
    exactly as `CorrelateFindingsUseCase` takes `Finding` off `FindingRepositoryPort` — the
    pattern `allow_indirect_imports = true` exists to permit. A `MatchGroup` carries a key,
    `finding_ids`, one `Confidence` per member (M8.5, ADR-0037) and **no severity**, so a
    consumer that needs to score one must read findings itself through `normalization`'s
    port; that second read is **G61**, and M8.5 adds none — the provenance rides a carrier
    that already crosses.

    **The `Confidence` is `shared_kernel`'s**, so a consumer folds and compares it without
    naming anything under `correlation.domain`, exactly as it already does with
    `ScannerTool` and `Severity`.

    Deliberately not widened to carry per-finding scoring scalars. ADR-0005 decision 3
    names that alternative and rejects it for M6: it would make `correlation` decide what
    `risk_engine` needs, a coupling worse than the read unless the read is measured slow.
    """

    async def candidate_risks(self, *, project_id: str, user_id: str) -> list[MatchGroup]:
        """This project's candidate Risks, grouped, for a caller allowed to read them.

        Authorizes before reading anything, and raises `CandidateRiskAccessDenied` if the
        caller may not read the project. Persists nothing and returns no Risk identifier —
        a candidate Risk is a projection recomputed per request (ADR-0025 decision 1), so
        two calls may legitimately return different groups as findings arrive.

        Ordering is `correlation`'s total order over groups, not a priority order. Nothing
        here is scored; scoring is `risk_engine`'s and ranking is M6.3's.
        """
        ...
