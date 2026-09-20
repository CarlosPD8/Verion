from collections.abc import Sequence
from dataclasses import dataclass

from verion.modules.correlation.domain.match_key import MatchKey, MatchKeyResult
from verion.shared_kernel.confidence import Confidence


def matches(left: MatchKey, right: MatchKey) -> bool:
    """Whether two findings' keys match: equality on every field, with one exception.

    ADR-0023's 2026-08-26 amendment section 2. Equality on all fields is a real
    equivalence relation and therefore defines groups, which is what makes this ADR's
    third placement — matching logic in `domain/`, taking the KEY and never `Finding` —
    implementable at all. The exception narrows that relation without breaking it:
    **a key with no signal field present matches no OTHER finding.**

    **There is deliberately no identity branch here, and it is worth saying why so it
    does not get re-proposed.** An earlier draft opened with `if left is right: return
    True`, to make the relation reflexive for a no-signal key. That is object identity,
    not equality: two no-signal keys equal by value but constructed twice would answer
    `False` while two references to one instance answer `True`, so the answer would turn
    on whether a caller happened to reuse an object — not defensible for a frozen
    dataclass anyone can construct twice. It would also have made a test named for
    reflexivity pass on object identity rather than on its named subject, which is this
    project's own recurring failure shape arriving inside the test meant to prevent it.

    The amendment's "matches no OTHER finding" is about **findings**, not about `MatchKey`
    instances, and the reflexivity its argument needs is the GROUPING's — a no-signal
    finding becomes a singleton rather than no group. `group_by_match_key` produces that
    directly, so this function does not have to lie to deliver it.

    What is left is symmetric, and is an equivalence relation restricted to the
    signal-bearing keys. For any two no-signal keys — equal or not, same instance or not —
    the answer is `False`.

    **This departs from the letter of that amendment, which describes a no-signal key as
    matching only itself, and the departure is registered as G36 rather than argued only
    here.** The ADR sentence is what needs amending and this docstring is not the place to
    do it; G36 carries what breaks if somebody implements the ADR's wording instead.

    The alternative reading of FR-6, "shares SOME non-empty signal", is deliberately not
    what this implements: it is not transitive, so the groups it produces would depend on
    iteration order. That is the non-deterministic-representative mistake this repo
    already carries as a scar twice.
    """
    if not (left.has_signal and right.has_signal):
        return False
    return left == right


@dataclass(frozen=True)
class MatchGroup:
    """One candidate Risk's worth of findings: the key they share, and which they are.

    In `domain/` rather than `application/` because every field is a fact about the
    findings rather than an artifact of how a caller asked — the criterion
    `SightedFinding`'s docstring states and `ProjectFindings` deliberately fails.

    **`finding_ids` rather than the findings themselves, and the ground is the contract
    rather than convenience.** `cross-module-correlation` forbids `normalization.domain`,
    so no file in this module may NAME `Finding` — which a group of entities would have
    to, in `domain/` and again in the use case's return annotation. Nothing is lost at the
    M5.2 boundary: entity ids are plain strings end-to-end (rule 9), so an id is the same
    thing a persisted Risk would carry anyway.

    Ordered rather than merely collected — see `group_by_match_key`.

    **`member_confidence` is positionally aligned to `finding_ids`** (M8.5, ADR-0037): the
    confidence at index *i* is the provenance of the member at index *i*, and the two are
    sorted **together**, never independently. That alignment is the whole meaning of the
    field, so it is what `test_match_key.py` asserts rather than the field's presence — a
    tuple of the right length in the wrong order labels the wrong finding, silently, which is
    why `test_match_key.py` asserts the ORDER and not only the length — and why the lengths are
    checked below rather than left to a consumer.

    A tuple rather than a set, on this module's own convention above: a set would lose the
    alignment, and `finding_ids` is ordered for the same reason.
    """

    key: MatchKey
    finding_ids: tuple[str, ...]
    member_confidence: tuple[Confidence, ...]

    def __post_init__(self) -> None:
        """The alignment is a property of the TYPE, not of whoever reads it.

        `group_by_match_key` cannot violate it — it sorts pairs — so this guards the other
        constructors: a `CandidateRiskPort` implementation other than this module's, and the
        test fakes that already build groups by hand. Without it the only consumer that would
        notice is `ComputeRiskUseCase`'s `zip(..., strict=True)`; `correlation`'s own listing
        reads `finding_ids` alone and would serve a mismatched group as a clean 200.

        ADR-0020 decision 1's shape, one module over: make the invariant structural rather
        than a convention two readers happen to share.
        """
        if len(self.member_confidence) != len(self.finding_ids):
            raise ValueError(
                f"member_confidence has {len(self.member_confidence)} entries for "
                f"{len(self.finding_ids)} finding_ids; they are positionally aligned"
            )


def _group_order(group: "MatchGroup") -> tuple[str, bool, str, bool, str, str]:
    """A total order over groups, so the output never depends on input order.

    `None` sorts first (`False < True`), the same idiom
    `normalization/domain/finding.py`'s `_representative_key` uses for the fields
    `dedup_hash` excludes. **Copied rather than imported**: that helper is private and
    lives on the far side of `cross-module-correlation`, so reaching for it would be the
    boundary violation ADR-0023 exists to route around.

    The lowest finding id is the final tiebreak, and it makes the order total rather than
    merely deterministic: ids are unique, so no two groups can tie on it. It is needed
    because the no-signal groups all share one key value and would otherwise be
    indistinguishable to the sort.
    """
    key = group.key
    return (
        key.project_id,
        key.package is not None,
        key.package or "",
        key.url is not None,
        key.url or "",
        group.finding_ids[0],
    )


def group_by_match_key(entries: Sequence[tuple[str, MatchKeyResult]]) -> list[MatchGroup]:
    """Group `(finding_id, key-and-provenance)` pairs into candidate Risks.

    **Takes the builder's whole result since M8.5** (ADR-0037), so each member's provenance
    travels with it rather than being re-derived here from the key and the finding — which
    would be the second copy of `build_match_key`'s branch rule that G53's closure exists to
    prevent, moved one module inward.

    **By key VALUE, not by pairwise comparison.** Equality on all fields is an
    equivalence relation, so bucketing on the key is exactly the relation `matches`
    describes, computed once per entry instead of once per pair. Reading it as "compare
    everything to everything" would reintroduce the order-dependence the amendment's
    non-transitive alternative was rejected for.

    **A no-signal entry becomes a singleton group, and this is the only place that
    happens.** Between raising and silently dropping such a finding, this project has
    already ranked the drop as the worse of the two — `list_for_project` raises rather
    than omitting a finding with no sighting, because a finding silently vanishing from a
    listing is the worse failure. The same comparison decides it here, one module over: a
    Risk count that cannot be reconciled against `count_for_project` would diverge with
    nothing saying so.

    Note the consequence, since it is the seam where this function and `matches`
    deliberately disagree: two no-signal findings land in two groups even though their
    keys are equal, and `matches` reports `False` for that pair — which is the same
    answer read two ways, not a contradiction. Bucketing them together would be matching
    two absences.
    """
    bucketed: dict[MatchKey, list[tuple[str, Confidence]]] = {}
    groups: list[MatchGroup] = []
    for finding_id, result in entries:
        if not result.key.has_signal:
            groups.append(
                MatchGroup(
                    key=result.key,
                    finding_ids=(finding_id,),
                    member_confidence=(result.confidence,),
                )
            )
            continue
        bucketed.setdefault(result.key, []).append((finding_id, result.confidence))

    for key, members in bucketed.items():
        # Sorted as PAIRS, so the two tuples cannot drift apart: sorting `finding_ids` and
        # `member_confidence` separately would pass every length assertion and label the
        # wrong finding. `sorted` is on the id, which is unique within a group.
        ordered = sorted(members)
        groups.append(
            MatchGroup(
                key=key,
                finding_ids=tuple(finding_id for finding_id, _ in ordered),
                member_confidence=tuple(confidence for _, confidence in ordered),
            )
        )
    return sorted(groups, key=_group_order)
