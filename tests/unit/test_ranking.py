"""`rank_surfaces` — the only place in this system a priority order exists.

**No `ScoredSurface` here is hand-constructed.** Every one comes through the real
`score_surface`, so the scores this file sorts on are the function's own rather than numbers
chosen to make an ordering look right.

The hand-written values are `SurfaceMember` combinations, which is the class M6.2 registered
under **G19**'s shape — and this file **does** add to it, which is said plainly rather than
claimed away. Every individual member below is emittable, but **three of the surfaces are
not**: the url-keyed ones in the tie and determinism tests carry a lone `TRIVY` member, and
per **G64**'s derivation a Trivy key is `(package, None)` and never a url, so
`group_by_match_key` cannot produce them. They are used deliberately — giving them a `ZAP`
member would earn the exposure point and destroy the equal-score premise the tie test needs —
and they are marked `UNREACHABLE` at the site, the convention M6.2 established for exactly
this. Nothing here depends on those surfaces being producible: the subject is an ORDERING over
scored surfaces, which is total whatever produced them.
"""

from verion.modules.correlation.domain.match_key import MatchKey
from verion.modules.correlation.domain.matching import MatchGroup, _group_order
from verion.modules.risk_engine.domain.scoring import (
    Priority,
    SurfaceMember,
    rank_surfaces,
    score_surface,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

PROJECT = "proj-1"


def _surface(
    *,
    finding_id,
    package=None,
    url=None,
    severity=Severity.HIGH,
    source=ScannerTool.TRIVY,
):
    """One scored surface, through the real scoring function."""
    return score_surface(
        project_id=PROJECT,
        package=package,
        url=url,
        members=[SurfaceMember(finding_id=finding_id, source=source, severity=severity)],
    )


def _group(*, finding_id, package=None, url=None):
    """The `correlation` group the surface above was scored from."""
    return MatchGroup(
        key=MatchKey(project_id=PROJECT, package=package, url=url),
        finding_ids=(finding_id,),
    )


# --- the ordering itself ---------------------------------------------------------------


def test_the_highest_score_comes_first_and_this_order_IS_a_priority_order():
    """The exact inverse of `test_the_item_order_is_not_a_priority_order`, same seed.

    That test seeds `zzz`/`CRITICAL` and `aaa`/`LOW` and asserts the M5.2 listing returns
    them `aaa, zzz` — deterministic and explicitly not ranked. Scored, the two disagree:
    `5 + 0 + 0 = 5 → plan` and `2 + 0 + 0 = 2 → monitor`, so a priority order returns
    `zzz, aaa`. The same pair proves both routes, in opposite directions, which is why the
    seed is reused rather than invented.
    """
    critical = _surface(finding_id="f-1", package="zzz", severity=Severity.CRITICAL)
    low = _surface(finding_id="f-2", package="aaa", severity=Severity.LOW)

    assert (critical.priority_score, critical.priority) == (5, Priority.PLAN)
    assert (low.priority_score, low.priority) == (2, Priority.MONITOR)

    assert [surface.package for surface in rank_surfaces([low, critical])] == ["zzz", "aaa"]


def test_the_tiebreak_agrees_with_correlations_group_order():
    """**The copied tiebreak, checked against the thing it was copied from.**

    `_rank_order` replicates `_group_order`'s tuple so that within one bucket the scored
    route and the M5.2 listing return the same relative order — one order refined rather
    than two unrelated ones. That is an invariant over two functions in two modules, one of
    them private, and ADR-0030 decision 2 requires it asserted rather than claimed: a copied
    invariant with nothing checking it is a prose claim over a silent divergence, which is
    this project's recorded failure class.

    `tests/` is not bound by `lint-imports`, which is what lets one file import both.
    """
    specs = [
        {"finding_id": "f-3", "package": "zzz"},
        {"finding_id": "f-1", "url": "/alpha"},
        {"finding_id": "f-2", "package": "aaa"},
        {"finding_id": "f-4"},
        {"finding_id": "f-5", "url": "/beta"},
    ]
    surfaces = [_surface(**spec) for spec in specs]
    groups = [_group(**spec) for spec in specs]

    # The premise: every surface scores the same, so nothing but the tiebreak can order them.
    assert {surface.priority_score for surface in surfaces} == {4}

    ranked = rank_surfaces(surfaces)
    ordered = sorted(groups, key=_group_order)

    assert [(s.package, s.url, s.finding_ids[0]) for s in ranked] == [
        (g.key.package, g.key.url, g.finding_ids[0]) for g in ordered
    ]


def test_the_order_does_not_depend_on_input_order():
    """Total, not merely deterministic: ids are unique, so no two surfaces can tie outright."""
    specs = [
        {"finding_id": "f-1", "package": "aaa", "severity": Severity.LOW},
        {"finding_id": "f-2", "package": "bbb", "severity": Severity.CRITICAL},
        {"finding_id": "f-3", "url": "/x", "severity": Severity.HIGH},
        {"finding_id": "f-4", "severity": Severity.HIGH},
    ]
    surfaces = [_surface(**spec) for spec in specs]

    expected = [s.finding_ids for s in rank_surfaces(surfaces)]
    for rotation in range(len(surfaces)):
        rotated = surfaces[rotation:] + surfaces[:rotation]
        assert [s.finding_ids for s in rank_surfaces(rotated)] == expected


def test_scores_come_back_descending_across_every_bucket():
    surfaces = [
        _surface(finding_id="f-1", package="aaa", severity=Severity.INFO),
        _surface(finding_id="f-2", package="bbb", severity=Severity.CRITICAL),
        _surface(finding_id="f-3", package="ccc", severity=Severity.MEDIUM),
    ]

    scores = [surface.priority_score for surface in rank_surfaces(surfaces)]

    assert scores == sorted(scores, reverse=True)


# --- totality --------------------------------------------------------------------------


def test_an_empty_set_ranks_to_an_empty_list():
    assert rank_surfaces([]) == []


def test_a_surface_with_no_members_sorts_rather_than_raising():
    """`score_surface` admits a memberless surface and `group_by_match_key` cannot produce
    one, so this is a totality guard on the tiebreak's `finding_ids[0]` rather than a
    reachable case — the same distinction `score_surface`'s own no-member test draws."""
    empty = score_surface(project_id=PROJECT, package="aaa", url=None, members=[])
    scored = _surface(finding_id="f-1", package="bbb", severity=Severity.CRITICAL)

    ranked = rank_surfaces([empty, scored])

    assert ranked == [scored, empty]
