"""The match key and the matching relation (M5.8), against ADR-0023.

Three things here are not ordinary coverage and say so:

- the **conformance** test, which derives the key's expected annotations from
  `Finding`'s AND `Location`'s own declarations — over `Finding` alone it would cover
  one field of three and pass green (ADR-0023's 2026-08-26 amendment, section 7);
- the **negative** cases, whose subject is operand order — G8's named trigger and M5.8's
  criterion (c). They are the analogue of `test_severity.py`'s `operator`-function form
  rather than a copy of it: there the subject was the comparison operators themselves, so
  `operator.lt` and friends were literally under test, while `matches(a, b)` is already a
  call. The coverage is carried by two named wrappers, one per operand order, so no
  operand-order assertion is written as a comparison expression that a fix could invert;
- the **anti-identity** test, which pins that the relation is over values rather than
  over object identity.
"""

import dataclasses
import itertools
import typing

import pytest

from verion.modules.correlation.domain.match_key import SCOPE_FIELDS, SIGNAL_FIELDS, MatchKey
from verion.modules.correlation.domain.matching import group_by_match_key, matches
from verion.modules.normalization.domain.finding import Finding, Location

_PROJECT = "project-1"
_OTHER_PROJECT = "project-2"

# Which type each of the key's fields replicates. This map is the CLAIM under test, so
# it is written out; what is derived is everything checked against it. Two of the three
# entries are `Location` and that is the whole point of section 7 — a conformance test
# that assumed `Finding` for all three would cover `project_id` and silently skip the
# other two.
_FIELD_SOURCES = {
    "project_id": Finding,
    "package": Location,
    "url": Location,
}


def _package_key(package: str, *, project_id: str = _PROJECT) -> MatchKey:
    return MatchKey(project_id=project_id, package=package, url=None)


def _url_key(url: str, *, project_id: str = _PROJECT) -> MatchKey:
    return MatchKey(project_id=project_id, package=None, url=url)


def _no_signal_key(*, project_id: str = _PROJECT) -> MatchKey:
    return MatchKey(project_id=project_id, package=None, url=None)


# ---------------------------------------------------------------------------
# Conformance — ADR-0023 section (b), sharpened by the amendment's section 7
# ---------------------------------------------------------------------------


def test_the_conformance_check_runs_over_both_source_types():
    """The precondition the rest of the conformance rests on, asserted rather than assumed.

    Section (b) as written says to derive the expected annotations from `Finding`'s own
    declarations. Two of the three fields are not on `Finding` — `package` and `url` live
    on `Location` — so a test following it literally covers one field of three and passes
    green. That defect is registered; this line is what stops it recurring here, by making
    a `_FIELD_SOURCES` narrowed back to one type fail immediately rather than quietly.
    """
    assert set(_FIELD_SOURCES.values()) == {Finding, Location}


def test_the_key_replicates_its_sources_annotations_without_narrowing():
    """Derived from both domain declarations, never retyped.

    A hand-written list of expected annotations would be a third copy, free to drift from
    both sides, and would assert that correlation agrees with itself. This compares the
    key's annotation against the annotation on the type it came off, so a `Finding` or
    `Location` field that is renamed, removed or re-typed fails here — the ADR-0020
    decision 4 shape.

    `typing.get_type_hints` rather than `field.type` directly: the two modules would have
    to agree about postponed annotations for a raw comparison to mean anything, and
    resolving both sides makes the test independent of that.
    """
    declared = {field.name for field in dataclasses.fields(MatchKey)}
    assert declared == set(_FIELD_SOURCES)

    key_hints = typing.get_type_hints(MatchKey)
    for name, source in _FIELD_SOURCES.items():
        source_names = {field.name for field in dataclasses.fields(source)}
        assert name in source_names, f"'{name}' is not declared on {source.__name__}"
        assert key_hints[name] == typing.get_type_hints(source)[name]


def test_every_key_field_is_declared_either_scope_or_signal():
    """A field cannot join the key without somebody deciding which half it is in.

    Total and disjoint. Without this, a fourth field would default to being invisible to
    `has_signal` — so a key carrying only that field would count as carrying no signal and
    become a singleton, which is the opposite of why anyone would have added it.
    """
    declared = {field.name for field in dataclasses.fields(MatchKey)}
    assert set(SCOPE_FIELDS) | set(SIGNAL_FIELDS) == declared
    assert not set(SCOPE_FIELDS) & set(SIGNAL_FIELDS)


@pytest.mark.parametrize("signal_field", SIGNAL_FIELDS)
def test_any_one_signal_field_on_its_own_makes_a_key_carry_signal(signal_field):
    """Derived from `SIGNAL_FIELDS`, so adding a name there without teaching `has_signal`
    fails here rather than making the constant decorative."""
    populated = {"project_id": _PROJECT, "package": None, "url": None, signal_field: "x"}
    assert MatchKey(**populated).has_signal is True


def test_a_key_carrying_only_scope_has_no_signal():
    assert _no_signal_key().has_signal is False


# ---------------------------------------------------------------------------
# Should correlate
# ---------------------------------------------------------------------------


def test_two_findings_on_the_same_package_match():
    assert matches(_package_key("urllib3"), _package_key("urllib3")) is True


def test_two_findings_at_the_same_url_match():
    assert matches(_url_key("http://t:8080/"), _url_key("http://t:8080/")) is True


def test_equal_keys_match_as_VALUES_rather_than_as_instances():
    """The positive counterpart to the anti-identity test below.

    Two findings produce two separately constructed keys, never one shared object, so a
    relation that answered on object identity would report these as not matching. Pinned
    because the whole grouping rests on it.
    """
    left, right = _package_key("urllib3"), _package_key("urllib3")
    assert left is not right
    assert matches(left, right) is True


# ---------------------------------------------------------------------------
# Should NOT correlate — operand order is the subject (G8, M5.8 criterion (c))
# ---------------------------------------------------------------------------


def _forward(left: MatchKey, right: MatchKey) -> bool:
    return matches(left, right)


def _reversed(left: MatchKey, right: MatchKey) -> bool:
    return matches(right, left)


_BOTH_ORDERS = (_forward, _reversed)


@pytest.mark.parametrize("call", _BOTH_ORDERS, ids=["forward", "reversed"])
@pytest.mark.parametrize(
    ("left", "right"),
    [
        pytest.param(_package_key("urllib3"), _package_key("Flask"), id="different-package"),
        pytest.param(_url_key("http://t/a"), _url_key("http://t/b"), id="different-url"),
        pytest.param(
            _package_key("urllib3"),
            _package_key("urllib3", project_id=_OTHER_PROJECT),
            id="same-package-different-project",
        ),
        pytest.param(_package_key("urllib3"), _url_key("http://t/"), id="package-against-url"),
        pytest.param(_package_key("urllib3"), _no_signal_key(), id="signal-against-no-signal"),
        pytest.param(_no_signal_key(), _no_signal_key(), id="two-equal-no-signal-keys"),
    ],
)
def test_findings_that_should_not_correlate_do_not_match(call, left, right):
    """Both operand orders, every case.

    **The subject of these assertions is operand order**, which is G8's named trigger:
    `ruff --fix`'s SIM300 rewrites a Yoda condition by inverting it, which once collapsed
    four distinct assertions in `test_severity.py` into two duplicated pairs and deleted
    every direct-order case, leaving a docstring claiming coverage that no longer ran.
    Written with named `operator`-style functions rather than by calling `matches` twice
    inline, so there is no comparison expression for a fix to rewrite. `unfixable` is a
    second line of defence, not a replacement for this form.

    Two of the cases are worth naming for what they establish rather than what they check.
    `same-package-different-project` is the tenant boundary: `project_id` is scope, so an
    equal signal across two projects must not correlate. `package-against-url` is the
    cross-tool case, and note what it does NOT prove — cross-tool matching is prevented by
    the MAPPERS, which construct `package` only for Trivy and `url` only for ZAP, not by
    the key. This pins that the key does not undo it.
    """
    assert call(left, right) is False


def test_a_no_signal_key_does_not_match_even_itself():
    """The relation must not turn on whether a caller reused an object.

    An earlier draft of `matches` opened with `if left is right: return True`, to make the
    relation reflexive for a no-signal key. Under it, this assertion would have been
    `True` while the equal-but-distinct pair above stayed `False` — the same two findings
    answering differently depending on whether the caller happened to build the key once
    or twice.

    There is deliberately no test of "reflexivity" in this file. Reflexivity is not this
    function's property; it is the grouping's, and it is asserted where it actually lives
    — `test_a_finding_with_no_signal_becomes_its_own_group_of_one`. The amendment's rule
    is that such a key matches no OTHER *finding*, which is a statement about findings
    rather than about `MatchKey` instances.
    """
    key = _no_signal_key()
    assert matches(key, key) is False


# ---------------------------------------------------------------------------
# Grouping — by key value, and where the singleton actually comes from
# ---------------------------------------------------------------------------


def test_findings_sharing_a_signal_land_in_one_group():
    groups = group_by_match_key(
        [
            ("f1", _package_key("urllib3")),
            ("f2", _package_key("urllib3")),
            ("f3", _package_key("Flask")),
        ]
    )

    assert [(group.key.package, group.finding_ids) for group in groups] == [
        ("Flask", ("f3",)),
        ("urllib3", ("f1", "f2")),
    ]


def test_a_finding_with_no_signal_becomes_its_own_group_of_one():
    """A singleton Risk, never no Risk — and never a group of two absences.

    Both halves matter and they pull opposite ways. Dropping the finding would make a Risk
    count that cannot be reconciled against `count_for_project`, diverging with nothing
    saying so; this project already ranked the silent drop as the worse failure when
    `list_for_project` chose to raise rather than omit a finding with no sighting.
    Bucketing the two together would be the other error — matching two absences, which
    fabricates an event that no tool reported.
    """
    groups = group_by_match_key([("f1", _no_signal_key()), ("f2", _no_signal_key())])

    assert [group.finding_ids for group in groups] == [("f1",), ("f2",)]


def test_grouping_does_not_depend_on_the_order_the_findings_arrive_in():
    """Deterministic regardless of input order, not merely deterministic per run.

    The repository's order is an implementation detail of whichever read the caller used,
    and this repo already carries two scars from a representative chosen by list position.
    """
    entries = [
        ("f1", _package_key("urllib3")),
        ("f2", _url_key("http://t/")),
        ("f3", _package_key("urllib3")),
        ("f4", _no_signal_key()),
        ("f5", _no_signal_key()),
    ]

    assert group_by_match_key(entries) == group_by_match_key(list(reversed(entries)))
    assert group_by_match_key(entries) == group_by_match_key(entries[2:] + entries[:2])


def test_group_membership_agrees_with_the_pairwise_relation():
    """The bucketing and `matches` describe one relation, so they must not disagree.

    With one deliberate exception, stated here rather than glossed: a no-signal singleton's
    member does not match even itself, so the same-group half is asserted over *distinct*
    pairs only. That is the seam where the two are designed to differ — grouping puts every
    finding somewhere, while the relation refuses to pair a finding with anything.
    """
    entries = [
        ("f1", _package_key("urllib3")),
        ("f2", _package_key("urllib3")),
        ("f3", _package_key("Flask")),
        ("f4", _url_key("http://t/")),
        ("f5", _no_signal_key()),
        ("f6", _no_signal_key()),
    ]
    key_of = dict(entries)
    groups = group_by_match_key(entries)

    for group in groups:
        for left, right in itertools.combinations(group.finding_ids, 2):
            assert matches(key_of[left], key_of[right]) is True

    for one, other in itertools.combinations(groups, 2):
        for left in one.finding_ids:
            for right in other.finding_ids:
                assert matches(key_of[left], key_of[right]) is False
