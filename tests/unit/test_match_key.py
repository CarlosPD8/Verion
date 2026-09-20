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

from verion.modules.correlation.application.match_key_builder import build_match_key
from verion.modules.correlation.domain.match_key import (
    SCOPE_FIELDS,
    SIGNAL_FIELDS,
    MatchKey,
    MatchKeyResult,
)
from verion.modules.correlation.domain.matching import MatchGroup, group_by_match_key, matches
from verion.modules.correlation.ports.candidate_risk import CONFIDENCE_DEFINITION
from verion.modules.normalization.domain.finding import Finding, Location
from verion.shared_kernel.confidence import Confidence

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


def _entry(finding_id: str, key: MatchKey) -> tuple[str, MatchKeyResult]:
    """A grouping entry for a hand-built key, with the provenance the builder would have given it.

    `group_by_match_key` takes the builder's whole result since M8.5 (ADR-0037), so a key alone
    is no longer an entry. The confidence is derived from `has_signal` here rather than passed,
    because these tests are about the *grouping* and a hand-picked value would be a second
    statement of the builder's rule inside a test of something else. The rule itself is asserted
    against the real builder below.
    """
    return (
        finding_id,
        MatchKeyResult(
            key=key,
            confidence=Confidence.REPORTED if key.has_signal else Confidence.UNGROUPED,
        ),
    )


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
            _entry("f1", _package_key("urllib3")),
            _entry("f2", _package_key("urllib3")),
            _entry("f3", _package_key("Flask")),
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
    groups = group_by_match_key([_entry("f1", _no_signal_key()), _entry("f2", _no_signal_key())])

    assert [group.finding_ids for group in groups] == [("f1",), ("f2",)]


def test_grouping_does_not_depend_on_the_order_the_findings_arrive_in():
    """Deterministic regardless of input order, not merely deterministic per run.

    The repository's order is an implementation detail of whichever read the caller used,
    and this repo already carries two scars from a representative chosen by list position.
    """
    entries = [
        _entry("f1", _package_key("urllib3")),
        _entry("f2", _url_key("http://t/")),
        _entry("f3", _package_key("urllib3")),
        _entry("f4", _no_signal_key()),
        _entry("f5", _no_signal_key()),
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
        _entry("f1", _package_key("urllib3")),
        _entry("f2", _package_key("urllib3")),
        _entry("f3", _package_key("Flask")),
        _entry("f4", _url_key("http://t/")),
        _entry("f5", _no_signal_key()),
        _entry("f6", _no_signal_key()),
    ]
    key_of = {finding_id: result.key for finding_id, result in entries}
    groups = group_by_match_key(entries)

    for group in groups:
        for left, right in itertools.combinations(group.finding_ids, 2):
            assert matches(key_of[left], key_of[right]) is True

    for one, other in itertools.combinations(groups, 2):
        for left in one.finding_ids:
            for right in other.finding_ids:
                assert matches(key_of[left], key_of[right]) is False


# ---------------------------------------------------------------------------
# Provenance — M8.5, ADR-0037. G53's closure, asserted rather than left to `mypy`
# ---------------------------------------------------------------------------


def _build(*, package=None, url=None, file_path=None, start_line=None, paths_serving=None):
    """The real builder over scalars, so these assert the shipped branch rule and not a copy."""
    return build_match_key(
        project_id=_PROJECT,
        package=package,
        url=url,
        file_path=file_path,
        start_line=start_line,
        paths_serving=paths_serving,
    )


def _one_route(path):
    return lambda *, file_path, line: (path,)


def _no_route(*, file_path, line):
    return ()


def _two_routes(*, file_path, line):
    return ("/a", "/b")


def test_every_confidence_the_builder_can_produce_is_declared_and_every_declared_one_is_produced():
    """The set the builder yields EQUALS the set the enum declares. ADR-0037 decision 4.

    **What this enforces, stated exactly, because the obvious reading claims more.** The
    `produced` set is built from four hand-written calls, one per branch of the builder. So it
    enforces *declared is a subset of produced*: a member added to `Confidence` that no branch
    here reaches fails, which is what stops the vocabulary advertising a value the product
    cannot emit. The other direction holds because `Confidence` is an enum and `mypy` checks
    the return type — not because this test says so.

    **What it therefore does NOT catch**: a fifth branch added to the builder that returns an
    existing value. Nothing here enumerates the builder's branches, and nothing can without
    parsing it, so the four calls below have to be extended by hand when a branch is.

    Still worth its place: the annotation says *a* `Confidence`, and this says *which ones*.
    """
    produced = {
        _build(url="http://t/calculate?x=1").confidence,
        _build(package="urllib3").confidence,
        _build(
            file_path="app.py", start_line=28, paths_serving=_one_route("/calculate")
        ).confidence,
        _build().confidence,
    }

    assert produced == set(Confidence)


def test_a_derived_url_is_inferred_and_a_reported_url_is_not():
    """**The security-relevant one.** ADR-0037 decision 1.

    A finding with no url of its own, placed on a route path by the map, is `INFERRED`. A
    finding keyed on the url its own scanner reported is `REPORTED`. Both end with the same
    `url` on the key — that equality is what makes the cross-tool group possible (ADR-0029
    decision 4) — so the key alone cannot tell them apart and the confidence is the only thing
    that does. Collapsing these two to one value makes an inference indistinguishable from an
    observation, which is the whole claim this issue ships.
    """
    derived = _build(file_path="app.py", start_line=28, paths_serving=_one_route("/calculate"))
    reported = _build(url="http://target:8080/calculate?expr=2*3")

    assert derived.key.url == reported.key.url == "/calculate"
    assert derived.confidence is Confidence.INFERRED
    assert reported.confidence is Confidence.REPORTED


def test_a_no_signal_key_is_ungrouped_and_a_package_key_is_reported():
    """Keyed on `has_signal`, never on how many members the group ends up with.

    A Trivy finding alone on a package was keyed on a real signal and would have absorbed a
    second finding on that package, so it is `REPORTED` even as a group of one. A finding whose
    key carries nothing is `UNGROUPED`. A scale keyed on cardinality would call both the same.
    """
    assert _build(package="urllib3").confidence is Confidence.REPORTED
    assert _build().confidence is Confidence.UNGROUPED


@pytest.mark.parametrize(
    "paths_serving", [None, _no_route, _two_routes], ids=["gated", "zero", "two"]
)
def test_a_finding_the_map_does_not_place_is_ungrouped_rather_than_inferred(paths_serving):
    """The three ways the derivation declines, all landing on the honest value.

    `None` is the serving declaration absent or out of force; zero paths is a line no route
    serves; two or more is a stacked view's shared body, which derives nothing rather than
    picking one. None of them may report `INFERRED`, because nothing was inferred.
    """
    result = _build(file_path="app.py", start_line=28, paths_serving=paths_serving)

    assert result.key.url is None
    assert result.confidence is Confidence.UNGROUPED


def test_every_group_carries_one_confidence_per_member_in_member_order():
    """The alignment invariant, which is the whole meaning of `member_confidence`.

    Asserted over a group whose members have DIFFERENT provenance and whose ids sort into a
    different order than they arrive in — otherwise a mis-sorted tuple still reads correctly by
    accident. `finding_ids` and `member_confidence` are sorted as pairs, so index *i* of one
    describes index *i* of the other.
    """
    derived = MatchKeyResult(key=_url_key("/calculate"), confidence=Confidence.INFERRED)
    reported = MatchKeyResult(key=_url_key("/calculate"), confidence=Confidence.REPORTED)

    [group] = group_by_match_key([("f-9", derived), ("f-1", reported), ("f-5", reported)])

    assert group.finding_ids == ("f-1", "f-5", "f-9")
    assert group.member_confidence == (
        Confidence.REPORTED,
        Confidence.REPORTED,
        Confidence.INFERRED,
    )
    assert len(group.member_confidence) == len(group.finding_ids)


def test_the_group_field_set_is_exactly_these_three():
    """`MatchGroup` is the one hop in the carrier chain that had no field-set assertion.

    Equality, so a field added in passing fails here rather than being depended on, and so does
    losing one. Paired with the alignment test above deliberately: this catches the field
    arriving or leaving, that one catches it arriving meaningless.
    """
    assert {field.name for field in dataclasses.fields(MatchGroup)} == {
        "key",
        "finding_ids",
        "member_confidence",
    }


def test_the_definition_names_every_confidence_value():
    """The text and the vocabulary cannot drift apart. ADR-0037 decision 10.

    A value added to `Confidence` without extending `CONFIDENCE_DEFINITION` fails here. That
    matters more than usual because **no prompt receives this value**: the definition on the
    response is the only thing that tells a reader what it means, so a value the text does not
    define would reach a user as a bare word.
    """
    for confidence in Confidence:
        assert f"'{confidence.value}'" in CONFIDENCE_DEFINITION, confidence


def test_the_definition_says_what_the_value_does_not_mean():
    """**G62**'s sentence, reused verbatim rather than paraphrased.

    The inversion this exists for: on `/calculate` the members carrying `reported` are the
    coincidental header alerts and the `inferred` one is the finding the product exists to
    find. A reader who takes the confidence as a statement about substantiveness gets it
    exactly backwards, so the text has to refuse that reading in terms.
    """
    assert "It does not mean the scanners agree, confirm each other, or found the same" in (
        CONFIDENCE_DEFINITION
    )
    assert "not a statement about whether any finding is real" in CONFIDENCE_DEFINITION
