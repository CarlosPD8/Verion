import operator

import pytest

from verion.shared_kernel.severity import Severity


def test_the_scale_orders_by_severity_not_alphabetically():
    """The property the whole type exists for, and the one a plain StrEnum gets wrong.

    Inheriting str's ordering makes `HIGH >= CRITICAL` True, because "high" sorts
    after "critical". That is the exact expression ADR-0018 argues this type
    exists to make possible, so getting it wrong would put a silent lie inside
    `risk_engine` — the module CLAUDE.md singles out for disproportionate rigor.
    """
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    assert Severity.INFO > Severity.UNKNOWN

    # The specific comparison alphabetical ordering would invert.
    assert not Severity.HIGH >= Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH

    assert sorted(Severity) == [
        Severity.UNKNOWN,
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_equality_and_serialization_still_behave_like_a_str_enum():
    """Ordering is overridden; equality deliberately is not — persistence and JSON
    depend on it, exactly as they do for ScanStatus and ScannerTool."""
    assert Severity.HIGH == "high"
    assert str(Severity.HIGH) == "high"
    assert Severity("critical") is Severity.CRITICAL
    assert {Severity.HIGH: 1}["high"] == 1


@pytest.mark.parametrize("other", ["high", "zzz", 3, None, 4.0])
@pytest.mark.parametrize("op", [operator.lt, operator.le, operator.gt, operator.ge])
def test_ordering_against_a_non_severity_raises_rather_than_falling_back(op, other):
    """Returning NotImplemented here would let Python use the reflected str
    comparison and quietly restore alphabetical ordering — the bug the operators
    exist to prevent, arriving through the back door.

    **Both operand orders, all four operators.** Severity subclasses str, so a
    naive reading says `"zzz" > Severity.HIGH` would reach `str.__gt__` and
    quietly return a string comparison. It does not: Python gives a subclass's
    reflected method priority, so that expression routes to `Severity.__lt__` and
    raises. That is load-bearing and non-obvious, so it is pinned rather than
    trusted.

    Written with `operator` functions rather than infix comparisons on purpose.
    The infix form was here first and `ruff check --fix` rewrote it: SIM300 flags
    `Severity.HIGH < other` as a Yoda condition and inverts it to
    `other > Severity.HIGH`, which silently collapsed four distinct assertions
    into two duplicated pairs and deleted every direct-order case — the docstring
    still claimed both orders while only the reflected path ran. `operator.lt(a, b)`
    is not an infix comparison, so the lint has nothing to rewrite and the
    coverage cannot be autofixed away again.
    """
    with pytest.raises(TypeError, match="only ordered against Severity"):
        op(Severity.HIGH, other)
    with pytest.raises(TypeError, match="only ordered against Severity"):
        op(other, Severity.HIGH)


def test_sorting_a_mixed_list_raises_rather_than_ordering_alphabetically():
    with pytest.raises(TypeError, match="only ordered against Severity"):
        sorted([Severity.HIGH, "aaa"])


def test_every_member_has_a_distinct_rank():
    ranks = [member.rank for member in Severity]
    assert len(set(ranks)) == len(ranks)
    assert sorted(ranks) == list(range(len(Severity)))
