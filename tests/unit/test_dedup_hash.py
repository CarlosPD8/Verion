import inspect

import pytest

from verion.modules.normalization.domain.dedup import DEDUP_HASH_VERSION, compute_dedup_hash
from verion.shared_kernel.scanner_tools import ScannerTool


def _hash(**overrides) -> str:
    return compute_dedup_hash(
        **{
            "source": ScannerTool.SEMGREP,
            "rule_id": "rules.dangerous-eval",
            "file_path": "app.py",
            "package": None,
            "url": None,
            "http_method": None,
            "parameter": None,
            **overrides,
        }
    )


def test_the_same_inputs_always_produce_the_same_hash():
    assert _hash() == _hash()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", ScannerTool.TRIVY),
        ("rule_id", "rules.something-else"),
        ("file_path", "other.py"),
        ("package", "urllib3"),
        ("url", "http://target.example:8080/"),
        ("http_method", "GET"),
        ("parameter", "q"),
    ],
)
def test_every_declared_input_actually_participates(field, value):
    """Parametrized over the whole input set so no field can quietly stop
    contributing — dropping one would silently merge findings that differ only in
    it, which looks exactly like successful deduplication."""
    assert _hash(**{field: value}) != _hash()


def test_none_and_empty_string_are_not_the_same_input():
    """ "The tool said nothing" and "the tool said nothing was there" are different
    claims everywhere else in this schema, and the hash keeps them different too.
    JSON encoding is what makes this hold without a separator convention: `null`
    and `""` are distinct tokens."""
    assert _hash(package=None) != _hash(package="")


def test_the_hash_is_stable_across_processes_and_releases():
    """The literal digest, which is the only assertion here that catches a change
    to the *encoding* or the field *order* — every relative comparison above would
    happily pass against a different scheme.

    A failure means the hash contract changed. That is allowed, and the procedure
    is in `dedup.py`: bump DEDUP_HASH_VERSION and re-normalize from the retained
    ScanResult.raw_output rows. It is not allowed to happen by accident, which is
    what this test is for.
    """
    assert _hash() == "v1:1e6d23662931a2d3b13819b86efc3cb646e56961c6ebb32342f5bab0a228f8bd"


def test_the_value_carries_its_version_and_a_full_sha256():
    version, _, digest = _hash().partition(":")

    assert version == DEDUP_HASH_VERSION
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_the_input_set_is_exactly_the_signature():
    """The exclusions are the judgement this issue exists to make, so the set of
    inputs is pinned here rather than left to each mapper's discretion.

    Line numbers shift when code above them changes; `installed_version` changes
    on a bump that fixes nothing; severity, CVSS, CWE and title are advisory- or
    ruleset-mutable. Every one of those, included, would *fabricate* a resolution
    event — against an exclusion whose only cost is an under-count (ADR-0019).
    `test_finding.py` asserts the same thing from the other side, over two
    entities that differ only in the excluded fields.
    """
    parameters = set(inspect.signature(compute_dedup_hash).parameters)

    assert parameters == {
        "source",
        "rule_id",
        "file_path",
        "package",
        "url",
        "http_method",
        "parameter",
    }
