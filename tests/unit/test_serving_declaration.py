"""ADR-0028 decision 2's in-force rule, proved load-bearing per field.

**Why per field rather than in aggregate.** The rule compares three pairs. A suite that
only ever varies the target URL passes against a rule that compares only the target URL,
which is this repository's recorded failure shape arriving in the smallest possible place.
So each of the three fields has a case whose only difference is that field, and the
mutation table in this commit's message records that each one kills a rule ignoring it.

**Operand order, per G8.** The subject here is a three-way string comparison, which is
that entry's named trigger. Two things follow. The assertions call
`declaration_in_force` and compare the returned bool with `is`, so `ruff --fix`'s SIM300
has no comparison expression to rewrite — **the construction `test_match_key.py` uses**,
which is the file that writes `matches(...) is True/False`. `test_severity.py` is the
**analogue** rather than the same construction: it has no boolean-identity assertion at
all, and reaches the property by parametrizing `operator.lt/le/gt/ge` inside
`pytest.raises`. G8's own `Note (2026-08-26, M5.8)` draws that distinction — *"The form
is the analogue rather than the copy"* — and an earlier version of this sentence
collapsed the two. And the shuffled-fields case below is the operand-order test proper.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.serving_declaration import (
    ServingDeclaration,
    declaration_in_force,
)
from verion.shared_kernel.scanner_tools import ScannerTool

_AT = datetime(2026, 1, 1, tzinfo=UTC)

# The three live values, named once. Every case below differs from this baseline in
# exactly one place, which is what makes a per-field claim readable at the call site.
_TARGET_URL = "https://staging.example.com"
_REPO_URL = "https://github.com/example/repo"
_BRANCH = "main"


def _config(*, zap_target_url: str | None = _TARGET_URL) -> ScannerConfig:
    return ScannerConfig(
        id="config-1",
        project_id="project-1",
        enabled_tools=(ScannerTool.ZAP,),
        zap_target_url=zap_target_url,
        updated_at=_AT,
    )


def _repo(*, url: str = _REPO_URL, default_branch: str = _BRANCH) -> ConnectedRepo:
    return ConnectedRepo(
        id="repo-1",
        project_id="project-1",
        provider="github",
        url=url,
        default_branch=default_branch,
    )


def _declaration(
    *,
    declared_target_url: str = _TARGET_URL,
    declared_repo_url: str = _REPO_URL,
    declared_default_branch: str = _BRANCH,
) -> ServingDeclaration:
    return ServingDeclaration(
        id="declaration-1",
        project_id="project-1",
        declared_target_url=declared_target_url,
        declared_repo_url=declared_repo_url,
        declared_default_branch=declared_default_branch,
        declared_at=_AT,
        declared_by="user-1",
    )


def _in_force(
    declaration: ServingDeclaration | None,
    *,
    config: ScannerConfig | None = None,
    repo: ConnectedRepo | None = None,
) -> bool:
    """One call site for the rule, so a case reads as its own subject.

    Keyword-only past the declaration, for the reason the rule itself is: `config` and
    `repo` are both optional and a swapped pair would be caught by nothing, since
    `mypy` is scoped to `src/` (ADR-015) and never reads this file. An earlier version
    of this helper took them positionally while its docstring claimed it preserved the
    rule's keyword-only property — the claim is what made the gap worth closing.
    """
    return declaration_in_force(
        declaration=declaration,
        scanner_config=_config() if config is None else config,
        connected_repo=_repo() if repo is None else repo,
    )


# --- in force ---------------------------------------------------------------


def test_a_declaration_matching_all_three_live_values_is_in_force():
    assert _in_force(_declaration()) is True


# --- each field alone voids it ----------------------------------------------


def test_a_changed_target_url_voids_the_declaration():
    """The URL side. Kills a rule that ignores `declared_target_url`."""
    assert (
        _in_force(_declaration(), config=_config(zap_target_url="https://other.example.com"))
        is False
    )


def test_a_changed_repo_url_voids_the_declaration():
    """The tree side's identity. Kills a rule that ignores `declared_repo_url`.

    This is the half a declaration living on `ScannerConfig` could not have seen —
    ADR-0028 decision 1's argument, arriving as a test.
    """
    assert _in_force(_declaration(), repo=_repo(url="https://github.com/example/other")) is False


def test_a_changed_default_branch_voids_the_declaration():
    """The tree side's branch. Kills a rule that ignores `declared_default_branch`.

    A branch rename is the cheapest real way to reach this: the repository is the same
    one and only the name the declaration recorded has moved.
    """
    assert _in_force(_declaration(), repo=_repo(default_branch="develop")) is False


# --- verbatim, not normalized -----------------------------------------------

# Every field against BOTH normalization shapes, rather than one shape each. One shape
# per field leaves single-field normalizations alive: measured, `str.lower` on
# `declared_target_url` alone, and `str.strip` on either of the other two alone, all
# survived the earlier version of this section, which pinned target-whitespace,
# repo-case and branch-case and nothing else. A global normalizer died; a local one did
# not, and a local one is the likelier edit.
_COSMETIC_EDITS = [
    ("declared_target_url", f"{_TARGET_URL} "),
    ("declared_target_url", _TARGET_URL.upper()),
    ("declared_repo_url", f"{_REPO_URL} "),
    ("declared_repo_url", _REPO_URL.upper()),
    ("declared_default_branch", f"{_BRANCH} "),
    ("declared_default_branch", "Main"),
]


@pytest.mark.parametrize(
    ("field", "value"), _COSMETIC_EDITS, ids=[f"{f}:{v!r}" for f, v in _COSMETIC_EDITS]
)
def test_a_declared_value_differing_only_cosmetically_voids_the_declaration(field, value):
    """ADR-0024 decision 3's non-normalization, copied by ADR-0028 decision 2 with its
    residue: a cosmetic edit voids the declaration and the owner re-declares.

    Whitespace and case, on each of the three fields, so a `strip` or a `lower` added to
    any single comparison is caught rather than only a normalizer added to all three.
    """
    assert _in_force(_declaration(**{field: value})) is False


# --- absence ----------------------------------------------------------------


def test_no_declaration_is_not_in_force():
    """ "Never declared" is the ordinary case and is not an error. Kills a rule that
    returns True when no row exists — the mutation that would make every project look
    declared. ADR-0028 **decision 2** is what this rests on — *"in force iff a row exists
    for the project and all three stored values equal their live counterparts"* — and not
    decision 5, which is about what a green M5.5 does not prove."""
    assert _in_force(None) is False


def test_no_scanner_config_is_not_in_force():
    """Nothing to compare the URL side against, so the claim cannot be current."""
    assert (
        declaration_in_force(
            declaration=_declaration(), scanner_config=None, connected_repo=_repo()
        )
        is False
    )


def test_no_connected_repo_is_not_in_force():
    """Nothing to compare the tree side against."""
    assert (
        declaration_in_force(
            declaration=_declaration(), scanner_config=_config(), connected_repo=None
        )
        is False
    )


def test_a_cleared_target_url_voids_the_declaration():
    """`zap_target_url` is `str | None` and `declared_target_url` is `str`, so clearing
    the target voids the declaration through the ordinary comparison rather than through
    a branch of its own. Asserted because "falls out of the types" is exactly the kind of
    claim that stops being true when somebody makes a field optional."""
    assert _in_force(_declaration(), config=_config(zap_target_url=None)) is False


# --- operand order, per G8 --------------------------------------------------


def test_a_declaration_whose_three_values_are_shuffled_between_fields_is_not_in_force():
    """The operand-order case. Each declared field holds another field's live value, so
    the multiset of stored strings is exactly right and every pairing is wrong.

    **What answers True here is one specific rotation, not any mis-pairing** — measured,
    because the general claim is the one worth not making. The shuffle is built against
    `declared_target_url`↔`repo.url`, `declared_repo_url`↔`repo.default_branch`,
    `declared_default_branch`↔`zap_target_url`, and only that rotation answers True on
    these inputs. Other mis-pairings, including a single swapped pair, answer False here
    and are not killed by this case.

    **And it is not the only assertion that kills even that one.** Because the three live
    values are pairwise distinct, every pure mis-pairing also turns
    `test_a_declaration_matching_all_three_live_values_is_in_force` red. So this case is
    kept for what it states rather than for unique coverage: it fails for the reason it is
    named for, where the baseline fails for a different one.
    """
    assert (
        _in_force(
            _declaration(
                declared_target_url=_REPO_URL,
                declared_repo_url=_BRANCH,
                declared_default_branch=_TARGET_URL,
            )
        )
        is False
    )
