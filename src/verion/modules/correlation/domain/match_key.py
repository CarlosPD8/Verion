from dataclasses import dataclass

from verion.shared_kernel.confidence import Confidence

# The key's fields, partitioned by what each one is FOR. `dataclasses.fields`
# already gives the declared set; these two say which half each member is in, and
# the conformance test asserts the partition is TOTAL and DISJOINT — so a field
# added to the key cannot arrive without somebody deciding whether it scopes the
# match or supplies a signal. Same shape as ADR-0020 decision 4's refresh set:
# derive the expectation from the declaration rather than retyping it.
SCOPE_FIELDS = ("project_id",)
SIGNAL_FIELDS = ("package", "url")


@dataclass(frozen=True)
class MatchKey:
    """What `correlation` matches on — its own type, deliberately not a mirror of `Finding`.

    ADR-0023's Decision, and the reason this type exists at all: `correlation/domain/`
    may not name `Finding`, because `cross-module-correlation` forbids
    `normalization.domain`. A key correlation owns has neither that problem nor the
    one an anti-corruption mirror has — the drift surface is three fields rather than
    a twelve-field entity two of whose fields are structures with their own.

    **Three fields, frozen in ADR-0023's 2026-08-26 amendment section 3, before any
    matching code existed.** That ordering was the point: a field list chosen by
    whoever also writes the matcher is a field list chosen by whatever makes its own
    tests pass. Every exclusion carries its own ground there — `source`, `file_path`,
    `cwe`, `rule_id`, `severity` and the rest — and they are not restated here, because
    a second copy is free to drift from the first.

    **The annotations replicate their sources field-for-field, WITHOUT NARROWING**, which
    is section (b)'s constraint on whoever writes this type: `project_id` from `Finding`,
    `package` and `url` from `Location`. A key declaring `str` where the source has
    `str | None` would move the meeting point without moving the green build — the
    construction site would silently stop being a total check and become a partial one,
    with nothing saying so. `tests/unit/test_match_key.py` pins the equivalence by
    deriving it from both source declarations rather than from a hand-written list.

    Note the absence of `from __future__ import annotations` in this module, which is
    load-bearing rather than incidental: the conformance test compares this class's
    annotations against `Finding`'s and `Location`'s, and neither of those modules uses
    it either. A postponed annotation on one side of that comparison and a real type on
    the other compares a string against a class and passes nothing.

    `project_id` is scope rather than signal — it is what keeps a match inside one
    project, the same boundary `merge_observation` and `collapse_by_identity` enforce
    one module over. It is never on its own a reason for two findings to correlate; see
    `has_signal`.
    """

    project_id: str
    package: str | None
    url: str | None

    @property
    def has_signal(self) -> bool:
        """Whether this key carries anything that could make it match another finding.

        `project_id` does not count: every finding in a project shares it, so a key
        carrying only scope says nothing about what the finding is. Matching two such
        absences would fabricate an event, which ADR-0019 decision 3 already legislated
        against — prefer the failure that under-counts over the failure that fabricates.

        **The ground for this exception is STRUCTURAL, not measured.** All eight
        `Location` fields are nullable and nothing prevents a future mapper from leaving
        them so. It is explicitly *not* measured: no finding in the committed corpus has
        an all-`None` `Location`. What the corpus does produce is the exclusion's real
        cost — every Semgrep finding carries `package` `None` and `url` `None`, because
        the only location fields `mappers/semgrep.py` populates are `file_path`,
        `start_line` and `end_line`, and the key carries none of the three. M5.6 is the
        named exit, and since its commit 3 it is taken in code: `build_match_key` gives
        such a finding a derived `url` when the project's declaration is in force and
        exactly one route serves its line. Production's route map stays empty until
        commit 4, so every production Semgrep finding is still a singleton until then.
        """
        return self.package is not None or self.url is not None


@dataclass(frozen=True)
class MatchKeyResult:
    """A key and **where its signal came from**. `build_match_key`'s return type. M8.5.

    **This type exists to close G53**, and the entry named the shape before it was built:
    what would close it is *"a provenance-aware check at the construction site — a second
    parameter naming where `url` came from, or a distinct type for a derived path"*. This is
    the second of those.

    **Why the provenance rides the RETURN rather than a field on `MatchGroup`.** The group is
    downstream of the builder, so filling a field there means some caller re-deriving *"was
    this url derived?"* by comparing the key against the finding — a second copy of the
    builder's branch rule, `mypy`-invisible, and exactly the defect this closes. Returning it
    makes the site total again: ADR-0023 section (b) calls `build_match_key` *"the single
    place `mypy` compares correlation's description of `Finding` against the real one"*, and
    until M8.5 the `url` field's **meaning** could change under an unchanged `str | None`
    annotation — section (c)'s *"semantic changes behind an unchanged signature"*, entered
    deliberately by ADR-0029 decision 4 and registered as G53.

    **No fourth `MatchKey` field**, which is why this is a separate type rather than a wider
    key. ADR-0029 decision 4 priced that and rejected it as the most expensive of three
    shapes: inert under whole-dataclass equality, unable to satisfy `test_match_key.py`'s
    `_FIELD_SOURCES` (which needs a declaring type per field, and no `Finding` or `Location`
    field a derived route comes off exists), and breaking the partition test and
    `_group_order`. The key's frozen field list, `has_signal` and the conformance test are
    all untouched by this type.

    **The confidence is `shared_kernel`'s**, not correlation's, so `risk_engine` can compare
    it without naming anything here (ADR-0037 decision 3).
    """

    key: MatchKey
    confidence: Confidence
