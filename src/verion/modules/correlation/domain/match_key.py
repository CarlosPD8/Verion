from dataclasses import dataclass

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
        named exit.
        """
        return self.package is not None or self.url is not None
