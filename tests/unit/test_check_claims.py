"""`check_claims.py`'s ADR-index, assignment-target and fired-trigger checks, on synthetic corpora.

These are the first tests the script has had. Its four earlier checks are verified only by
running against the live corpus, and there a check that works and a check that cannot fire
both print "checks passed". Both checks here found zero violations on their first run over
the real tree, which is exactly the case where the two cannot be told apart. So each one is
pointed at a small corpus built to make it fire.

`scripts/` is not a package and not on `sys.path`, so the module is loaded from its file.
Every check reads through the module-level `ROOT`, looked up at call time, so a test
redirects it with `monkeypatch` without changing any path handling in the script.
"""

import importlib.util
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_claims.py"

Findings = list[tuple[str, int, str]]
Write = Callable[[str, str], None]


def _load_check_claims() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_claims", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_claims = _load_check_claims()


@pytest.fixture
def write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Write:
    """Points the script's `ROOT` at an empty tree and returns a writer for files in it."""
    monkeypatch.setattr(check_claims, "ROOT", tmp_path)

    def _write(relative: str, text: str) -> None:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    return _write


def _run(check: Callable[[Findings], None]) -> Findings:
    findings: Findings = []
    check(findings)
    return findings


# --- check_adrs_are_indexed --------------------------------------------------------------


def _adr_corpus(
    write: Write,
    *,
    files: list[str],
    index_rows: list[str],
    summary: str,
    after_summary: str = "",
) -> None:
    for name in files:
        write(f"docs/adr/{name}", "# An ADR\n")
    rows = "".join(f"| {row} | A title | Accepted |\n" for row in index_rows)
    write("docs/adr/README.md", f"# ADRs\n\n| ADR | Title | Status |\n|---|---|---|\n{rows}")
    write(
        "docs/ARCHITECTURE.md",
        "## 11. Deployment View\n\n"
        "## 12. Architecture Decision Records (summary)\n\n"
        f"{summary}\n"
        "## 13. Next Steps\n\n"
        f"{after_summary}",
    )


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("ADR-009", "ADR-023"),  # three digits, the form ADR-001 to ADR-016 use
        ("ADR-0009", "ADR-0023"),  # four digits, the form ADR-0017 onwards use
    ],
)
def test_a_summary_entry_under_either_spelling_satisfies_the_check(
    write: Write, low: str, high: str
) -> None:
    _adr_corpus(
        write,
        files=["0009-verify.md", "0023-key.md"],
        index_rows=["[0009](0009-verify.md)", "[0023](0023-key.md)"],
        summary=f"- **{low} — Verify.** Text.\n- **{high} — Key.** Text.\n",
    )

    assert _run(check_claims.check_adrs_are_indexed) == []


@pytest.mark.parametrize("present", ["ADR-009", "ADR-0009"])
def test_a_missing_summary_entry_is_named_whichever_spelling_its_neighbour_uses(
    write: Write, present: str
) -> None:
    _adr_corpus(
        write,
        files=["0009-verify.md", "0023-key.md"],
        index_rows=["[0009](0009-verify.md)", "[0023](0023-key.md)"],
        summary=f"- **{present} — Verify.** Text.\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert len(findings) == 1
    path, line, message = findings[0]
    assert (path, line) == ("docs/ARCHITECTURE.md", 3)
    assert "0023-key.md has no entry in the ADR summary" in message


def test_a_missing_index_row_is_named(write: Write) -> None:
    _adr_corpus(
        write,
        files=["0009-verify.md", "0023-key.md"],
        index_rows=["[0009](0009-verify.md)"],
        summary="- **ADR-009 — Verify.**\n- **ADR-0023 — Key.**\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert len(findings) == 1
    assert findings[0][0] == "docs/adr/README.md"
    assert "0023-key.md has no row in the ADR index" in findings[0][2]


@pytest.mark.parametrize(
    "row",
    [
        "[0023](0023-old-slug.md)",  # the file was renamed and the row was not
        "0023",  # numbered, but the first cell links to nothing
    ],
)
def test_an_index_row_counts_only_if_its_first_cell_links_the_exact_file(
    write: Write, row: str
) -> None:
    _adr_corpus(
        write,
        files=["0023-key.md"],
        index_rows=[row],
        summary="- **ADR-0023 — Key.**\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert [message for _, _, message in findings] == [
        "0023-key.md has no row in the ADR index; no table row's first cell links to it"
    ]


def test_an_index_link_in_a_later_cell_is_not_a_row_for_that_adr(write: Write) -> None:
    _adr_corpus(write, files=["0022-read.md", "0025-risk.md"], index_rows=[], summary="")
    write(
        "docs/adr/README.md",
        "| ADR | Title | Status |\n|---|---|---|\n"
        "| [0025](0025-risk.md) | Builds on [0022](0022-read.md) | Accepted |\n",
    )
    write(
        "docs/ARCHITECTURE.md",
        "## 12. Architecture Decision Records (summary)\n\n"
        "- **ADR-0022 — Read.**\n- **ADR-0025 — Risk.**\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert [message.split(" has ")[0] for _, _, message in findings] == ["0022-read.md"]


def test_a_citation_inside_another_adrs_entry_is_not_an_entry(write: Write) -> None:
    """The live shape: ADR-0022 is cited in ADR-0025's summary bullet."""
    _adr_corpus(
        write,
        files=["0022-read.md", "0025-risk.md"],
        index_rows=["[0022](0022-read.md)", "[0025](0025-risk.md)"],
        summary="- **ADR-0025 — Risk.** Carried in ADR-0022 decision 3's envelope.\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert len(findings) == 1
    assert findings[0][2].startswith("0022-read.md has no entry in the ADR summary")


def test_an_indented_bullet_is_not_an_entry(write: Write) -> None:
    _adr_corpus(
        write,
        files=["0022-read.md", "0025-risk.md"],
        index_rows=["[0022](0022-read.md)", "[0025](0025-risk.md)"],
        summary="- **ADR-0025 — Risk.**\n  - **ADR-0022 — Read.** A sub-bullet.\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert [message.split(" has ")[0] for _, _, message in findings] == ["0022-read.md"]


def test_an_entry_after_the_section_ends_does_not_count(write: Write) -> None:
    _adr_corpus(
        write,
        files=["0009-verify.md", "0023-key.md"],
        index_rows=["[0009](0009-verify.md)", "[0023](0023-key.md)"],
        summary="- **ADR-009 — Verify.**\n",
        after_summary="- **ADR-0023 — Key.** Under the next section's heading.\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert [message.split(" has ")[0] for _, _, message in findings] == ["0023-key.md"]


def test_a_shorter_number_does_not_satisfy_a_longer_one(write: Write) -> None:
    """ADR-001 is ADR 1. It must not also answer for ADR 10."""
    _adr_corpus(
        write,
        files=["0001-monolith.md", "0010-indirect.md"],
        index_rows=["[0001](0001-monolith.md)", "[0010](0010-indirect.md)"],
        summary="- **ADR-001 — Monolith.**\n",
    )

    findings = _run(check_claims.check_adrs_are_indexed)

    assert [message.split(" has ")[0] for _, _, message in findings] == ["0010-indirect.md"]


def test_a_missing_summary_section_is_reported_rather_than_passing(write: Write) -> None:
    _adr_corpus(
        write,
        files=["0009-verify.md"],
        index_rows=["[0009](0009-verify.md)"],
        summary="",
    )
    write("docs/ARCHITECTURE.md", "## 12. Decisions\n\n- **ADR-009 — Verify.**\n")

    findings = _run(check_claims.check_adrs_are_indexed)

    assert len(findings) == 1
    assert "Architecture Decision Records' section" in findings[0][2]


# --- check_assignments_name_real_issues --------------------------------------------------

_MILESTONE = (
    "## Milestone 5 — Correlation Engine (Weeks 7-9)\n\n"
    "- **M5.1 — Correlation strategy design**\n"
    "  Module: `correlation`\n\n"
    "- **M5.3 — Correlation accuracy test suite**\n"
    "  Module: `correlation`\n\n"
)


def _roadmap(write: Write, register: str, *, milestones: str = _MILESTONE) -> None:
    write(
        "docs/ROADMAP.md",
        "# Roadmap\n\n"
        f"{milestones}"
        "## Milestone-boundary review\n\n"
        "## Deferred gaps\n\n"
        "Rules: at three confirmations an entry needs an assignment.\n\n"
        f"{register}\n"
        "## V2 Backlog\n",
    )


def _entry(number: int, status: str) -> str:
    return f"### G{number} — A gap\nConfirmed: M4.5 · Status: {status}\nBlocks-if-unresolved: x\n"


@pytest.mark.parametrize(
    "status",
    [
        "assigned → M5.3",
        "**assigned → M5.3**",  # G19's form at introduction
        "`assigned → M5.3`",
        "_assigned → M5.3_",
        "assigned → M5.3 commit 2",  # a qualifier after the id
        "assigned → M5.3.",  # a full stop is not part of the id
    ],
)
def test_an_assignment_to_a_real_issue_passes(write: Write, status: str) -> None:
    _roadmap(write, _entry(19, status))

    assert _run(check_claims.check_assignments_name_real_issues) == []


@pytest.mark.parametrize(
    "status",
    [
        "assigned → M5.9",
        "**assigned → M5.9**",
        # Both passed silently before the guardian's pass: only `*` was stripped, so the
        # value did not begin with "assign" and was never read.
        "`assigned → M5.9`",
        "_assigned → M5.9_",
    ],
)
def test_an_assignment_to_a_missing_issue_is_named_whatever_wraps_it(
    write: Write, status: str
) -> None:
    _roadmap(write, _entry(17, "open") + "\n" + _entry(19, status))

    findings = _run(check_claims.check_assignments_name_real_issues)

    assert len(findings) == 1
    path, line, message = findings[0]
    assert path == "docs/ROADMAP.md"
    lines = (check_claims.ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8").splitlines()
    assert lines[line - 1] == f"Confirmed: M4.5 · Status: {status}"
    assert message.startswith("gap 'G19 — A gap' is assigned to M5.9, which is not an issue")


def test_a_longer_id_sharing_a_prefix_is_not_that_issue(write: Write) -> None:
    """M5.10 is not M5.1."""
    _roadmap(write, _entry(19, "assigned → M5.10"))

    findings = _run(check_claims.check_assignments_name_real_issues)

    assert len(findings) == 1
    assert "is assigned to M5.10," in findings[0][2]


def test_an_id_that_is_a_heading_only_outside_a_milestone_does_not_exist(write: Write) -> None:
    register = "- **M9.9 — A bullet inside the register, not an issue**\n\n" + _entry(
        19, "assigned → M9.9"
    )
    _roadmap(write, register)

    findings = _run(check_claims.check_assignments_name_real_issues)

    assert len(findings) == 1
    assert "is assigned to M9.9," in findings[0][2]


@pytest.mark.parametrize(
    "status",
    [
        "open",
        "resolved → M9.9",
        "**resolved → M9.9**",
        "resolved → M5.3 *(was `assigned → M9.9 commit 4`)*",  # G27's shape at introduction
        "**open — the M9.9 assignment is discharged, the gap is not**",  # G6's, likewise
    ],
)
def test_a_status_that_is_not_an_assignment_is_not_read(write: Write, status: str) -> None:
    _roadmap(write, _entry(27, status))

    assert _run(check_claims.check_assignments_name_real_issues) == []


def test_a_field_quoted_outside_a_confirmed_line_is_not_read(write: Write) -> None:
    register = _entry(27, "open") + "Note: this was once `Status: assigned → M9.9`.\n"
    _roadmap(write, register)

    assert _run(check_claims.check_assignments_name_real_issues) == []


@pytest.mark.parametrize(
    "status",
    [
        "**ASSIGNED (M5.3)**",
        "assigned -> M5.3",
        "assigned to M5.3",
        "assigned → M5.3.1",  # not M5.3 with something after it, and not an issue id
    ],
)
def test_an_assignment_in_an_unreadable_form_is_reported_not_skipped(
    write: Write, status: str
) -> None:
    _roadmap(write, _entry(19, status))

    findings = _run(check_claims.check_assignments_name_real_issues)

    assert len(findings) == 1
    assert "claims an assignment in a form this check cannot read" in findings[0][2]


def test_a_missing_register_is_reported_rather_than_passing(write: Write) -> None:
    write("docs/ROADMAP.md", f"# Roadmap\n\n{_MILESTONE}## V2 Backlog\n")

    findings = _run(check_claims.check_assignments_name_real_issues)

    assert len(findings) == 1
    assert "no '## Deferred gaps' section" in findings[0][2]


# --- check_fired_triggers_are_recorded ----------------------------------------------------

# M6.3 carries the `— done` marker and M7.1 does not, so one milestone has shipped and the
# other has not. Kept separate from `_MILESTONE` above, whose issues carry no marker and on
# whose absence the assignment tests depend.
_DONE_MILESTONES = (
    "## Milestone 6 — Risk / Decision Engine (Weeks 9-11)\n\n"
    "- **M6.3 — Scoring persistence + API** — done\n"
    "  Module: `risk_engine`\n\n"
    "## Milestone 7 — Security Brief (Weeks 11-12)\n\n"
    "- **M7.1 — ExplanationProviderPort + LLM adapter**\n"
    "  Module: `brief`\n\n"
)


def _gap(body: str, *, status: str = "open") -> str:
    """One register entry whose `Deferral rationale:` line carries `body`."""
    return (
        "### G64 — A gap\n"
        f"Confirmed: M6.2 · Status: {status}\n"
        "Blocks-if-unresolved: x\n"
        f"Deferral rationale: it is deferred. {body}\n"
    )


def _fired(write: Write, register: str) -> Findings:
    _roadmap(write, register, milestones=_DONE_MILESTONES)
    return _run(check_claims.check_fired_triggers_are_recorded)


def test_a_fired_trigger_with_no_history_line_is_reported(write: Write) -> None:
    findings = _fired(write, _gap("Trigger: **M6.3's ranked endpoint**."))

    assert len(findings) == 1
    path, line, message = findings[0]
    assert path == "docs/ROADMAP.md"
    lines = (check_claims.ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8").splitlines()
    assert lines[line - 1] == "### G64 — A gap"
    assert message.startswith("gap 'G64 — A gap' names M6.3 as a trigger and M6.3 is marked done")


def test_a_fired_trigger_named_in_a_history_header_passes(write: Write) -> None:
    body = "Trigger: **M6.3's ranked endpoint**.\nNote (2026-09-16, M6.3): **it fired.**"

    assert _fired(write, _gap(body)) == []


def test_an_id_in_a_history_lines_body_does_not_count_as_recorded(write: Write) -> None:
    """The mention failure that passed G33 and G61 while their own dated note was deleted."""
    body = "Trigger: **M6.3's ranked endpoint**.\nNote (2026-09-16): **the M6.3 trigger fired.**"

    findings = _fired(write, _gap(body))

    assert len(findings) == 1
    assert "no history line's header names M6.3" in findings[0][2]


def test_a_trigger_naming_an_unstarted_milestone_is_not_reported(write: Write) -> None:
    assert _fired(write, _gap("Trigger: **M7.1**, the first consumer.")) == []


def test_a_resolved_entry_is_skipped(write: Write) -> None:
    """A resolved entry's trigger is spent by definition, so it is never read."""
    assert _fired(write, _gap("Trigger: **M6.3**.", status="resolved → M6.3")) == []


def test_an_unbolded_trigger_target_is_invisible(write: Write) -> None:
    """Pins the widest documented hole, so it cannot widen or close unnoticed."""
    assert _fired(write, _gap("Trigger: M6.3's ranked endpoint.")) == []


def test_a_milestone_in_prose_after_the_trigger_is_not_a_target(write: Write) -> None:
    """G21's shape: its `Trigger:` clause ends 'Do it the way M5.0 did ruff'."""
    body = "Trigger: **the next time the file is opened**. Do it the way M6.3 did it."

    assert _fired(write, _gap(body)) == []


def test_a_colonless_re_point_inside_a_history_line_is_read(write: Write) -> None:
    """G33's shape: a trigger re-pointed inside a `Note`, with no colon before the bold.

    That line's header names M6.1, so nothing records M6.3 and the re-pointed trigger is
    the thing that must be caught.
    """
    body = (
        "Trigger: **M7.1**.\n"
        "Note (2026-09-16, M6.1): **x.** Re-entry trigger re-points to **M6.3**."
    )

    findings = _fired(write, _gap(body))

    assert len(findings) == 1
    assert "names M6.3 as a trigger" in findings[0][2]


def test_a_struck_trigger_is_still_read(write: Write) -> None:
    """A struck trigger is a SPENT one, which is the case this check exists for."""
    findings = _fired(write, _gap("Trigger: ~~**M6.3's endpoint**~~ *(fired)*."))

    assert len(findings) == 1
    assert "names M6.3 as a trigger" in findings[0][2]


@pytest.mark.parametrize(
    "prefix",
    ["Note", "Rewritten", "Resolution", "Discharge", "Assignment", "Split", "Update"],
)
def test_every_history_prefix_records_not_only_note(write: Write, prefix: str) -> None:
    """G42 recorded its fired M5.9 trigger under `Rewritten`, not under `Note`."""
    body = f"Trigger: **M6.3's endpoint**.\n{prefix} (2026-09-16, M6.3): **it fired.**"

    assert _fired(write, _gap(body)) == []


def test_an_issue_without_the_done_marker_has_not_fired(write: Write) -> None:
    milestones = _DONE_MILESTONES.replace("Scoring persistence + API** — done", "Scoring**")
    _roadmap(write, _gap("Trigger: **M6.3's endpoint**."), milestones=milestones)

    assert _run(check_claims.check_fired_triggers_are_recorded) == []
