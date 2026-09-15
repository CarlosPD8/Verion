"""Verifies that documentation claims still match the artifacts that make them true.

Every check here exists because the claim it checks was observed to be false in
this repo, survived multiple milestones, and was found by a manual review rather
than by anything mechanical. CLAUDE.md already carries a "fix the doc in the same
PR that changed reality" rule; it only ever fired when someone remembered it.

The governing principle, borrowed from .claude/agents/architecture-guardian.md's
own instruction about import-linter: re-derive the fact from the artifact, never
from a second copy of the description.

ADR *text* is deliberately out of scope. ADRs are point-in-time records, and
they are *supposed* to name rejected tooling — ADR-007 discusses dependency-cruiser
as a rejected alternative, ADR-015 quotes the old "Protocol / ABCs" wording as the
thing it corrected. Flagging those would make this checker wrong, and a checker
that cries wolf gets disabled. `check_adrs_are_indexed` reads `docs/adr/` for its
file NAMES and its README index only, never an ADR's body, so that exclusion holds.

Run: `uv run python scripts/check_claims.py`
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Docs that describe the CURRENT state of the project. docs/adr/ is excluded on
# purpose — see the module docstring.
LIVE_DOCS: tuple[str, ...] = (
    "CLAUDE.md",
    "docs/ARCHITECTURE.md",
    "docs/ROADMAP.md",
    "docs/PRODUCT_SPEC.md",
    ".claude/agents/architecture-guardian.md",
)

# Tooling this project considered and does not use. Naming one of these in a live
# doc states that the project has something it doesn't.
#   dependency-cruiser — rejected in ADR-007 (Node toolchain in a pure-Python repo)
#   ABCs               — zero exist in src/; all ports are typing.Protocol
RETIRED_TOOLS: dict[str, str] = {
    "dependency-cruiser": "rejected in ADR-007, never used",
    "ABCs": "zero ABCs in src/ — every port is a typing.Protocol",
}

CI_WORKFLOW = ".github/workflows/ci.yml"
GUARDIAN = ".claude/agents/architecture-guardian.md"
ROADMAP = "docs/ROADMAP.md"
ARCHITECTURE = "docs/ARCHITECTURE.md"
ADR_DIR = "docs/adr"
ADR_INDEX = "docs/adr/README.md"

# An issue id as ROADMAP.md writes one in a heading: `M5.6`, `M10.2`.
ISSUE_ID = r"M\d+\.\d+"

# Confirmations after which a deferred gap must be assigned or explicitly
# justified. Three, because three is where G1 broke: M3.4 and M3.5 were
# reasonable deferrals, and by M3.6 the repetition was information nobody acted on.
ESCALATION_THRESHOLD = 3


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _findings_to_lines(findings: list[tuple[str, int, str]]) -> list[str]:
    return [f"{path}:{line}: {message}" for path, line, message in findings]


def _h2_section(
    lines: list[str], is_heading: Callable[[str], bool]
) -> tuple[int, list[str]] | None:
    """The first `## ` section whose heading satisfies `is_heading`, heading line included.

    Returns (index of the heading, the section's lines). The section ends at the next `## `
    heading or at end of file; a `### ` subheading does not end it.
    """
    for index, line in enumerate(lines):
        if line.startswith("## ") and is_heading(line):
            end = next(
                (later for later in range(index + 1, len(lines)) if lines[later].startswith("## ")),
                len(lines),
            )
            return index, lines[index:end]
    return None


def _ci_run_commands() -> set[str]:
    """Every `uv run <cmd>` step in the CI workflow, normalised to <cmd>.

    Read out of ci.yml itself rather than kept as a list here — a hardcoded copy
    would be one more description to drift.
    """
    commands: set[str] = set()
    for raw in _read(CI_WORKFLOW).splitlines():
        match = re.search(r"run:\s*(uv run .+?)\s*$", raw)
        if match:
            command = match.group(1).removeprefix("uv run ").strip()
            # Trailing path argument ("ruff check .") is noise for this comparison.
            commands.add(command.removesuffix(" .").strip())
    return commands


def _tier1_table_commands() -> tuple[set[str], set[str], int]:
    """Backticked commands in CLAUDE.md's Tier 1 table.

    Returns (all commands, those written with an explicit `uv run` prefix, the
    line the table starts on).
    """
    lines = _read("CLAUDE.md").splitlines()
    start = end = None
    for index, line in enumerate(lines):
        if line.startswith("### Tier 1"):
            start = index
        elif start is not None and line.startswith("### Tier 2"):
            end = index
            break
    if start is None or end is None:
        raise LookupError(
            "CLAUDE.md has no '### Tier 1' / '### Tier 2' pair — the enforcement "
            "section this check reads was renamed or removed"
        )

    every: set[str] = set()
    prefixed: set[str] = set()
    for line in lines[start:end]:
        if not line.lstrip().startswith("|"):
            continue
        # First cell only: later cells are prose that also contains backticks.
        first_cell = line.split("|")[1] if line.count("|") >= 2 else ""
        for token in re.findall(r"`([^`]+)`", first_cell):
            if token.startswith("uv run "):
                prefixed.add(token.removeprefix("uv run ").strip())
                every.add(token.removeprefix("uv run ").strip())
            else:
                every.add(token.strip())
    return every, prefixed, start + 1


def check_ci_steps_match_tier1_table(findings: list[tuple[str, int, str]]) -> None:
    """CLAUDE.md's Tier 1 table and ci.yml must describe the same set of gates.

    Bidirectional on purpose. The forward direction catches a documented gate that
    does not exist (CLAUDE.md:38's "enforced by CI" overclaim, ARCHITECTURE.md's
    "type-checked against them" before mypy existed). The reverse catches a gate
    that exists but is undocumented — which is how mypy would have been noticed as
    missing from the table rather than only after someone thought to add it.
    """
    ci_commands = _ci_run_commands()
    table_commands, table_prefixed, table_line = _tier1_table_commands()

    for command in sorted(ci_commands - table_commands):
        findings.append(
            (
                "CLAUDE.md",
                table_line,
                f"CI runs `uv run {command}` but the Tier 1 table does not list it — "
                f"a gate exists that the docs do not claim",
            )
        )

    for command in sorted(table_prefixed - ci_commands):
        findings.append(
            (
                "CLAUDE.md",
                table_line,
                f"Tier 1 table claims `uv run {command}` but {CI_WORKFLOW} has no "
                f"such step — a documented gate that does not run",
            )
        )


def check_retired_tools_are_not_named(findings: list[tuple[str, int, str]]) -> None:
    """No live doc may name tooling this project decided against or never used."""
    for doc in LIVE_DOCS:
        for line_number, line in enumerate(_read(doc).splitlines(), start=1):
            for tool, reason in RETIRED_TOOLS.items():
                if tool in line:
                    findings.append((doc, line_number, f"names '{tool}' as if in use — {reason}"))


def check_rule_count_is_in_sync(findings: list[tuple[str, int, str]]) -> None:
    """architecture-guardian's stated rule count must match CLAUDE.md's actual count.

    A number duplicated into a second file, with nothing keeping them equal. It was
    already wrong (14 vs 15) when this check was written.
    """
    actual = len(re.findall(r"^\d+\. ", _read("CLAUDE.md"), flags=re.MULTILINE))

    for line_number, line in enumerate(_read(GUARDIAN).splitlines(), start=1):
        match = re.search(r"currently (\d+)", line)
        if match:
            claimed = int(match.group(1))
            if claimed != actual:
                findings.append(
                    (
                        GUARDIAN,
                        line_number,
                        f"claims CLAUDE.md has {claimed} numbered rules; it has {actual}",
                    )
                )
            return

    findings.append(
        (GUARDIAN, 1, "no 'currently <N>' rule count found — this check can no longer verify it")
    )


def check_deferred_gaps_are_escalated(findings: list[tuple[str, int, str]]) -> None:
    """A gap re-confirmed three or more times must be assigned or justified.

    Noting a gap does not scale on its own: multi-scanner orchestration (G1) was
    correctly flagged and correctly deferred three times and still became a
    critical-path blocker for M4/M5 unnoticed. Three is the threshold because
    three is where that one broke — the first two deferrals were reasonable, the
    third was repetition nobody acted on.
    """
    lines = _read(ROADMAP).splitlines()

    section_start = None
    for index, line in enumerate(lines):
        if line.startswith("## Deferred gaps"):
            section_start = index
        elif section_start is not None and line.startswith("## "):
            lines = lines[section_start:index]
            break
    else:
        if section_start is None:
            findings.append(
                (ROADMAP, 1, "no '## Deferred gaps' section — the register was removed")
            )
            return
        lines = lines[section_start:]

    entries: list[tuple[int, str, list[str]]] = []
    for offset, line in enumerate(lines):
        if line.startswith("### "):
            entries.append((section_start + offset + 1, line.removeprefix("### ").strip(), []))
        elif entries:
            entries[-1][2].append(line)

    for line_number, title, body in entries:
        text = "\n".join(body)
        confirmed = re.search(r"^Confirmed:\s*(.+?)(?:·|$)", text, flags=re.MULTILINE)
        if not confirmed:
            findings.append((ROADMAP, line_number, f"gap '{title}' has no 'Confirmed:' field"))
            continue

        count = len([m for m in confirmed.group(1).split(",") if m.strip()])
        if count < ESCALATION_THRESHOLD:
            continue

        assigned = re.search(r"Status:\s*(assigned|resolved)\s*→", text)
        justified = re.search(r"^Deferral rationale:\s*\S", text, flags=re.MULTILINE)
        if not assigned and not justified:
            findings.append(
                (
                    ROADMAP,
                    line_number,
                    f"gap '{title}' has been confirmed {count} times "
                    f"(threshold {ESCALATION_THRESHOLD}) but carries neither "
                    f"'Status: assigned → <issue>' nor 'Deferral rationale:' — "
                    f"re-noting it again is not a decision",
                )
            )


def check_adrs_are_indexed(findings: list[tuple[str, int, str]]) -> None:
    """Every `docs/adr/0*.md` has a row in the ADR index and an entry in ARCHITECTURE's summary.

    **The index row is keyed on the link target, not the number.** A row counts when the
    first cell of a table row links to the file's exact name, so a row left pointing at an
    ADR's old slug after a rename fails too, since that is the link a reader follows.

    **The summary entry is keyed on a bullet that STARTS with the ADR, not on a mention.**
    At introduction 13 of the 28 ADRs were also cited inside another ADR's summary bullet,
    e.g. ADR-0022 inside ADR-0025's. A mention-keyed check would have stayed green after
    deleting any of those 13 entries. Only a column-0 `- **ADR-<n>` line counts, so an
    indented sub-bullet does not.

    **Both citation spellings are accepted**, as the number after `ADR-` read as an integer.
    The tree writes the same ADR both ways: 15 summary bullets use three digits (ADR-001 to
    ADR-016) and 13 use four (ADR-0017 onwards). A check keyed on one form would fail for the
    wrong reason on over half the corpus.

    The section is found by its title, "Architecture Decision Records", rather than by its
    number, and it ends at the next `## ` heading.
    """
    adr_files = sorted(path.name for path in (ROOT / ADR_DIR).glob("0*.md"))

    index_lines = _read(ADR_INDEX).splitlines()
    index_line = next(
        (number for number, line in enumerate(index_lines, start=1) if line.startswith("|")), 1
    )
    linked: set[str] = set()
    for line in index_lines:
        if not line.lstrip().startswith("|"):
            continue
        # First cell only, as in the Tier 1 table: a later cell's prose may link elsewhere.
        first_cell = line.split("|")[1] if line.count("|") >= 2 else ""
        linked.update(re.findall(r"\]\(([^)\s]+)\)", first_cell))

    summary = _h2_section(
        _read(ARCHITECTURE).splitlines(), lambda heading: "Architecture Decision Records" in heading
    )
    if summary is None:
        findings.append(
            (
                ARCHITECTURE,
                1,
                "no '## … Architecture Decision Records' section, so no ADR's summary "
                "entry can be verified",
            )
        )
    summary_start, summary_lines = summary if summary is not None else (0, [])
    summarized = {
        int(match.group(1))
        for line in summary_lines
        if (match := re.match(r"- \*\*ADR-(\d+)\b", line))
    }

    for name in adr_files:
        if name not in linked:
            findings.append(
                (
                    ADR_INDEX,
                    index_line,
                    f"{name} has no row in the ADR index; no table row's first cell links to it",
                )
            )
        number_match = re.match(r"\d+", name)
        if summary is not None and (
            number_match is None or int(number_match.group()) not in summarized
        ):
            findings.append(
                (
                    ARCHITECTURE,
                    summary_start + 1,
                    f"{name} has no entry in the ADR summary; no bullet in that section "
                    f"starts with its ADR number (either spelling), and a citation inside "
                    f"another ADR's entry does not count",
                )
            )


def check_assignments_name_real_issues(findings: list[tuple[str, int, str]]) -> None:
    """Every deferred gap assigned to an issue names an issue that exists in ROADMAP.md.

    An issue exists when it is a heading, `- **M<n>.<n> — <title>**`, at column 0 inside a
    `## Milestone ` section. An id that appears only in prose, or in a bullet inside the
    register itself, does not count.

    Only the register's `Confirmed:` field lines are read, and only a `Status:` value that
    begins with the assignment keyword. A resolved entry's parenthetical about what it
    was once assigned to is history, not a claim, and neither is a `Note:` quoting a field.

    **Leading bold, code and italic markers are tolerated.** The `*`, backtick and `_`
    characters are stripped from the start of the value before it is read. At introduction
    G19's value was written `**assigned → M5.3**`, a form `check_deferred_gaps_are_escalated`'s
    regex cannot read (see G28's 2026-08-25 note), and this register backticks field values
    routinely. **A value that then begins with "assign", in any case, but does not parse as
    `assigned → M<n>.<n>` is REPORTED, not skipped.** That is exactly the input a silent check
    would pass, and it is the class that note measured in the escalation guard. A trailing
    qualifier (`commit 4`) or a full stop after the id is accepted.

    An assignment that does NOT start the value is not read: `open — assigned → …`,
    `re-assigned → …`. Matching "assign" anywhere would misfire on G6's value, which at
    introduction read `open — the M5.1 assignment is discharged`.

    Scope: assignments only. A `resolved →` target is not checked.
    """
    lines = _read(ROADMAP).splitlines()

    issues: set[str] = set()
    in_milestone = False
    for line in lines:
        if line.startswith("## "):
            in_milestone = line.startswith("## Milestone ")
        elif in_milestone and (match := re.match(rf"- \*\*({ISSUE_ID}) — ", line)):
            issues.add(match.group(1))

    register = _h2_section(lines, lambda heading: heading.startswith("## Deferred gaps"))
    if register is None:
        findings.append(
            (ROADMAP, 1, "no '## Deferred gaps' section, so no assignment can be verified")
        )
        return
    register_start, register_lines = register

    title = "<before any entry>"
    for offset, line in enumerate(register_lines):
        if line.startswith("### "):
            title = line.removeprefix("### ").strip()
            continue
        if not line.startswith("Confirmed:") or "Status:" not in line:
            continue
        value = line.split("Status:", 1)[1].strip().lstrip("*`_ ")
        if not value.lower().startswith("assign"):
            continue

        line_number = register_start + offset + 1
        match = re.match(rf"assigned\s*→\s*({ISSUE_ID})(?!\.?\d)", value)
        if match is None:
            findings.append(
                (
                    ROADMAP,
                    line_number,
                    f"gap '{title}' claims an assignment in a form this check cannot read; "
                    f"write it as 'assigned → M<n>.<n>'",
                )
            )
        elif match.group(1) not in issues:
            findings.append(
                (
                    ROADMAP,
                    line_number,
                    f"gap '{title}' is assigned to {match.group(1)}, which is not an issue "
                    f"heading in any milestone, so the assignment points at nothing",
                )
            )


def report_type_suppressions() -> list[str]:
    """Reports, and deliberately does not block on, type/lint suppressions.

    This is the one metric that detects the mypy gate being *bypassed* rather
    than satisfied — a mechanical check degrading into theatre while still
    reporting green. Baseline at introduction: zero, which makes any increase a
    visible, arguable event rather than a number lost in noise.

    Non-blocking on purpose. A hard zero would push people toward
    pyproject.toml's `disable_error_code` / `ignore_missing_imports` / per-module
    `overrides`, which are strictly worse: they suppress silently and are
    invisible at the call site. Those are counted here too, so the quieter
    escape route is watched as closely as the loud one.
    """
    inline: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "# type: ignore" in line or "# noqa" in line:
                relative = path.relative_to(ROOT).as_posix()
                inline.append(f"{relative}:{number}")

    config = [
        f"pyproject.toml:{number}"
        for number, line in enumerate(_read("pyproject.toml").splitlines(), start=1)
        if re.search(
            r"disable_error_code|ignore_missing_imports|\[\[tool\.mypy\.overrides\]\]", line
        )
    ]

    lines = [f"suppressions: {len(inline)} inline in src/, {len(config)} mypy escape(s) in config"]
    if inline or config:
        lines.append("  (baseline was 0/0 — each of these should carry a one-line reason)")
        lines.extend(f"  {location}" for location in inline + config)
    return lines


CHECKS = (
    check_ci_steps_match_tier1_table,
    check_retired_tools_are_not_named,
    check_rule_count_is_in_sync,
    check_deferred_gaps_are_escalated,
    check_adrs_are_indexed,
    check_assignments_name_real_issues,
)


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    for check in CHECKS:
        check(findings)

    # Printed on every run, pass or fail — a metric nobody sees is not tracked.
    for line in report_type_suppressions():
        print(f"check_claims: {line}" if not line.startswith(" ") else line)

    if not findings:
        print(f"check_claims: {len(CHECKS)} checks passed.")
        return 0

    print("\ncheck_claims: documentation no longer matches the artifacts it describes.\n")
    for line in _findings_to_lines(sorted(findings)):
        print(f"  {line}")
    print(
        f"\n{len(findings)} claim(s) out of date. Fix the doc, or fix the thing it "
        f"describes — whichever is actually wrong."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
