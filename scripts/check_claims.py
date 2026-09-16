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
#   dependency-cruiser — rejected in ADR-007 (Node toolchain in a pure-Python repo;
#                        the repo stops being pure-Python when ADR-0031's frontend/
#                        is created, 2026-09-16, and the rejection stands on its
#                        other ground: no benefit over a native Python tool)
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

# A LABELLED trigger, the only form `check_fired_triggers_are_recorded` reads:
# `Trigger:`, `Re-entry trigger:`, `Trigger sharpens to:`, and — with the colon
# OPTIONAL before a bold — `Re-entry trigger re-points to **M7.1**`, which is how G33
# moves its own trigger and is therefore one of this register's established forms.
# The lookahead tolerates a leading `~~` because a STRUCK trigger is a spent one, and a
# spent trigger is the case this check exists for: G61's reads
# `Trigger: ~~**M6.3's endpoint, measured**~~`. Demanding `**` immediately after the
# colon instead would drop G61, G38, G59 and G67 ENTIRELY and in silence — measured by
# comparing both directions, because the first version of this widening was checked for
# what it gained and not for what it lost, and it lost four entries including G61.
TRIGGER_LABEL = re.compile(r"[Tt]rigger[a-z]*(?:\s+[a-z-]+){0,3}\s*:?\s*(?=[~*]*\*\*)")

# A trigger's TARGET is bolded by this register's convention. `~~**M6.3**~~` counts:
# a struck trigger is a spent one, which is the case that check exists for.
BOLD_ISSUE = re.compile(rf"\*\*~*\s*({ISSUE_ID})")

# The seven dated forms this register opens a history line with. Not `Note` alone —
# G42 recorded its fired trigger under `Rewritten (2026-09-08, M5.9 commit 1)`.
HISTORY_LINE = re.compile(r"^(?:Note|Rewritten|Resolution|Discharge|Assignment|Split|Update)\b")

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


def _history_header(line: str) -> str:
    """A history line's header: its label and parenthetical, and nothing after them.

    Ends at the earliest of the line's first bold, its first `: ` or its first spaced
    em dash. Keyed this tightly because the loose version — "everything before the first
    bold" — is the WHOLE LINE on a history line that carries no bold, and that is the
    mention-keying this module exists to avoid. Re-derived over this register: of 153
    history lines, **16 carry no bold at all, and 12 of those 16 hold an issue id in
    their prose that their header does not** — G24's and G29's identical
    `Note (2026-08-27): the assignment moved from M5.4 to M5.9 when …` would otherwise
    record both ids, having recorded neither, and G1's and G12's `Resolution:` lines
    the same. None of the 12 changes a verdict today, so the defect is latent rather
    than live, which is exactly the condition under which it would have been adopted
    and never noticed.
    """
    end = len(line)
    for marker in ("**", ": ", " — "):
        position = line.find(marker)
        if position != -1:
            end = min(end, position)
    return line[:end]


def check_fired_triggers_are_recorded(findings: list[tuple[str, int, str]]) -> None:
    """An open gap whose trigger named a milestone that has since shipped must say so.

    The class this catches: a `Trigger:` aimed at an event that has already happened.
    Such an entry surfaces to nobody — it is waiting for a thing that is behind it —
    which is G1's failure shape exactly, and it does not fail
    `check_deferred_gaps_are_escalated`, since that guard counts `Confirmed:` entries
    and a spent trigger adds none. Found by hand seven times at the M5→M6 boundary
    and twice more inside M6 (G61's trigger, spent by the commit that wrote it; G33's,
    three commits earlier), each time by reading the register against `git log` — which
    step 3 of the boundary review does not ask anyone to do.

    **Both sides are keyed on an anchor, never on a mention**, which is the lesson
    `check_adrs_are_indexed` records about the 13 ADRs a mention-keyed check would have
    made invisible. Measured over this register at introduction, a mention anchor was
    wrong in both directions:

    * **The trigger side takes a bolded id after a trigger LABEL** — `Trigger:`,
      `Re-entry trigger:`, `Trigger sharpens to:`. Keying on the bare word `trigger`
      sweeps up prose instead. **Measured under the configuration this check actually
      ships — both sides reading every line — 13 of the 52 SCANNED entries would report
      a fired trigger that is not one; the shipped anchor reports none.**

      **The span, stated once and used by every count in this docstring.** SCANNED means
      the **52** register entries whose `Status:` does not begin `resolved`, out of 66.
      That **includes the three that are assigned** — G17, G18, G61 — because an
      assignment does not spend a trigger: G61's own trigger names M8.2, the issue it is
      assigned to, so marking M8.2 done must make G61 fire. Counting the assigned three
      as closed instead gives 49 scanned and 17 with a target, and that is the whole of
      the difference between the two readings. Both figures are stated with their span
      because a bare count here is not re-derivable, and a coverage number about a guard
      is the one number that has to be. *(The configuration matters as much as the span:
      an earlier count of four false positives was taken while the trigger side skipped
      history lines.)* G21's is the clearest of the 13:
      its `Trigger:` clause ends *"Do it the way M5.0 did ruff"*, where `M5.0` is an
      example of how to do the work and not a thing to wait for. The register bolds a trigger's
      target, so the bold is what distinguishes the two — and because the bold carries
      the meaning, the colon does not have to: a label followed directly by a bolded id
      counts, which is what makes G33's `Re-entry trigger re-points to **M7.1**`
      readable. **An UNBOLDED target is invisible here**, and that is the widest hole
      this check has.
    * **The recorded side takes an id from the history line's HEADER**, never from its
      body — see `_history_header` for where a header ends and why it is bounded that
      tightly. Scanning whole history lines passed G33 and G61 while their own dated
      note was deleted, because a *second* note mentioned the milestone in passing.
      That is the mention failure arriving inside the fix for it. Note the header is
      not required to carry a DATE: `Note (M5.1):` and `Resolution (M5.1):` are both
      forms this register already uses.

    History lines are the seven dated forms this register uses — `Note`, `Rewritten`,
    `Resolution`, `Discharge`, `Assignment`, `Split`, `Update` — and not `Note` alone:
    G42 recorded its fired M5.9 trigger under `Rewritten (2026-09-08, M5.9 commit 1)`,
    in full, and a `Note`-only anchor would have failed the one entry that did the job
    thoroughly.

    Scope, stated because each exclusion is a place this check is silent. Resolved
    entries are skipped — their trigger is spent by definition. A trigger naming no
    `M<n>.<n>` is invisible here, which is 34 of those same 52 scanned entries, most
    of them keyed on an event rather than an issue (*"any workflow gaining a
    `pull_request_target` trigger"*). And nothing here requires an entry to HAVE a
    trigger; that is a rule M6 set for new entries and not a property of the 66 already
    written.
    """
    lines = _read(ROADMAP).splitlines()

    done_issues: set[str] = set()
    in_milestone = False
    for line in lines:
        if line.startswith("## "):
            in_milestone = line.startswith("## Milestone ")
        elif (
            in_milestone
            and re.search(r"— done\b", line)
            and (match := re.match(rf"- \*\*({ISSUE_ID}) — ", line))
        ):
            done_issues.add(match.group(1))

    register = _h2_section(lines, lambda heading: heading.startswith("## Deferred gaps"))
    if register is None:
        findings.append(
            (ROADMAP, 1, "no '## Deferred gaps' section, so no trigger can be verified")
        )
        return
    register_start, register_lines = register

    entries: list[tuple[int, str, list[str]]] = []
    for offset, line in enumerate(register_lines):
        if line.startswith("### "):
            entries.append((register_start + offset + 1, line.removeprefix("### ").strip(), []))
        elif entries:
            entries[-1][2].append(line)

    for line_number, title, body in entries:
        status = re.search(r"^Confirmed:.*?Status:\s*(.+)$", "\n".join(body), flags=re.MULTILINE)
        value = (status.group(1) if status else "").strip().lstrip("*`_ ").lower()
        if value.startswith("resolved"):
            continue

        targets: set[str] = set()
        recorded: set[str] = set()
        for entry_line in body:
            if HISTORY_LINE.match(entry_line):
                recorded.update(re.findall(ISSUE_ID, _history_header(entry_line)))
            # Both sides read every line, because a history line may also RE-POINT a
            # trigger: G33 re-points its own inside a `Note`, which is this register's
            # established way of doing it. Skipping history lines here would make the
            # one shape that moves a trigger the one shape this check cannot read.
            for label in TRIGGER_LABEL.finditer(entry_line):
                targets.update(BOLD_ISSUE.findall(entry_line[label.end() :]))

        for issue in sorted((targets & done_issues) - recorded):
            findings.append(
                (
                    ROADMAP,
                    line_number,
                    f"gap '{title}' names {issue} as a trigger and {issue} is marked done, "
                    f"but no history line's header names {issue} — the trigger has "
                    f"fired and the entry does not say so",
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
    check_fired_triggers_are_recorded,
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
