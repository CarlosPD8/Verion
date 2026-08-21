"""Verifies that documentation claims still match the artifacts that make them true.

Every check here exists because the claim it checks was observed to be false in
this repo, survived multiple milestones, and was found by a manual review rather
than by anything mechanical. CLAUDE.md already carries a "fix the doc in the same
PR that changed reality" rule; it only ever fired when someone remembered it.

The governing principle, borrowed from .claude/agents/architecture-guardian.md's
own instruction about import-linter: re-derive the fact from the artifact, never
from a second copy of the description.

`docs/adr/` is deliberately out of scope. ADRs are point-in-time records, and
they are *supposed* to name rejected tooling — ADR-007 discusses dependency-cruiser
as a rejected alternative, ADR-015 quotes the old "Protocol / ABCs" wording as the
thing it corrected. Flagging those would make this checker wrong, and a checker
that cries wolf gets disabled.

Run: `uv run python scripts/check_claims.py`
"""

from __future__ import annotations

import re
import sys
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

# Confirmations after which a deferred gap must be assigned or explicitly
# justified. Three, because three is where G1 broke: M3.4 and M3.5 were
# reasonable deferrals, and by M3.6 the repetition was information nobody acted on.
ESCALATION_THRESHOLD = 3


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _findings_to_lines(findings: list[tuple[str, int, str]]) -> list[str]:
    return [f"{path}:{line}: {message}" for path, line, message in findings]


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
