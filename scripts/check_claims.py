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


CHECKS = (
    check_ci_steps_match_tier1_table,
    check_retired_tools_are_not_named,
    check_rule_count_is_in_sync,
)


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    for check in CHECKS:
        check(findings)

    if not findings:
        print(f"check_claims: {len(CHECKS)} checks passed.")
        return 0

    print("check_claims: documentation no longer matches the artifacts it describes.\n")
    for line in _findings_to_lines(sorted(findings)):
        print(f"  {line}")
    print(
        f"\n{len(findings)} claim(s) out of date. Fix the doc, or fix the thing it "
        f"describes — whichever is actually wrong."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
