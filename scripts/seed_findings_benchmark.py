"""Seed findings at realistic volume and EXPLAIN the queries M4.5 added.

ADR-0020 asked M4.5 to `EXPLAIN` the project listing and the sighting join "at
realistic volume before deciding anything further", and warned in the same breath
that the three committed fixtures produce 34 findings — a volume at which
Postgres seq-scans whatever indexes exist, so a benchmark there measures nothing
while reading as evidence.

**This script is versioned rather than kept as a scratch file, and that is the
point of it existing at all.** A measurement recorded in an ADR with no way to
re-derive it is a number nobody can check — which is what ADR-012's unvalidated
180s Trivy timeout became, and what G4 is the record of. The ADR names an
invocation; this is the thing that invocation runs.

**Nothing in CI executes it, which is a real cost.** It can rot against a schema
change and nobody would learn until the next person tries to re-run it. Two
things bound that, and neither is a test:

- it builds its schema with `alembic upgrade head`, exactly as
  `tests/integration/conftest.py` does, so a drift fails loudly at startup rather
  than silently measuring a stale shape — wrong numbers presented as measurements
  being worse than no numbers;
- the defaults are small, so `--help` and a smoke run cost seconds.

A CI test that ran it at full volume was considered and rejected: a 100k-row seed
is container-bound, and `CLAUDE.md` puts roughly three ZAP-class tests between
here and the 120s split. This exists to be re-run by a person.

**What it proves and does not.** It shows which ACCESS PATH Postgres chooses —
whether the listing rides `uq_findings_project_id_dedup_hash` as an index prefix
or falls to a seq scan, whether the sighting aggregate uses the composite primary
key, whether `ix_normalization_runs_project_id` is reached. It does NOT show
real-world selectivity, real payload-size distribution, or behaviour under
concurrency: the data below is synthetic and uniform. Read it for plan shape, not
for latency.

**READ THIS BEFORE CHANGING HOW ANY VALUE BELOW IS GENERATED.** Volume is not
what makes a benchmark honest. Every field this script invents has to match the
SHAPE production writes, because the query planner reads shape — cardinality,
ordering, distribution, width — and a synthetic value that differs from
production in a way that looks cosmetic can silently change the plan and make the
measurement describe the generator instead of the query.

That is not a hypothetical caution. It happened while writing this file, at full
volume, and it produced a number that was wrong by 250×:

- finding ids were generated **sequentially** (`bench-f-0-1`, `bench-f-0-2`, …);
- that clustered one project's findings at the head of any id-ordered scan;
- so the sighting join terminated almost immediately and the listing measured
  **8.8 ms**;
- production ids are UUIDs (**rule 9**, `IdGeneratorPort.new_id()`), which do not
  cluster. With UUID-shaped ids the same query measured **763 ms** — a seq scan of
  300,000 sighting rows with a 22 MB external merge sort — and had to be rewritten
  as a correlated LATERAL, which is what actually ships.

The 8.8 ms reading was at full volume, from real Postgres, with `EXPLAIN
(ANALYZE, BUFFERS)`. Everything about it looked like evidence except the one
property nobody had checked. So: **when adding a column or a table here, ask what
production's values look like on that column, not just how many of them there
are.** Distribution, ordering and uniqueness are part of the fixture.

This is the shape G8 and G9 already record — a verification that is sound and
disconnected from reality — arriving through a seed script rather than through a
linter or a redacted fixture. It is registered as **G19** so the next person
writing one of these meets it before repeating it, not after.

Usage:

    uv run python scripts/seed_findings_benchmark.py --projects 50 --findings-per-project 2000

The database is the one `Settings.database_url` points at, and this script
DELETES the rows it created (and only those) on the way out unless --keep is
passed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verion.platform.settings import get_settings  # noqa: E402
from verion.shared_kernel.scanner_tools import ScannerTool  # noqa: E402
from verion.shared_kernel.severity import Severity  # noqa: E402

# A marker on every id this script writes, so cleanup can delete exactly its own
# rows and never a real one. Chosen rather than "truncate the tables" because
# somebody will eventually run this against a database that has something in it.
_MARK = "bench-"

# The same marker for ids that must fit `String(36)` in UUID shape — it is the
# first group of the UUID rather than a prefix on it, so cleanup can still match
# exactly this script's rows.
_UUID_MARK = "beeeeeee"

# Drawn from the measured range of real payloads: 360 chars (semgrep) to 9,888
# (trivy), across the three committed fixtures. Uniform here, which is one of the
# ways this data is not real.
_PAYLOAD_SIZES = (360, 1_247, 2_236, 4_000, 9_888)

_SEVERITIES = [str(member) for member in Severity]
_SOURCES = [str(member) for member in ScannerTool]


def _ensure_schema() -> None:
    """`alembic upgrade head`, the same way the integration suite builds its schema.

    Not an optimisation and not politeness: it is what stops this script from
    measuring a schema that no longer matches the models. A seed that succeeded
    against a stale table would produce numbers that look fine and describe
    nothing.
    """
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def _month(index: int, *, minute: int = 0, day_offset: int = 0) -> datetime:
    """asyncpg binds real datetimes, not ISO strings, and rejects the latter."""
    return datetime(2026, index + 1, 1, 0, minute, tzinfo=UTC) + timedelta(seconds=day_offset)


def _rows(
    projects: int, per_project: int, runs_per_project: int
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    findings: list[dict] = []
    evidence: list[dict] = []
    sightings: list[dict] = []
    runs: list[dict] = []

    for project_index in range(projects):
        project_id = f"{_MARK}project-{project_index}"
        for run_index in range(runs_per_project):
            runs.append(
                {
                    "id": f"{_MARK}run-{project_index}-{run_index}",
                    "scan_id": f"{_MARK}scan-{project_index}-{run_index}",
                    "project_id": project_id,
                    "status": "completed" if run_index else "failed",
                    "requested_at": _month(run_index % 12, day_offset=run_index),
                    "started_at": _month(run_index % 12, day_offset=run_index),
                    "finished_at": _month(run_index % 12, day_offset=run_index, minute=1),
                    "failure_reason": None if run_index else "Normalization failed with OSError.",
                }
            )

        for finding_index in range(per_project):
            # Shaped like the real thing — "v1:" plus 64 hex — so index entries
            # are the width production writes rather than a short synthetic key.
            digest = hashlib.sha256(f"{project_index}:{finding_index}".encode()).hexdigest()
            # A UUID-SHAPED id, not a sequential one, and this is the single
            # most load-bearing line in the file — see the module docstring and
            # G19. Production ids are UUIDs (RULE 9, `IdGeneratorPort.new_id()`),
            # so a project's finding ids are spread uniformly across the id space.
            # Sequential ids cluster one project's findings at the head of any
            # id-ordered scan, which lets a sighting join terminate almost
            # immediately: measured at 8.8 ms that way against 763 ms with UUIDs,
            # so that number described the id scheme rather than the query.
            # Do not "simplify" this back to a counter. See ADR-0022.
            #
            # The marker has to live INSIDE the 36 characters `String(36)` allows,
            # so it is the first group rather than a prefix.
            finding_id = "-".join(
                (_UUID_MARK, digest[8:12], digest[12:16], digest[16:20], digest[20:32])
            )
            rule_id = f"rule-{finding_index % 400}"
            findings.append(
                {
                    "id": finding_id,
                    "project_id": project_id,
                    "dedup_hash": f"v1:{digest}",
                    "source": _SOURCES[finding_index % len(_SOURCES)],
                    "rule_id": rule_id,
                    "file_path": f"src/module_{finding_index % 50}.py",
                    "package": None,
                    "url": None,
                    "http_method": None,
                    "parameter": None,
                    "severity": _SEVERITIES[finding_index % len(_SEVERITIES)],
                    "native_severity": "ERROR",
                    "title": f"Synthetic finding {finding_index}",
                    "cwe": "CWE-95",
                    "owasp_category": None,
                    "cvss": None,
                    "start_line": finding_index % 500,
                    "end_line": finding_index % 500,
                    "installed_version": None,
                }
            )
            size = _PAYLOAD_SIZES[finding_index % len(_PAYLOAD_SIZES)]
            evidence.append(
                {
                    "id": f"{_MARK}e-{digest[:24]}",
                    "finding_id": finding_id,
                    "scan_id": f"{_MARK}scan-{project_index}-2",
                    "raw_payload": '{"padding": "' + "x" * (size - 16) + '"}',
                    "source_tool": _SOURCES[finding_index % len(_SOURCES)],
                    "captured_at": _month(2),
                }
            )
            # Three sightings per finding, which is what makes the aggregate
            # non-trivial: 100k findings become 300k sighting rows. Deliberately
            # not tied to --runs-per-project: that flag exists to grow
            # `normalization_runs`, which is a different question.
            for run_index in range(3):
                sightings.append(
                    {
                        "finding_id": finding_id,
                        "scan_id": f"{_MARK}scan-{project_index}-{run_index}",
                        "observed_at": _month(run_index),
                        "match_count": 1,
                    }
                )
    return findings, evidence, sightings, runs


_INSERTS = {
    "normalization_runs": (
        "INSERT INTO normalization_runs (id, scan_id, project_id, status, requested_at,"
        " started_at, finished_at, failure_reason) VALUES (:id, :scan_id, :project_id,"
        " :status, :requested_at, :started_at, :finished_at, :failure_reason)"
    ),
    "findings": (
        "INSERT INTO findings (id, project_id, dedup_hash, source, rule_id, file_path,"
        " package, url, http_method, parameter, severity, native_severity, title, cwe,"
        " owasp_category, cvss, start_line, end_line, installed_version) VALUES (:id,"
        " :project_id, :dedup_hash, :source, :rule_id, :file_path, :package, :url,"
        " :http_method, :parameter, :severity, :native_severity, :title, :cwe,"
        " :owasp_category, :cvss, :start_line, :end_line, :installed_version)"
    ),
    "evidence": (
        "INSERT INTO evidence (id, finding_id, scan_id, raw_payload, source_tool, captured_at)"
        " VALUES (:id, :finding_id, :scan_id, :raw_payload, :source_tool, :captured_at)"
    ),
    "finding_sightings": (
        "INSERT INTO finding_sightings (finding_id, scan_id, observed_at, match_count)"
        " VALUES (:finding_id, :scan_id, :observed_at, :match_count)"
    ),
}

# The severity ordering the adapter builds with a CASE, rendered here as the same
# expression so the plan measured is the plan served. Derived from Severity.rank
# for the reason the adapter derives it: a hand-written copy would drift.
_RANK_CASE = (
    "CASE "
    + " ".join(f"WHEN severity = '{member}' THEN {member.rank}" for member in Severity)
    + " ELSE -1 END"
)

_AT_OR_ABOVE_HIGH = ", ".join(
    f"'{member}'" for member in Severity if member.rank >= Severity.HIGH.rank
)

QUERIES: dict[str, str] = {
    "1. filtered project listing (the page)": f"""
        SELECT f.*, e.*, s.*
        FROM (
            SELECT id FROM findings
            WHERE project_id = :project_id
              AND severity IN ({_AT_OR_ABOVE_HIGH})
              AND source = :source
            ORDER BY {_RANK_CASE} DESC, dedup_hash
            LIMIT 50 OFFSET 0
        ) page
        JOIN findings f ON f.id = page.id
        LEFT JOIN evidence e ON e.finding_id = f.id
        LEFT JOIN LATERAL (
            SELECT scan_id AS last_seen_scan_id,
                   observed_at AS last_seen_at,
                   match_count AS latest_match_count,
                   min(observed_at) OVER () AS first_seen_at,
                   count(*) OVER () AS sighting_count
            FROM finding_sightings
            WHERE finding_id = f.id
            ORDER BY observed_at DESC, scan_id DESC
            LIMIT 1
        ) s ON true
        ORDER BY {_RANK_CASE} DESC, f.dedup_hash
    """,
    "2. the count behind `total`": f"""
        SELECT count(*) FROM findings
        WHERE project_id = :project_id
          AND severity IN ({_AT_OR_ABOVE_HIGH})
          AND source = :source
    """,
    "3. latest normalization run for a project": """
        SELECT * FROM normalization_runs
        WHERE project_id = :project_id
        ORDER BY requested_at DESC, id DESC
        LIMIT 1
    """,
    "4. unfinished normalization runs for a project": """
        SELECT count(*) FROM normalization_runs
        WHERE project_id = :project_id AND status <> 'completed'
    """,
    # Added at M5.2. `get_by_project_id`'s statement, which correlation reads on
    # every request under ADR-0025 decision 1. Unpaged and unfiltered by design —
    # see that port method's docstring. This is the acceptance criterion for that
    # decision rather than a plan anyone is tuning: ADR-0025's Consequences says
    # what a bad number here means and refuses three responses to it in advance.
    "5. the full-project read behind a Risk listing": """
        SELECT f.*, e.*
        FROM findings f
        LEFT JOIN evidence e ON e.finding_id = f.id
        WHERE f.project_id = :project_id
        ORDER BY f.dedup_hash
    """,
}


# Every query above filters on ONE project_id, so a plan over zero rows is fast
# and reads exactly like a plan over a full one. These print first so the plans
# below are read against a row count rather than against the seed's own claim
# about what it wrote. In the script rather than typed once at a shell, for the
# reason the module docstring gives for the script existing at all.
_GUARD_COUNTS: dict[str, str] = {
    "findings in the measured project": """
        SELECT count(*) FROM findings WHERE project_id = :project_id
    """,
    "evidence rows in the measured project": """
        SELECT count(*) FROM evidence e
        JOIN findings f ON e.finding_id = f.id
        WHERE f.project_id = :project_id
    """,
}


async def _run(projects: int, per_project: int, runs_per_project: int, keep: bool) -> None:
    _ensure_schema()
    engine = create_async_engine(get_settings().database_url)
    findings, evidence, sightings, runs = _rows(projects, per_project, runs_per_project)

    print(
        f"seeding {len(findings):,} findings, {len(evidence):,} evidence rows, "
        f"{len(sightings):,} sightings, {len(runs):,} runs across {projects} projects"
    )
    try:
        async with engine.begin() as conn:
            for table, rows in (
                ("normalization_runs", runs),
                ("findings", findings),
                ("evidence", evidence),
                ("finding_sightings", sightings),
            ):
                for start in range(0, len(rows), 5_000):
                    await conn.execute(text(_INSERTS[table]), rows[start : start + 5_000])
            # Without this the planner works from stale or absent statistics and
            # the plans below describe a table Postgres does not think it has.
            await conn.execute(text("ANALYZE findings, evidence, finding_sightings"))
            await conn.execute(text("ANALYZE normalization_runs"))

        async with engine.connect() as conn:
            params = {"project_id": f"{_MARK}project-0", "source": str(ScannerTool.SEMGREP)}
            print(f"\n=== measured project: {params['project_id']} ===")
            for label, count_query in _GUARD_COUNTS.items():
                measured = (await conn.execute(text(count_query), params)).scalar_one()
                print(f"{label}: {measured:,}")
            for label, query in QUERIES.items():
                plan = await conn.execute(text(f"EXPLAIN (ANALYZE, BUFFERS) {query}"), params)
                print(f"\n=== {label} ===")
                for row in plan:
                    print(row[0])
    finally:
        if not keep:
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM finding_sightings WHERE finding_id LIKE :m"),
                    {"m": f"{_UUID_MARK}-%"},
                )
                await conn.execute(
                    text("DELETE FROM evidence WHERE id LIKE :m"), {"m": f"{_MARK}%"}
                )
                await conn.execute(
                    text("DELETE FROM findings WHERE id LIKE :m"), {"m": f"{_UUID_MARK}-%"}
                )
                await conn.execute(
                    text("DELETE FROM normalization_runs WHERE id LIKE :m"), {"m": f"{_MARK}%"}
                )
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # Small defaults so a smoke run costs seconds. The volume the ADR reports is
    # --projects 50 --findings-per-project 2000.
    parser.add_argument("--projects", type=int, default=2)
    parser.add_argument("--findings-per-project", type=int, default=50)
    # `normalization_runs` grows one row per SCAN forever, so
    # ix_normalization_runs_project_id is justified by scan history rather than by
    # project count — and the DEFAULT here deliberately does not exercise it.
    #
    # At the default 3, fifty projects give 150 rows and Postgres seq-scans them
    # however good the index is, which says nothing either way. That is the right
    # default because it is the CHEAP one, not because it is the informative one.
    # To see the index actually used, raise it: at `--runs-per-project 400`
    # (20,000 runs) the latest-run query becomes an Index Scan and the unfinished
    # count a Bitmap Index Scan. Both figures are recorded in ADR-0022, measured
    # that way and labelled as such.
    parser.add_argument("--runs-per-project", type=int, default=3)
    parser.add_argument(
        "--keep", action="store_true", help="leave the seeded rows in place afterwards"
    )
    args = parser.parse_args()
    asyncio.run(_run(args.projects, args.findings_per_project, args.runs_per_project, args.keep))


if __name__ == "__main__":
    main()
