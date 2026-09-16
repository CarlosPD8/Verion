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

**Extended at M6.3 to measure a scored REQUEST, and what it gained is two rows
per project and nothing else.** `ProjectAccessPort` refuses a read without a
membership row, so `projects` and `project_memberships` rows had to arrive before
the endpoint could be reached at all. **No generated finding value changed** —
which is the short answer G19's trigger asks for, since no emitted field moved
and therefore no shape question moved with it.

**What the request figures do and do not say.** Every finding here carries
`package: None` and `url: None`, so 2,000 findings become 2,000 **singleton**
surfaces, each single-source with corroboration 0. That is the worst case for
per-surface overhead and it is **not** a production grouping, so the Python-side
cost below is an **UPPER BOUND reported with its shape beside it** and must never
be quoted as "a scored request costs X ms". What it does measure honestly is
**G61**'s actual subject: `/risks` performs ONE `get_by_project_id` and
`/scored-risks` performs TWO plus the scoring pass, so the difference between the
two routes is the doubling, measured rather than inferred. The read itself is
grouping-independent — same statement, same rows — though populating
`package`/`url` would widen them, which is why each plan is reported rather than
assumed.

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
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verion.modules.identity.adapters.outbound.security.jwt_issuer import (  # noqa: E402
    JwtAccessTokenIssuer,
)
from verion.modules.normalization.adapters.outbound.db.repository import (  # noqa: E402
    PostgresFindingRepository,
)
from verion.modules.projects.domain.project import Role  # noqa: E402
from verion.platform.app import app  # noqa: E402
from verion.platform.clock import SystemClock  # noqa: E402
from verion.platform.settings import get_settings  # noqa: E402
from verion.shared_kernel.scanner_tools import ScannerTool  # noqa: E402
from verion.shared_kernel.severity import Severity  # noqa: E402

# A marker on every id this script writes, so cleanup can delete exactly its own
# rows and never a real one. Chosen rather than "truncate the tables" because
# somebody will eventually run this against a database that has something in it.
_MARK = "bench-"

# The owner of every seeded project, and the subject of the token the request
# measurement signs. One user for all of them: `may_read_project` asks whether a
# membership row exists, so a second user would model more than the port exposes.
_MEMBER = f"{_MARK}member"

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


def _project_rows(projects: int) -> tuple[list[dict], list[dict]]:
    """A project row and an owner membership per seeded project. **M6.3's only new data.**

    `ProjectAccessPort` refuses a project-scoped read without a membership row, so the
    request measurement cannot reach the endpoint at all without these two. They are the
    whole of what this script's generated data gained, and deliberately so: every finding
    value is untouched, so **G19**'s shape question is unchanged rather than re-answered.

    `role` is written from `Role.OWNER` rather than the literal `"owner"`, so a renamed
    member fails here instead of silently seeding a row no authorization rule matches.
    """
    project_rows: list[dict] = []
    membership_rows: list[dict] = []
    for index in range(projects):
        project_id = f"{_MARK}project-{index}"
        project_rows.append(
            {
                "id": project_id,
                "owner_id": _MEMBER,
                "name": f"Benchmark project {index}",
                "created_at": _month(0),
            }
        )
        membership_rows.append(
            {"project_id": project_id, "user_id": _MEMBER, "role": str(Role.OWNER)}
        )
    return project_rows, membership_rows


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
    # Projects and their memberships come first: `findings` carries no foreign key to
    # either (ADR-0017 decision 1, and G11 records what that costs), but the membership
    # row does, and `ProjectAccessPort` reads it on every request measured below.
    "projects": (
        "INSERT INTO projects (id, owner_id, name, created_at)"
        " VALUES (:id, :owner_id, :name, :created_at)"
    ),
    "project_memberships": (
        "INSERT INTO project_memberships (project_id, user_id, role)"
        " VALUES (:project_id, :user_id, :role)"
    ),
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


async def _measure_reads(project_id: str, runs: int) -> None:
    """Time ONE `get_by_project_id` END TO END, on the same footing as the requests below.

    **This function exists because `EXPLAIN` and a request are not comparable, and an
    earlier reading of this script's output compared them anyway.** `EXPLAIN (ANALYZE)`
    reports server-side `Execution Time` only. It does not include the driver round-trip,
    the transfer of every returned row, or SQLAlchemy's hydration of them into `Finding`
    entities — and at 2,000 rows roughly 871 bytes wide (see query 5's plan) those steps
    usually dominate. Subtracting a 26 ms `Execution Time` from a 156 ms difference between
    two routes therefore says **nothing** about how that difference splits, which is exactly
    the claim **G61** exists to settle.

    Timed with `perf_counter` around the port call, exactly as the routes are timed, so the
    read term and the route difference are finally the same kind of number.

    Its own engine rather than the caller's, so the read is not served from a connection the
    app has already warmed; the discarded warm-up below then covers first-connection cost
    the same way it does for the routes.
    """
    engine = create_async_engine(get_settings().database_url)
    try:
        timings: list[float] = []
        returned = 0
        async with AsyncSession(engine) as session:
            repository = PostgresFindingRepository(session)
            await repository.get_by_project_id(project_id)  # discarded warm-up
            for _ in range(runs):
                started = time.perf_counter()
                findings = await repository.get_by_project_id(project_id)
                timings.append((time.perf_counter() - started) * 1000)
                returned = len(findings)
        print("\n=== get_by_project_id — ONE read, end to end ===")
        print(f"findings returned: {returned:,} (driver round-trip + transfer + hydration)")
        print("ms, ascending: " + ", ".join(f"{value:.1f}" for value in sorted(timings)))
    finally:
        await engine.dispose()


async def _measure_requests(project_id: str, runs: int) -> None:
    """Time a SCORED request against the unscored one, and the read term against both.

    `GET /risks` performs ONE `get_by_project_id`; `GET /scored-risks` performs TWO plus the
    scoring and ranking pass. **The difference between the two route rows is therefore the
    second read PLUS the scoring pass, and the difference alone does not say how it
    splits** — which is why `_measure_reads` runs first and on the same footing. An earlier
    version of this docstring claimed the difference *was* the doubling measured; it is not,
    and **G61** is precisely the entry that would have inherited that error.

    Every reading is printed, never an average: ADR-0025 found this project's evidence join
    **bimodal** over eight runs, and a mean would name a latency no run produced.

    Goes through the real app over an ASGI transport, so the route, its DI graph and
    `CorrelationCandidateRisks` are all genuinely constructed. The lifespan is deliberately
    not run — `ASGITransport` does not invoke it — so no Redis pool is created; nothing on
    this path touches the job queue.
    """
    await _measure_reads(project_id, runs)

    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    headers = {"Authorization": f"Bearer {issuer.issue(subject=_MEMBER).value}"}

    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(
        transport=transport, base_url="http://bench", timeout=300.0
    ) as client:
        for label, path in (
            ("GET /risks — ONE findings read, no scoring", f"/projects/{project_id}/risks"),
            (
                "GET /scored-risks — TWO findings reads, plus scoring and ranking",
                f"/projects/{project_id}/scored-risks",
            ),
        ):
            # ONE DISCARDED WARM-UP PER ROUTE, and it is not tidiness. Observed while
            # developing this at the 50-finding smoke volume, without the warm-up: the first
            # route read 12.2 and 142.5 ms while the second — by then warm — read 17.0 and
            # 20.8. **That run's output was not captured**, so those four figures are the
            # observation that motivated the discard and NOT a measurement of record; the
            # reproducible ones are in ADR-0030's Consequences. The outlier is one-time
            # process setup (the engine's first connection, the DI graph, Pydantic's
            # validator construction) landing on whichever request happens to go first, so
            # leaving it in would let ROUTE ORDER decide the comparison this function
            # exists to make, and would show the one-read route as slower than the
            # two-read one. Discarded rather than reported, because it measures process
            # startup and G61 is about the per-request doubling.
            await client.get(path, headers=headers)

            timings: list[float] = []
            body: dict = {}
            for _ in range(runs):
                started = time.perf_counter()
                response = await client.get(path, headers=headers)
                timings.append((time.perf_counter() - started) * 1000)
                if response.status_code != 200:
                    raise SystemExit(
                        f"{path} returned {response.status_code}: {response.text[:300]}"
                    )
                body = response.json()
            print(f"\n=== {label} ===")
            print(f"surfaces in the project: {body['total']:,} (page of {len(body['items'])})")
            print("ms, ascending: " + ", ".join(f"{value:.1f}" for value in sorted(timings)))

    print(
        "\nREAD THE ROUTE ROWS AS A DIFFERENCE, NOT AS A LATENCY. Every seeded finding\n"
        "carries package=None and url=None, so each one is a NO-SIGNAL singleton: the totals\n"
        "above are one surface per finding, which is the worst case for per-surface overhead\n"
        "and is not a production grouping. The scored figure is therefore an UPPER BOUND on\n"
        "the Python-side cost, and must not be quoted as 'a scored request costs X ms'.\n"
        "\n"
        "AND DO NOT SUBTRACT THE EXPLAIN FIGURE FROM THE ROUTE DIFFERENCE. Query 5's\n"
        "Execution Time is server-side only; the read row above is the same read measured\n"
        "end to end, and it is the ONLY one of the two that is commensurable with the route\n"
        "rows. The route difference is the second read PLUS scoring; the read row is what\n"
        "says how much of it is the read. That split is G61's whole subject."
    )


async def _run(
    projects: int, per_project: int, runs_per_project: int, keep: bool, request_runs: int
) -> None:
    _ensure_schema()
    engine = create_async_engine(get_settings().database_url)
    findings, evidence, sightings, runs = _rows(projects, per_project, runs_per_project)
    project_rows, membership_rows = _project_rows(projects)

    print(
        f"seeding {len(findings):,} findings, {len(evidence):,} evidence rows, "
        f"{len(sightings):,} sightings, {len(runs):,} runs across {projects} projects"
    )
    try:
        async with engine.begin() as conn:
            # Projects and memberships FIRST: `project_memberships` carries a foreign key
            # to `projects`, and `ProjectAccessPort` reads it on every measured request.
            for table, rows in (
                ("projects", project_rows),
                ("project_memberships", membership_rows),
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

        # After the plans, and against the same seeded rows: M6.3's own deliverable.
        if request_runs:
            await _measure_requests(f"{_MARK}project-0", request_runs)
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
                # Reverse foreign-key order: the membership references the project.
                await conn.execute(
                    text("DELETE FROM project_memberships WHERE user_id LIKE :m"),
                    {"m": f"{_MARK}%"},
                )
                await conn.execute(
                    text("DELETE FROM projects WHERE id LIKE :m"), {"m": f"{_MARK}%"}
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
    # M6.3's own deliverable. Eight is ADR-0030 decision 7's floor, and it is that number
    # because ADR-0025 found this project's evidence join BIMODAL over exactly eight runs —
    # fewer would report one plan as though it were the only one. `--request-runs 0` skips
    # the request measurement and leaves the EXPLAIN plans above, which is what a
    # schema-only re-run wants.
    parser.add_argument("--request-runs", type=int, default=8)
    args = parser.parse_args()
    asyncio.run(
        _run(
            args.projects,
            args.findings_per_project,
            args.runs_per_project,
            args.keep,
            args.request_runs,
        )
    )


if __name__ == "__main__":
    main()
