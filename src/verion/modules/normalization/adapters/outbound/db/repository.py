from datetime import datetime

from sqlalchemy import ColumnElement, case, func, select, true
from sqlalchemy import update as sqlalchemy_update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import LateralFromClause

from verion.modules.normalization.adapters.outbound.db.models import (
    EvidenceModel,
    FindingModel,
    FindingSightingModel,
    NormalizationRunModel,
)
from verion.modules.normalization.domain.finding import (
    Evidence,
    Finding,
    FindingSighting,
    Location,
    SightedFinding,
)
from verion.modules.normalization.domain.normalization_run import (
    NormalizationRun,
    NormalizationRunStatus,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity


def _to_domain(model: NormalizationRunModel) -> NormalizationRun:
    return NormalizationRun(
        id=model.id,
        scan_id=model.scan_id,
        project_id=model.project_id,
        status=NormalizationRunStatus(model.status),
        requested_at=model.requested_at,
        started_at=model.started_at,
        finished_at=model.finished_at,
        failure_reason=model.failure_reason,
    )


class PostgresNormalizationRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def request(
        self, *, id: str, scan_id: str, project_id: str, requested_at: datetime
    ) -> None:
        # Constructed, not written straight from the primitives: this is what
        # makes NormalizationRun.__post_init__ reachable on the production write
        # path, so the invariant genuinely holds in two places rather than only
        # in the CHECK constraint (ADR-0017 decision 1).
        run = NormalizationRun.requested(
            id=id, scan_id=scan_id, project_id=project_id, requested_at=requested_at
        )
        # ON CONFLICT DO NOTHING, and specifically not DO UPDATE: a row already
        # existing means a retry re-requested a run that is already recorded,
        # which is the correct end state either way. DO UPDATE would reset a
        # running/completed row back to pending and re-normalize a scan that was
        # already normalized. The alternative, INSERT + catching IntegrityError,
        # is what ADR-014 rejected for WebhookDeliveryRepository — it leaves the
        # session in a failed-transaction state, which fights worker.py's
        # commit-in-`finally` lifecycle even harder than it fought the
        # request-scoped session's.
        statement = (
            insert(NormalizationRunModel)
            .values(
                id=run.id,
                scan_id=run.scan_id,
                project_id=run.project_id,
                status=str(run.status),
                requested_at=run.requested_at,
                started_at=run.started_at,
                finished_at=run.finished_at,
                failure_reason=run.failure_reason,
            )
            .on_conflict_do_nothing(constraint="uq_normalization_runs_scan_id")
        )
        await self._session.execute(statement)
        # Surfaces a constraint failure here rather than inside worker.py's
        # commit-in-`finally`, which matters for ADR-0017 decision 2's ordering:
        # this write has to fail *before* the Scan is marked COMPLETED.
        await self._session.flush()

    async def get_by_scan_id(self, scan_id: str) -> NormalizationRun | None:
        result = await self._session.execute(
            select(NormalizationRunModel).where(NormalizationRunModel.scan_id == scan_id)
        )
        model = result.scalars().one_or_none()
        return _to_domain(model) if model is not None else None

    async def claim(self, *, scan_id: str, now: datetime) -> NormalizationRun | None:
        # SELECT ... FOR UPDATE, then the domain transition, then the write —
        # NOT a single conditional UPDATE with the transition transcribed into a
        # SET clause. The transcription is what the finding upsert has to live
        # with (ADR-0020 decision 1) and it is a real cost: a second copy of the
        # policy, kept honest only by a test.
        #
        # It is avoidable here and not there, for one specific reason. ADR-0020
        # decision 2 rejected read-modify-write because the finding row may not
        # exist yet, so two concurrent workers both SELECT nothing, both INSERT,
        # and one takes an IntegrityError — the failed-transaction state this
        # project has now rejected three times. This row ALWAYS already exists:
        # ADR-0017 decision 3's invariant is that a normalization_runs row exists
        # iff ScanResult rows were persisted, and the handoff wrote it in that
        # same transaction. There is no insert, so there is nothing to collide,
        # and a row lock closes the window the read-modify-write would open.
        #
        # The lock is held only until this method's transaction commits, which is
        # the claim alone — the mapping work runs in a second session.
        result = await self._session.execute(
            select(NormalizationRunModel)
            .where(NormalizationRunModel.scan_id == scan_id)
            .with_for_update()
        )
        model = result.scalars().one_or_none()
        if model is None:
            return None
        run = _to_domain(model)
        if run.status is NormalizationRunStatus.COMPLETED:
            # Redelivered after success. The only terminal state, and the only
            # one that short-circuits — see NormalizationRun's docstring for why
            # FAILED deliberately does not.
            return None
        claimed = run.start(now)
        await self._write(claimed)
        return claimed

    async def update(self, run: NormalizationRun) -> None:
        await self._write(run)

    async def _write(self, run: NormalizationRun) -> None:
        await self._session.execute(
            sqlalchemy_update(NormalizationRunModel)
            .where(NormalizationRunModel.id == run.id)
            .values(
                status=str(run.status),
                started_at=run.started_at,
                finished_at=run.finished_at,
                failure_reason=run.failure_reason,
            )
        )
        # Surfaces a CHECK violation here rather than inside worker.py's
        # commit-in-`finally`, the same reason `request` flushes.
        await self._session.flush()

    async def get_latest_by_project_id(self, project_id: str) -> NormalizationRun | None:
        # `requested_at` DESC, then `id` as a total tiebreak: two scans of one
        # project can be requested within the same clock tick, and without the
        # second key "the latest run" would be whichever row Postgres returned
        # first — the non-deterministic-representative mistake ZAP's instances[0]
        # is this project's record of. Served by ix_normalization_runs_project_id.
        result = await self._session.execute(
            select(NormalizationRunModel)
            .where(NormalizationRunModel.project_id == project_id)
            .order_by(NormalizationRunModel.requested_at.desc(), NormalizationRunModel.id.desc())
            .limit(1)
        )
        model = result.scalars().one_or_none()
        return _to_domain(model) if model is not None else None

    async def count_unfinished_by_project_id(self, project_id: str) -> int:
        # Everything that is not COMPLETED, which is the only terminal state
        # (ADR-0021 decision 3). Expressed as `!= completed` rather than as a list
        # of the other three so that a fifth status member is counted as
        # unfinished by default — the safe direction for a field whose whole job
        # is to say "this list may be missing findings".
        result = await self._session.execute(
            select(func.count())
            .select_from(NormalizationRunModel)
            .where(
                NormalizationRunModel.project_id == project_id,
                NormalizationRunModel.status != str(NormalizationRunStatus.COMPLETED),
            )
        )
        return result.scalar_one()

    async def get_stale(self, *, older_than: datetime, limit: int) -> list[NormalizationRun]:
        # `normalization_runs` and nothing else. No join to `scans`, no subquery
        # against it, no filter on `Scan.status` — ADR-0017 decision 2 states that
        # as an invariant, and `test_normalization_sweep.py` proves it
        # behaviourally rather than by asserting on this statement's text: it
        # sweeps a row whose scan_id names no scans row at all, which every
        # implementation that reads `scans` returns nothing for.
        #
        # RUNNING is included alongside PENDING, which is a deliberate deviation
        # from ADR-0017's anticipated `WHERE status = 'pending'`. A job killed by
        # job_timeout, or a worker killed after the claim commits, leaves a
        # RUNNING row that a pending-only sweep can never recover — permanent
        # silent loss. Including it risks re-enqueuing a live job instead, which
        # is harmless: arq's job-id dedup makes that a no-op and the work is
        # idempotent by construction. Prefer the harmless failure to the silent
        # one. See ADR-0021.
        result = await self._session.execute(
            select(NormalizationRunModel)
            .where(
                NormalizationRunModel.status.in_(
                    (
                        str(NormalizationRunStatus.PENDING),
                        str(NormalizationRunStatus.RUNNING),
                    )
                ),
                NormalizationRunModel.requested_at < older_than,
            )
            .order_by(NormalizationRunModel.requested_at)
            .limit(limit)
        )
        return [_to_domain(model) for model in result.scalars()]


# The columns ON CONFLICT DO UPDATE refreshes, which is the SQL half of
# merge_observation. It is exactly `_RULE_LEVEL_ATTRIBUTES` plus the three
# Location fields compute_dedup_hash excludes for positional reasons — asserted
# against both of those domain declarations by a test, so neither can change
# without this failing. Everything absent from this set is either a surrogate id
# (kept, which is merge_observation's `id=existing.id`) or an identity input
# (unchanged by construction, since the conflict target IS the identity).
_REFRESHED_COLUMNS = (
    "severity",
    "native_severity",
    "title",
    "cwe",
    "owasp_category",
    "cvss",
    "start_line",
    "end_line",
    "installed_version",
)

_REFRESHED_EVIDENCE_COLUMNS = ("scan_id", "raw_payload", "source_tool", "captured_at")


def _evidence_to_domain(model: EvidenceModel) -> Evidence:
    return Evidence(
        id=model.id,
        finding_id=model.finding_id,
        scan_id=model.scan_id,
        raw_payload=model.raw_payload,
        # Reconstructed at the boundary, never left as a bare str. ScannerTool
        # and Severity below both compare by equality across a String column but
        # NOT by ordering — `Severity.HIGH >= "high"` raises — and ordering is
        # the half M5, M6 and M8 use (ADR-0018 decision 2). mypy --strict catches
        # a bare str here only because this parameter is annotated with the ORM
        # model type; hydrating inline off session.execute()'s Result[Any] would
        # be Any -> Any and checked by nothing.
        source_tool=ScannerTool(model.source_tool),
        captured_at=model.captured_at,
    )


def _finding_to_domain(model: FindingModel, evidence: EvidenceModel) -> Finding:
    return Finding(
        id=model.id,
        project_id=model.project_id,
        source=ScannerTool(model.source),
        rule_id=model.rule_id,
        severity=Severity(model.severity),
        native_severity=model.native_severity,
        title=model.title,
        location=Location(
            file_path=model.file_path,
            start_line=model.start_line,
            end_line=model.end_line,
            package=model.package,
            installed_version=model.installed_version,
            url=model.url,
            http_method=model.http_method,
            parameter=model.parameter,
        ),
        evidence=_evidence_to_domain(evidence),
        cwe=model.cwe,
        owasp_category=model.owasp_category,
        cvss=model.cvss,
    )


# Severity ordering in SQL, DERIVED from Severity.rank rather than transcribed.
#
# This is ADR-0020 decision 1's problem in a second place: a domain rule and its
# SQL equivalent that can drift with nothing detecting it. There the answer was to
# make the SET clause a transcription and pin it with tests; here the rule is a
# pure function of the enum, so the SQL can be GENERATED from it and there is no
# second copy to keep honest at all.
#
# `{str(s): s.rank}` reads .rank directly. An `array_position(ARRAY[...], severity)`
# expression would have worked too and was the first shape considered, but it
# derives the rank from a list POSITION — one indirection away from the source, so
# a change to _RANK that reordered nothing would leave it silently stale. This
# cannot: every value here is the rank itself.
#
# else_=-1 sorts an unrecognised stored value last rather than NULL. Unreachable
# through ck_findings_severity; kept because a CHECK is a claim about the database
# and this is a claim about the query.
_SEVERITY_RANK_SQL = case(
    {str(member): member.rank for member in Severity},
    value=FindingModel.severity,
    else_=-1,
)


def _project_filters(
    project_id: str, min_severity: Severity | None, source: ScannerTool | None
) -> list[ColumnElement[bool]]:
    """The listing's WHERE clause, shared by `list_for_project` and `count_for_project`."""
    filters: list[ColumnElement[bool]] = [FindingModel.project_id == project_id]
    if min_severity is not None:
        # An IN over the members at or above this rank, computed here, rather than
        # a comparison against a rank expression in SQL. Two reasons, and neither
        # is style: `.rank` is only defined on Severity, so an uncoerced query
        # string raises AttributeError at construction instead of being compared
        # alphabetically (ADR-0018 decision 2's failure); and an IN over a handful
        # of literals is something an index on `severity` could serve, where a
        # CASE comparison never can.
        #
        # Note what this means for UNKNOWN, which ranks BELOW info: any
        # min_severity other than UNKNOWN itself excludes findings whose severity
        # no tool could determine. Stated in the port docstring and pinned by a
        # test, because it is surprising and it is a deliberate consequence of
        # honouring one total order rather than inventing a second.
        filters.append(
            FindingModel.severity.in_(
                [str(member) for member in Severity if member.rank >= min_severity.rank]
            )
        )
    if source is not None:
        filters.append(FindingModel.source == str(source))
    return filters


def _sighting_summary() -> LateralFromClause:
    """Per finding: when it was first and last seen, how often, and by which scan.

    ADR-0019 decision 1 refuses `last_seen_at`/`last_seen_scan_id` as COLUMNS on
    `findings` — a denormalized summary that can silently go stale in M9.1's path
    — while stating that both are `max()` over the sightings. This is that
    `max()`, computed per request, so there is nothing to go stale.

    **A LATERAL correlated to one finding, NOT a `DISTINCT ON` over the whole
    table, and the difference was measured rather than reasoned about.** The first
    version was a whole-table subquery merge-joined against the page. Postgres
    cannot push the page's 50 ids into it, so it seq-scanned all 300,000 sightings
    and sorted them on disk (22 MB, `external merge`) to serve one page:
    **763 ms**. Correlated, each row is an index scan of that finding's ~3
    sightings on `finding_sightings_pkey`'s leading column, 50 times.

    That measurement is also a warning about how it was nearly missed. The same
    query benchmarked at **8.8 ms** with sequential synthetic ids, because one
    project's findings then clustered at the head of the id-ordered scan and the
    merge join terminated early. Real ids are UUIDs (rule 9), so they do not
    cluster — the fast number described the id scheme, not the query. See
    ADR-0022 and `scripts/seed_findings_benchmark.py`.

    The window functions run over this finding's sightings before `LIMIT 1`, so
    `first_seen_at` and `sighting_count` cover the whole history while the row
    itself is the latest observation.

    **`scan_id DESC` is a tiebreak, not decoration.** Two scans of one project can
    be normalized within the same clock tick, and ordering by `observed_at` alone
    returns whichever row the plan happened to produce first — the same
    non-deterministic-representative mistake `_representative_key` exists to avoid
    and that ZAP's `instances[0]` is this project's record of.
    """
    return (
        select(
            FindingSightingModel.scan_id.label("last_seen_scan_id"),
            FindingSightingModel.observed_at.label("last_seen_at"),
            FindingSightingModel.match_count.label("latest_match_count"),
            func.min(FindingSightingModel.observed_at).over().label("first_seen_at"),
            func.count().over().label("sighting_count"),
        )
        .where(FindingSightingModel.finding_id == FindingModel.id)
        .order_by(
            FindingSightingModel.observed_at.desc(),
            FindingSightingModel.scan_id.desc(),
        )
        .limit(1)
        .lateral()
    )


def _sighting_to_domain(model: FindingSightingModel) -> FindingSighting:
    return FindingSighting(
        finding_id=model.finding_id,
        scan_id=model.scan_id,
        observed_at=model.observed_at,
        match_count=model.match_count,
    )


class PostgresFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, finding: Finding) -> Finding:
        # ON CONFLICT DO UPDATE on (project_id, dedup_hash), and the SET clause
        # is a TRANSCRIPTION of merge_observation rather than a second copy of
        # its policy. That works because the function's refresh set is total
        # except the two surrogate ids: it returns `replace(observed,
        # id=existing.id, evidence=replace(..., id=existing.evidence.id))`. So
        # "keep the id" is `id` being absent from set_, and "take everything else
        # from the observation" is every other mutable column reading EXCLUDED.
        #
        # Read-modify-write through merge_observation itself was the alternative
        # and is rejected for a concurrency window that is real rather than
        # theoretical: UNIQUE(scan_id) on normalization_runs bounds duplicate
        # jobs for ONE scan, not two different scans of the same project being
        # normalized at once — two pushes in quick succession produce exactly
        # that, and arq runs jobs concurrently. Both would SELECT nothing, both
        # would INSERT, and one would take an IntegrityError, which ADR-014
        # rejected because it leaves the session in a failed-transaction state.
        # See ADR-0020.
        insert_finding = insert(FindingModel).values(
            id=finding.id,
            project_id=finding.project_id,
            # The materialization of the derived property. There is no parameter
            # through which a caller could supply anything else, which is what
            # makes the column incapable of disagreeing with compute_dedup_hash
            # over the same row.
            dedup_hash=finding.dedup_hash,
            source=str(finding.source),
            rule_id=finding.rule_id,
            file_path=finding.location.file_path,
            package=finding.location.package,
            url=finding.location.url,
            http_method=finding.location.http_method,
            parameter=finding.location.parameter,
            severity=str(finding.severity),
            native_severity=finding.native_severity,
            title=finding.title,
            cwe=finding.cwe,
            owasp_category=finding.owasp_category,
            cvss=finding.cvss,
            start_line=finding.location.start_line,
            end_line=finding.location.end_line,
            installed_version=finding.location.installed_version,
        )
        statement = insert_finding.on_conflict_do_update(
            constraint="uq_findings_project_id_dedup_hash",
            set_={
                column: getattr(insert_finding.excluded, column) for column in _REFRESHED_COLUMNS
            },
        ).returning(FindingModel)
        # populate_existing, because the returned row must be the one the
        # database now holds: without it a second upsert in the same session
        # would be served the stale object already in the identity map, and this
        # method's whole contract is that it returns the RESOLVED finding.
        result = await self._session.execute(
            statement, execution_options={"populate_existing": True}
        )
        # Annotated, not inferred: session.execute() is typed Result[Any], so the
        # value arrives as Any and every enum reconstruction below it would go
        # unchecked. The annotation is what restores mypy --strict's grip.
        stored: FindingModel = result.scalars().one()

        insert_evidence = insert(EvidenceModel).values(
            id=finding.evidence.id,
            # The RESOLVED id, not the observation's — this is
            # merge_observation's inner `finding_id=existing.id`.
            finding_id=stored.id,
            scan_id=finding.evidence.scan_id,
            raw_payload=finding.evidence.raw_payload,
            source_tool=str(finding.evidence.source_tool),
            captured_at=finding.evidence.captured_at,
        )
        evidence_statement = insert_evidence.on_conflict_do_update(
            constraint="uq_evidence_finding_id",
            set_={
                column: getattr(insert_evidence.excluded, column)
                for column in _REFRESHED_EVIDENCE_COLUMNS
            },
        ).returning(EvidenceModel)
        evidence_result = await self._session.execute(
            evidence_statement, execution_options={"populate_existing": True}
        )
        stored_evidence: EvidenceModel = evidence_result.scalars().one()

        await self._session.flush()
        return _finding_to_domain(stored, stored_evidence)

    async def record_sighting(self, sighting: FindingSighting) -> None:
        # DO UPDATE, and the reason is idempotency rather than recency:
        # ARCHITECTURE.md §9 requires re-normalizing a scan to refresh rows
        # rather than add them, and an arq retry re-running every enabled scanner
        # is guaranteed (ADR-016 decision 1). Summing match_count would
        # double-count silently on every retry; DO NOTHING would leave a stale
        # count and never refresh observed_at. Overwriting with a complete total
        # is the only idempotent option — which makes "match_count is a total,
        # never an increment" a precondition on the caller. See
        # FindingRepositoryPort.record_sighting and ADR-0020.
        #
        # index_elements rather than a constraint name: the composite primary key
        # is unnamed, following ProjectMembership's migration.
        insert_sighting = insert(FindingSightingModel).values(
            finding_id=sighting.finding_id,
            scan_id=sighting.scan_id,
            observed_at=sighting.observed_at,
            match_count=sighting.match_count,
        )
        statement = insert_sighting.on_conflict_do_update(
            index_elements=["finding_id", "scan_id"],
            set_={
                "observed_at": insert_sighting.excluded.observed_at,
                "match_count": insert_sighting.excluded.match_count,
            },
        )
        await self._session.execute(statement)
        await self._session.flush()

    async def list_for_project(
        self,
        *,
        project_id: str,
        min_severity: Severity | None,
        source: ScannerTool | None,
        limit: int,
        offset: int,
    ) -> list[SightedFinding]:
        # The page is chosen FIRST, in its own subquery, and everything else joins
        # to those rows. Ordering and limiting in the outer query instead would
        # make the joins run before the LIMIT — which is how the first version of
        # this method came to aggregate every sighting in the database to return
        # fifty findings (763 ms at 300k sightings; see `_sighting_summary`).
        page = (
            select(FindingModel.id)
            .where(*_project_filters(project_id, min_severity, source))
            .order_by(_SEVERITY_RANK_SQL.desc(), FindingModel.dedup_hash)
            .limit(limit)
            .offset(offset)
            .subquery()
        )
        sightings = _sighting_summary()
        # An OUTER join to evidence with an explicit raise rather than an inner
        # join: every finding has evidence by construction (both rows are written
        # by the same upsert, in one transaction), and Finding.evidence is not
        # optional, so a missing row is unrepresentable in the domain. An inner
        # join would silently omit such a finding, which is the wrong failure — a
        # security finding disappearing from a response is worse than an error
        # saying the database is inconsistent. The sighting summary is joined the
        # same way and for the same reason: _persist writes the sighting in the
        # same transaction as the upsert, so a finding without one means something
        # wrote around this repository.
        #
        # The ORDER BY is repeated here because a subquery's ordering is not
        # guaranteed to survive a join — the inner one selects the page, this one
        # presents it, and at fifty rows the second sort is free.
        statement = (
            select(FindingModel, EvidenceModel, sightings)
            .join(page, page.c.id == FindingModel.id)
            .outerjoin(EvidenceModel, EvidenceModel.finding_id == FindingModel.id)
            .outerjoin(sightings, true())
            .order_by(_SEVERITY_RANK_SQL.desc(), FindingModel.dedup_hash)
        )
        result = await self._session.execute(statement)

        sighted: list[SightedFinding] = []
        for row in result.all():
            finding_model, evidence_model = row[0], row[1]
            if evidence_model is None:
                raise ValueError(
                    f"Finding '{finding_model.id}' has no evidence row — Evidence is 1:1 with "
                    f"Finding and both are written by the same upsert, so this means something "
                    f"wrote a finding outside the repository"
                )
            if row.sighting_count is None:
                raise ValueError(
                    f"Finding '{finding_model.id}' has no sightings — NormalizeScanUseCase "
                    f"records one in the same transaction as the upsert, so this means "
                    f"something wrote a finding outside the repository"
                )
            sighted.append(
                SightedFinding(
                    finding=_finding_to_domain(finding_model, evidence_model),
                    first_seen_at=row.first_seen_at,
                    last_seen_at=row.last_seen_at,
                    last_seen_scan_id=row.last_seen_scan_id,
                    sighting_count=row.sighting_count,
                    latest_match_count=row.latest_match_count,
                )
            )
        return sighted

    async def count_for_project(
        self, *, project_id: str, min_severity: Severity | None, source: ScannerTool | None
    ) -> int:
        # The same predicates as list_for_project, built by the same function
        # rather than retyped — a count that filtered differently from its listing
        # would be a `total` that silently disagrees with the page it describes.
        result = await self._session.execute(
            select(func.count())
            .select_from(FindingModel)
            .where(*_project_filters(project_id, min_severity, source))
        )
        return result.scalar_one()

    async def get_by_project_id(self, project_id: str) -> list[Finding]:
        # No sighting join and no severity ordering — see the port docstring for
        # why this survived M4.5's listing rather than being replaced by it.
        result = await self._session.execute(
            select(FindingModel, EvidenceModel)
            .outerjoin(EvidenceModel, EvidenceModel.finding_id == FindingModel.id)
            .where(FindingModel.project_id == project_id)
            .order_by(FindingModel.dedup_hash)
        )
        findings: list[Finding] = []
        for finding_model, evidence_model in result.all():
            if evidence_model is None:
                raise ValueError(
                    f"Finding '{finding_model.id}' has no evidence row — Evidence is 1:1 with "
                    f"Finding and both are written by the same upsert, so this means something "
                    f"wrote a finding outside the repository"
                )
            findings.append(_finding_to_domain(finding_model, evidence_model))
        return findings

    async def get_by_id(self, *, project_id: str, finding_id: str) -> Finding | None:
        # project_id is in the WHERE clause, not checked after the fetch. A
        # finding from another project and a finding that does not exist both
        # produce zero rows, so the caller cannot tell them apart and neither can
        # its 404 — which is what stops an id from one project being used to probe
        # which ids exist in another.
        result = await self._session.execute(
            select(FindingModel, EvidenceModel)
            .outerjoin(EvidenceModel, EvidenceModel.finding_id == FindingModel.id)
            .where(FindingModel.id == finding_id, FindingModel.project_id == project_id)
        )
        row = result.one_or_none()
        if row is None:
            return None
        finding_model, evidence_model = row
        if evidence_model is None:
            raise ValueError(
                f"Finding '{finding_model.id}' has no evidence row — Evidence is 1:1 with "
                f"Finding and both are written by the same upsert, so this means something "
                f"wrote a finding outside the repository"
            )
        return _finding_to_domain(finding_model, evidence_model)

    async def get_sightings_by_finding_id(self, finding_id: str) -> list[FindingSighting]:
        result = await self._session.execute(
            select(FindingSightingModel)
            .where(FindingSightingModel.finding_id == finding_id)
            .order_by(FindingSightingModel.scan_id)
        )
        return [_sighting_to_domain(model) for model in result.scalars()]
