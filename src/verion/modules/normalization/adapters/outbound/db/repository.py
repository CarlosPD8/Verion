from datetime import datetime

from sqlalchemy import select
from sqlalchemy import update as sqlalchemy_update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

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

    async def get_by_project_id(self, project_id: str) -> list[Finding]:
        # Ordered by dedup_hash so the result is deterministic regardless of
        # insertion order — the same total order collapse_by_identity returns in.
        #
        # An OUTER join with an explicit raise rather than an inner join: every
        # finding has evidence by construction (both rows are written by the same
        # upsert, in one transaction), and Finding.evidence is not optional, so a
        # missing row is unrepresentable in the domain. An inner join would
        # silently omit such a finding from a listing, which is the wrong failure
        # — a security finding disappearing from a response is worse than an
        # error saying the database is inconsistent.
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

    async def get_sightings_by_finding_id(self, finding_id: str) -> list[FindingSighting]:
        result = await self._session.execute(
            select(FindingSightingModel)
            .where(FindingSightingModel.finding_id == finding_id)
            .order_by(FindingSightingModel.scan_id)
        )
        return [_sighting_to_domain(model) for model in result.scalars()]
