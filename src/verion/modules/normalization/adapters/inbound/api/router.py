from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from verion.modules.normalization.adapters.inbound.api.schemas import (
    EvidenceMetadataResponse,
    EvidenceResponse,
    FindingResponse,
    LocationResponse,
    NormalizationRunResponse,
    NormalizationStateResponse,
    ProjectFindingsResponse,
)
from verion.modules.normalization.application.get_finding_evidence import payload_is_truncated
from verion.modules.normalization.application.list_project_findings import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    ProjectFindings,
)
from verion.modules.normalization.domain.exceptions import FindingNotFound, ProjectAccessDenied
from verion.modules.normalization.domain.finding import SightedFinding
from verion.platform.di import (
    CurrentUserIdDep,
    GetFindingEvidenceUseCaseDep,
    ListProjectFindingsUseCaseDep,
)
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

router = APIRouter()


def _coerce_severity(value: str | None) -> Severity | None:
    """The one place a query string becomes a `Severity`. See ADR-0018 decision 2.

    **Explicit rather than `Annotated[Severity | None, Query()]`**, and the
    difference is not style. Pydantic would coerce before the handler body runs,
    so the answer to "where does the coercion happen" becomes "invisibly, in the
    framework" — and the hazard being defended against (a bare `str` reaching a
    `Severity` comparison, where `>=` raises while `==` silently works) would then
    be held off by a framework detail rather than by a line a test can point at.
    It also lets the 422 name the alternatives, the same reason
    `UpdateScannerConfigRequest.enabled_tools` is `list[str]`.

    Case-sensitive: `Severity("HIGH")` raises. One canonical spelling.
    """
    if value is None:
        return None
    try:
        return Severity(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"Unknown severity '{value}'. Known severities: "
                f"{', '.join(str(member) for member in Severity)}"
            ),
        ) from exc


def _coerce_source(value: str | None) -> ScannerTool | None:
    if value is None:
        return None
    try:
        return ScannerTool(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"Unknown scanner '{value}'. Known scanners: "
                f"{', '.join(str(member) for member in ScannerTool)}"
            ),
        ) from exc


def _finding_response(sighted: SightedFinding) -> FindingResponse:
    finding = sighted.finding
    return FindingResponse(
        id=finding.id,
        source=str(finding.source),
        rule_id=finding.rule_id,
        severity=str(finding.severity),
        native_severity=finding.native_severity,
        title=finding.title,
        cwe=finding.cwe,
        owasp_category=finding.owasp_category,
        cvss=finding.cvss,
        location=LocationResponse(
            file_path=finding.location.file_path,
            start_line=finding.location.start_line,
            end_line=finding.location.end_line,
            package=finding.location.package,
            installed_version=finding.location.installed_version,
            url=finding.location.url,
            http_method=finding.location.http_method,
            parameter=finding.location.parameter,
        ),
        # Metadata only. `raw_payload` is reachable at the evidence route and
        # nowhere else — rule 12, and the reason this schema exists (rule 10).
        evidence=EvidenceMetadataResponse(
            scan_id=finding.evidence.scan_id,
            source_tool=str(finding.evidence.source_tool),
            captured_at=finding.evidence.captured_at,
            payload_chars=len(finding.evidence.raw_payload),
        ),
        first_seen_at=sighted.first_seen_at,
        last_seen_at=sighted.last_seen_at,
        last_seen_scan_id=sighted.last_seen_scan_id,
        sighting_count=sighted.sighting_count,
        latest_match_count=sighted.latest_match_count,
    )


def _project_findings_response(findings: ProjectFindings) -> ProjectFindingsResponse:
    latest = findings.latest_run
    return ProjectFindingsResponse(
        items=[_finding_response(item) for item in findings.items],
        total=findings.total,
        limit=findings.limit,
        offset=findings.offset,
        normalization=NormalizationStateResponse(
            latest_run=None
            if latest is None
            else NormalizationRunResponse(
                scan_id=latest.scan_id,
                status=str(latest.status),
                requested_at=latest.requested_at,
                started_at=latest.started_at,
                finished_at=latest.finished_at,
                failure_reason=latest.failure_reason,
            ),
            unfinished_runs=findings.unfinished_runs,
        ),
    )


@router.get(
    "/{project_id}/findings",
    status_code=status.HTTP_200_OK,
    response_model=ProjectFindingsResponse,
)
async def list_project_findings(
    project_id: str,
    user_id: CurrentUserIdDep,
    use_case: ListProjectFindingsUseCaseDep,
    min_severity: Annotated[str | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectFindingsResponse:
    """A project's findings, most severe first.

    `min_severity` filters by RANK, so it means "this severity or higher". One
    consequence is worth knowing before it surprises somebody: `UNKNOWN` ranks
    below `INFO`, so any value other than `unknown` **excludes findings whose
    severity no tool could determine**. `min_severity=unknown` is a no-op that
    returns everything.

    Ordered by severity rank descending, then by identity as a total tiebreak, so
    the order is deterministic regardless of insertion order. `UNKNOWN` sorts
    last, which is the display convention `Severity` itself declares.

    Findings are project-scoped and durable: this is every finding ever recorded
    for the project, not the latest scan's. `last_seen_at` says when each was last
    observed; nothing here claims a finding is resolved.
    """
    try:
        findings = await use_case.execute(
            project_id=project_id,
            user_id=user_id,
            min_severity=_coerce_severity(min_severity),
            source=_coerce_source(source),
            limit=limit,
            offset=offset,
        )
    except ProjectAccessDenied as exc:
        # 404, not 403 — for a project that does not exist AND for one the caller
        # is not a member of, indistinguishably. A 403 would confirm the project
        # exists, which on a findings endpoint is project enumeration against the
        # most sensitive read in the system. `ProjectAccessPort` has no vocabulary
        # for the difference, so this cannot accidentally become a 403.
        #
        # This diverges from `projects`' own routes, which still answer 403 —
        # deliberate, argued in ADR-0022, and registered as G17/G18 for M10.2,
        # because a caller can recover existence by asking a sibling route.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return _project_findings_response(findings)


@router.get(
    "/{project_id}/findings/{finding_id}/evidence",
    status_code=status.HTTP_200_OK,
    response_model=EvidenceResponse,
)
async def get_finding_evidence(
    project_id: str,
    finding_id: str,
    user_id: CurrentUserIdDep,
    use_case: GetFindingEvidenceUseCaseDep,
) -> EvidenceResponse:
    """The verbatim tool output for one finding (FR-9).

    **This route returns scanned content, and it is the only one that does.** The
    payload is a copy of one element of a scanner's report; for Semgrep that
    includes the matched source line, and secret-detection rules match secrets. It
    is a route of its own rather than a field on the listing so that reading it is
    a deliberate, individually-addressed act rather than a side effect of asking
    for a list — see `GetFindingEvidenceUseCase`, and G7 for the configuration
    change that would make it live.

    It is also this project's first response whose body size is bounded only by
    `MAX_RAW_PAYLOAD_CHARS` (20 KB) rather than by a fixed schema, which makes it
    the natural first candidate for M10.2's rate limiting.

    `raw_payload` is opaque. Parse it only when `payload_truncated` is false.
    """
    try:
        evidence = await use_case.execute(
            project_id=project_id, user_id=user_id, finding_id=finding_id
        )
    except ProjectAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except FindingNotFound as exc:
        # Also 404 for a finding that exists in ANOTHER project, for the same
        # reason the access failure is: a caller authorized for one project must
        # not be able to probe which finding ids exist in another.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return EvidenceResponse(
        finding_id=evidence.finding_id,
        scan_id=evidence.scan_id,
        source_tool=str(evidence.source_tool),
        captured_at=evidence.captured_at,
        raw_payload=evidence.raw_payload,
        payload_truncated=payload_is_truncated(evidence.raw_payload),
    )
