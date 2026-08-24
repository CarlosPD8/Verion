from dataclasses import dataclass

from verion.modules.normalization.domain.exceptions import ProjectAccessDenied
from verion.modules.normalization.domain.finding import SightedFinding
from verion.modules.normalization.domain.normalization_run import NormalizationRun
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort
from verion.modules.normalization.ports.normalization_run_repository import (
    NormalizationRunRepositoryPort,
)

# `projects`' PORT, never its domain or adapters — the same legality
# NormalizeScanUseCase relies on for `scanning`, and the reason the
# cross-module-normalization contract sets allow_indirect_imports.
#
# Note WHICH port: ProjectAccessPort, not ProjectMembershipRepositoryPort. The
# second is contract-legal too and is the wrong one. It is a persistence port, so
# reading it would mean this module knowing that authorization means "a membership
# row exists" — `projects`' domain knowledge crossing a boundary through a
# repository, and one copy of an authorization rule per consuming module. This
# port hands over the verdict instead. See ADR-0022 decision 2.
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity

# Paging bounds. The maximum exists because each item carries an evidence row's
# metadata and a sighting aggregate, and because `total` gives a client the
# information it needs to page rather than to ask for everything at once.
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


@dataclass(frozen=True)
class ProjectFindings:
    """One page of a project's findings, plus what it says about its own completeness.

    Deliberately NOT in `domain/`. `limit`, `offset` and `total` are artifacts of
    how a caller asked the question rather than facts about the findings, which is
    the criterion `SightedFinding`'s docstring states and this type fails. It
    lives here, in `application/`, as a use case's return value — the layer whose
    job is exactly to assemble an answer to a request.
    """

    items: list[SightedFinding]
    total: int
    limit: int
    offset: int
    # Both nullable-ish halves of "can this list be trusted to be complete?".
    # See the ports' docstrings for why the count is the load-bearing one.
    latest_run: NormalizationRun | None
    unfinished_runs: int


class ListProjectFindingsUseCase:
    """A project's findings, with each one's sighting history and the pipeline's state.

    **Project-scoped and scan-independent, deliberately.** "The findings for this
    project" is not "the findings in the latest scan", and this use case answers
    only the first. It exposes when a finding was last seen and never whether it
    is still present, because turning the first into the second requires knowing
    which tools SUCCEEDED in the scan being compared against (ADR-0019's
    Consequences) — and without that, one failed Trivy run silently marks every
    dependency finding in the project resolved. That is M9.1's, together with the
    scan-first index the query would need.

    **The response says something about its own completeness**, which is the
    other half of this use case's job and the reason it reaches for
    `NormalizationRunRepositoryPort` at all. A project whose last three scans
    failed to normalize returns an empty or short list that is otherwise
    indistinguishable from a clean project (G15). `unfinished_runs` is what makes
    the difference visible; nothing else in the system surfaces it.
    """

    def __init__(
        self,
        project_access: ProjectAccessPort,
        findings: FindingRepositoryPort,
        normalization_runs: NormalizationRunRepositoryPort,
    ) -> None:
        self._project_access = project_access
        self._findings = findings
        self._normalization_runs = normalization_runs

    async def execute(
        self,
        *,
        project_id: str,
        user_id: str,
        min_severity: Severity | None = None,
        source: ScannerTool | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> ProjectFindings:
        """Authorize first, then read. The order is the security property.

        The access check is the first statement, before any repository is touched
        — the gate placement ADR-0013 established for the SSRF validators and for
        the same reason: a check that runs after a read is a check that can be
        skipped by a refactor without anything failing. A fake repository that
        raises when touched pins it.

        `min_severity` and `source` arrive already coerced. They are typed as the
        enums, not `str`, so `mypy --strict` rejects an uncoerced query parameter
        here — which is what stops ADR-0018 decision 2's failure (a `Severity`
        compared against a bare string) from reaching the repository at all.
        """
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            # One message for both "no such project" and "not a member". The port
            # cannot tell them apart and neither should this — see
            # ProjectAccessDenied.
            raise ProjectAccessDenied(f"No readable project with id '{project_id}'")

        items = await self._findings.list_for_project(
            project_id=project_id,
            min_severity=min_severity,
            source=source,
            limit=limit,
            offset=offset,
        )
        total = await self._findings.count_for_project(
            project_id=project_id, min_severity=min_severity, source=source
        )
        return ProjectFindings(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            latest_run=await self._normalization_runs.get_latest_by_project_id(project_id),
            unfinished_runs=await self._normalization_runs.count_unfinished_by_project_id(
                project_id
            ),
        )
