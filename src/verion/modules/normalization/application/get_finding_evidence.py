import json

from verion.modules.normalization.domain.exceptions import FindingNotFound, ProjectAccessDenied
from verion.modules.normalization.domain.finding import Evidence
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort
from verion.modules.projects.ports.project_access import ProjectAccessPort


def payload_is_truncated(raw_payload: str) -> bool:
    """Whether this payload is an INCOMPLETE PREFIX of its source element.

    **Named for the fact it asserts, not for the test it runs, and the difference
    is the whole point of this docstring.** A reader who saw
    `payload_parses_as_json` would take it as permission to `JSON.parse`; what a
    caller actually needs to know is whether the thing it is looking at is the
    whole element. Those are two different facts that happen to coincide today.

    They coincide because the only lossy step is a character slice: all three
    mappers build `raw_payload` with `json.dumps` and then apply
    `[:MAX_RAW_PAYLOAD_CHARS]`, so a payload that fails to parse is one that was
    cut, and a payload that parses is whole.

    **They stop coinciding under exactly one future change**, which is why G16
    exists: if a mapper ever truncates at an ELEMENT boundary instead — dropping
    whole instances from a ZAP alert, say — the result would parse while still
    being incomplete, and this function would report `False` for a truncated
    payload. That is a silent wrong answer, so the trigger is registered rather
    than left in a comment: any change to how a mapper truncates.

    Two alternatives rejected. `len(raw_payload) == MAX_RAW_PAYLOAD_CHARS`
    *fabricates* truncation for a payload that happens to land exactly on the cap
    — reporting an event that did not happen, which is the failure ADR-0019's
    principle ranks worst. A stored `Evidence.truncated` column would be exact,
    and is refused because it is a column, a domain field and a migration for a
    state that has never occurred: measured across the three committed fixtures,
    the largest payload ever produced is 9,888 chars against a 20,000 cap, so the
    slice has never fired. That is ADR-016 decision 3's shape, and ADR-0021
    refused it again for `skipped_count`.
    """
    try:
        json.loads(raw_payload)
    except ValueError:
        return True
    return False


class GetFindingEvidenceUseCase:
    """The verbatim tool output for one finding — FR-9's link, followed.

    **This is the rule-12 surface of the whole module, and it is handled here
    rather than inherited.** `raw_payload` is a verbatim copy of one element of a
    scanner's output: for Semgrep that includes `extra.lines`, which is normally
    the matched source line, and secret-detection rules match secrets. The listing
    endpoint deliberately does not return it — a response carrying every finding's
    scanned source is a source-code export with nothing in its signature saying
    so — so this route is the one place it crosses the boundary, one finding at a
    time, at a URL of its own.

    **It is inert today by accident, not by design, and that accident is
    registered.** Anonymous Semgrep OSS redacts `extra.lines` to the literal
    string `"requires login"` and this repo sets no `SEMGREP_APP_TOKEN` anywhere.
    Adding one — for better rules, or telemetry — arms this route with no code
    change and no review. That is **G7**, whose `Blocks-if-unresolved:` names this
    use case.

    FR-9 asks that every Risk and Brief "link back to" the tool output that
    produced it. An addressable route is that link. Reading FR-9 as "return the
    payload inline everywhere" is convenience rather than the requirement, and it
    is the reading that would have put 71 KB of scanned source into a listing of
    24 findings.
    """

    def __init__(self, project_access: ProjectAccessPort, findings: FindingRepositoryPort) -> None:
        self._project_access = project_access
        self._findings = findings

    async def execute(self, *, project_id: str, user_id: str, finding_id: str) -> Evidence:
        """Authorize the project, then fetch the finding scoped to it.

        Two gates, and the second is not redundant. The first says the caller may
        read *this project*; the second says the finding is *in* it. Without the
        second, a caller authorized for project A could pass a finding id from
        project B and read another tenant's scanned source — and `get_by_id` puts
        the project in its WHERE clause rather than checking after the fetch, so
        "not yours" and "does not exist" are the same zero rows.
        """
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise ProjectAccessDenied(f"No readable project with id '{project_id}'")

        finding = await self._findings.get_by_id(project_id=project_id, finding_id=finding_id)
        if finding is None:
            raise FindingNotFound(f"No finding with id '{finding_id}' in project '{project_id}'")
        return finding.evidence
