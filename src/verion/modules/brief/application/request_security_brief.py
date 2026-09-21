from verion.modules.brief.domain.brief_generation import BriefGeneration, BriefGenerationStatus
from verion.modules.brief.domain.exceptions import BriefGenerationAccessDenied
from verion.modules.brief.ports.brief_generation_queue import BriefGenerationQueuePort
from verion.modules.brief.ports.brief_generation_repository import BriefGenerationRepositoryPort

# `projects`' verdict port, never its persistence ports (ADR-0022 decision 2).
from verion.modules.projects.ports.project_access import ProjectAccessPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class RequestSecurityBriefUseCase:
    """Accept a request to generate a Brief, and answer before the work runs. M8.6, ADR-0038.

    **This is the first of TWO authorization gates, in two processes** (decision 4). This one
    runs at enqueue time and asks `ProjectAccessPort.may_read_project` directly; the job runs the
    second at execution time, by passing the stored `user_id` into `explainable_risk`.

    **Why a route check at all, when the job checks too.** Without it the route promises a Brief
    to a caller who may not read the project, spends a job on an unauthorized request — an
    amplification against the provider bill that **G100** records as unbounded — and makes an
    authorization failure indistinguishable from a work failure at the poll.

    **Order: mint, write, ask for the job** — `TriggerScanUseCase`'s, with the enqueue deferred
    past the commit by the adapter (ADR-0035 decision 5). The id is minted here, before the work,
    because a 202 has to carry something addressable and `SecurityBrief`'s own id does not exist
    until after both provider calls.

    **It does not resolve the surface.** `finding_ids` is stored as the caller sent it and is not
    checked against any current Risk, because that check is `explainable_risk`'s and it needs the
    verdict, the correlation and the scoring — the whole of what moved to the worker. A set that
    no longer names a Risk therefore reaches the poll as `surface_changed` rather than a 404
    (decision 6), which is the one user-visible consequence of ADR-0033 decision 1's selection
    moving off the request path.
    """

    def __init__(
        self,
        project_access: ProjectAccessPort,
        generations: BriefGenerationRepositoryPort,
        queue: BriefGenerationQueuePort,
        clock: ClockPort,
        ids: IdGeneratorPort,
    ) -> None:
        self._project_access = project_access
        self._generations = generations
        self._queue = queue
        self._clock = clock
        self._ids = ids

    async def execute(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> BriefGeneration:
        # Before anything is written or queued, so a refused caller costs no row and no job.
        # The message is the one `ListSecurityBriefsUseCase` raises, verbatim, so this module's
        # two project-level denials are indistinguishable from each other as well as from an
        # absent project (**G17**).
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise BriefGenerationAccessDenied(f"No readable project with id '{project_id}'")

        generation = BriefGeneration(
            id=self._ids.new_id(),
            project_id=project_id,
            user_id=user_id,
            finding_ids=finding_ids,
            status=BriefGenerationStatus.PENDING,
            brief_id=None,
            failure_kind=None,
            requested_at=self._clock.now(),
        )
        await self._generations.add(generation)
        # The adapter holds this until the transaction commits. Asked for AFTER the add, so the
        # registration order matches the write order even though neither has happened yet.
        await self._queue.enqueue_brief_generation(generation.id)
        return generation
