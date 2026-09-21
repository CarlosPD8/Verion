from verion.modules.brief.domain.brief_generation import BriefGeneration
from verion.modules.brief.domain.exceptions import BriefGenerationAccessDenied
from verion.modules.brief.ports.brief_generation_repository import BriefGenerationRepositoryPort

# `projects`' verdict port, never its persistence ports (ADR-0022 decision 2).
from verion.modules.projects.ports.project_access import ProjectAccessPort


class GetBriefGenerationUseCase:
    """One generation's state, for the caller who asked for it. M8.6, ADR-0038 decision 8.

    **Two conditions, and the second is the one that is easy to leave out.**

    1. `may_read_project` — the project verdict, as every read route in this project takes it.
    2. **An actor match**: the generation is readable only by the caller who requested it. Every
       other member of the same project gets the same 404 a stranger does.

    **The actor match is what makes decision 6's unobservability real rather than asserted.** A
    caller whose membership is revoked between enqueue and run has their generation terminated
    `failed`/`surface_changed`; condition 1 then refuses them, and condition 2 refuses everyone
    else. So the row that records what was in substance a denial is readable by nobody while the
    revocation stands, which is why the vocabulary needs no fourth `failure_kind` naming access.

    **It authorizes on its own and inherits no verdict from the POST.** The POST's check happened
    at enqueue time, possibly long before; a poll that trusted it would serve a revoked caller.

    **One 404 for every refusal** (**G17**): an absent project, a non-member, an absent
    generation id, a generation of another project, and another member's generation are one
    outcome with one message.
    """

    def __init__(
        self,
        project_access: ProjectAccessPort,
        generations: BriefGenerationRepositoryPort,
    ) -> None:
        self._project_access = project_access
        self._generations = generations

    async def execute(
        self, *, project_id: str, user_id: str, generation_id: str
    ) -> BriefGeneration:
        # Before the read, so a refused caller learns nothing from what the repository does —
        # `ListSecurityBriefsUseCase`'s ordering, for its reason.
        if not await self._project_access.may_read_project(project_id=project_id, user_id=user_id):
            raise BriefGenerationAccessDenied(f"No readable project with id '{project_id}'")

        generation = await self._generations.get(project_id=project_id, generation_id=generation_id)
        # `is None` covers the absent id and the other project's generation, which the
        # repository's project-scoped query already merged. The `user_id` comparison is the
        # actor match, and it is HERE rather than in the query because it is an authorization
        # rule: a repository returning rows only for their requester would make that rule a
        # property of a SELECT nobody reads as policy.
        if generation is None or generation.user_id != user_id:
            raise BriefGenerationAccessDenied(
                f"No brief generation with id '{generation_id}' in project '{project_id}'"
            )
        return generation
