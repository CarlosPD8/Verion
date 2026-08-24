from typing import Protocol


class ProjectAccessPort(Protocol):
    """Whether a caller may read a project's data — the verdict, not the evidence.

    **The only port another module should use to authorize against a project**,
    and the reason it exists next to `ProjectMembershipRepositoryPort` rather than
    instead of it. That one is *persistence*: it returns `ProjectMembership` rows.
    A consumer in another module reading it would thereby know that authorization
    means "a membership row exists" — this module's domain knowledge, crossing a
    boundary through a repository. Contract-legal under rule 3 and ADR-0010, and
    design-wrong for the same reason ADR-0017 made the handoff port take
    primitives so no domain type crossed, and ADR-0018 scoped `shared_kernel/` to
    vocabulary that is *compared* rather than structures that are *transported*.

    A `bool` crosses the verdict. `projects` keeps the rule, as
    `domain/authorization.may_read`.

    **One method, and that is what settles 404-versus-403 for every consumer.**
    A `project_exists` companion was considered and rejected: a caller holding
    both would rebuild the project-existence leak on its own side, and the policy
    for what a non-member sees would end up in the consuming module rather than
    here. With one method there is no vocabulary for "which reason", so a consumer
    can only answer 404 — a non-member cannot distinguish an existing project from
    an absent one. The policy is expressed structurally rather than by convention.

    That deviates from this module's own routes, which still answer 403 for an
    existing project and 404 for an absent one. Deliberate, argued in ADR-0022,
    and registered as **G17** (the divergence) and **G18** (the pre-existing leak
    those routes carry), both assigned to M10.2 — because the concealment above is
    only as good as the least careful sibling route, and today one of them tells.
    """

    async def may_read_project(self, *, project_id: str, user_id: str) -> bool:
        """True iff this user may read this project's data.

        False covers both "no such project" and "not a member", indistinguishably
        and on purpose. Implementations must not widen the return type to say
        which.
        """
        ...
