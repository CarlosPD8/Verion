from typing import Protocol


class ProjectAccessPort(Protocol):
    """What a caller may do with a project — the verdicts, not the evidence.

    **The only port another module should use to authorize against a project**,
    and the reason it exists next to `ProjectMembershipRepositoryPort` rather than
    instead of it. That one is *persistence*: it returns `ProjectMembership` rows.
    A consumer in another module reading it would thereby know that authorization
    means "a membership row exists" — this module's domain knowledge, crossing a
    boundary through a repository. Contract-legal under rule 3 and ADR-0010, and
    design-wrong for the same reason ADR-0017 made the handoff port take
    primitives so no domain type crossed, and ADR-0018 scoped `shared_kernel/` to
    vocabulary that is *compared* rather than structures that are *transported*.

    A `bool` crosses each verdict. `projects` keeps the rules, as
    `domain/authorization.may_read` and `domain/authorization.may_manage`.

    **One method per verdict, and never a method per reason — that is what settles
    404-versus-403 for every consumer.** A `project_exists` companion was considered
    and rejected: a caller holding it would rebuild the project-existence leak on
    its own side, and the policy for what a non-member sees would end up in the
    consuming module rather than here. Each verdict is `False` for an absent project
    and for a caller it does not permit, indistinguishably, so a consumer can only
    answer 404. A second verdict does not reopen the leak: a caller told it may read
    and may not manage is a member, who already knows the project exists. ADR-0022
    decision 2, amended 2026-09-19 by ADR-0035 decision 2.

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

    async def may_manage_project(self, *, project_id: str, user_id: str) -> bool:
        """True iff this user may take an owner-class action on this project.

        Starting a scan is one (ADR-0035). False covers "no such project", "not a
        member" and "a member who is not an owner", indistinguishably and on purpose,
        under the same rule as `may_read_project`.
        """
        ...
