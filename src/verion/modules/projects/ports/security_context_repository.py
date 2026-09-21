from typing import Protocol

from verion.modules.projects.domain.security_context import SecurityContext


class SecurityContextRepositoryPort(Protocol):
    """Persistence for a project's Security Context. One row per project (M8.7, ADR-0039).

    **Two writers with different ownership, which no other one-per-project port here has**,
    and the reason it does not simply carry `get_by_project_id` + `upsert`: detect owns the
    detected fields, `PATCH` owns `exposure_tags`. A single shared `upsert` cannot serve
    both — one `set_` cannot both omit `exposure_tags`, which ADR-0039 decision 3 requires,
    and let `PATCH` write them.

    Async by rule 7, as every port in this package is.
    """

    async def upsert_detected(self, context: SecurityContext) -> None:
        """Inserts, or refreshes the DETECTED fields of the existing row for that project.

        Named for what it owns. **`exposure_tags` is not among them** (ADR-0039 decision
        3): `BuildSecurityContextUseCase` builds its context with `exposure_tags=[]`, so
        a write that carried the column would erase the owner's confirmed tags on every
        re-detect — the step M8.4's first bullet exists to perform. The adapter's `set_`
        omits it for exactly the reason it omits `id`: this write does not own it.
        """
        ...

    async def get_by_project_id(self, project_id: str) -> SecurityContext | None: ...

    async def add(self, context: SecurityContext) -> None:
        """`PATCH`'s insert branch, for a project that has no context yet.

        **The read-then-add in `UpdateExposureTagsUseCase` is not atomic, and from M8.7
        that has a visible consequence.** With no constraint, two concurrent `PATCH`es to
        a context-less project created two rows — the defect ADR-0039 fixes — and neither
        failed. Under `uq_security_contexts_project_id` the second now raises
        `IntegrityError`. That is the trade, and it is intended: a loud failure replacing
        a silent corruption. Recorded here because it is a behaviour change on a path
        M8.7 otherwise does not touch, and unwritten it would surface later as a surprise.
        """
        ...

    async def update(self, context: SecurityContext) -> None:
        """`PATCH`'s update branch: writes `exposure_tags` by id, the one field detect
        does not own."""
        ...
