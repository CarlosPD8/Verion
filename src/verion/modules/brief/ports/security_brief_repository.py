from typing import Protocol

from verion.modules.brief.domain.security_brief import SecurityBrief


class SecurityBriefRepositoryPort(Protocol):
    """Persist and read Security Briefs. Async by rule 7. M7.2, ADR-0033.

    **Append-only**: there is no update and no upsert. Two Briefs for one member set are two
    rows, because regenerating after a rescore, or for a different narration, is legitimate
    (ADR-0033 decision 3).
    """

    async def add(self, brief: SecurityBrief) -> None: ...

    async def list_for_project(
        self, *, project_id: str, limit: int, offset: int
    ) -> list[SecurityBrief]:
        """A page of the project's Briefs, newest `generated_at` first, then by `id` ascending.

        Raises `StoredBriefUnreadable` if any row on the page cannot be read, rather than
        omitting it.
        """
        ...

    async def count_for_project(self, project_id: str) -> int:
        """Every Brief the project has.

        A second statement, so under READ COMMITTED a concurrent generation can leave it one
        ahead of the page (ADR-0022 decision 1's cost, carried here too).
        """
        ...
