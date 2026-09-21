from typing import Protocol

from verion.modules.projects.domain.project import ConnectedRepo


class ConnectedRepoRepositoryPort(Protocol):
    async def upsert(self, connected_repo: ConnectedRepo) -> None:
        """Inserts, or replaces the existing row for the same project_id.

        Upsert rather than add/update, on `ScannerConfigRepositoryPort.upsert`'s and
        `ServingDeclarationRepositoryPort.upsert`'s precedent and for their reason:
        there is exactly one row per project (M8.7, ADR-0039 decision 4), and an owner
        re-connecting should not have to know whether the project has ever been
        connected before. Re-connecting is the expected act rather than an edge case —
        it is the only way to correct a repository connected by mistake, and under
        ADR-0039 decision 9 the only way out for a row written with a credential in its
        URL (G60).

        **There is deliberately no `add`.** Keeping one would leave a second write path
        that now raises `IntegrityError` instead of replacing — a future writer reaching
        for it would meet the exact failure this port's constraint exists to fix,
        renamed and with no diagnosis.
        """
        ...

    async def get_by_id(self, connected_repo_id: str) -> ConnectedRepo | None:
        """No caller in `src/`, and kept deliberately rather than by inattention.
        ADR-0039 decision 4 records the absence as an observation supporting the
        id-preserving upsert — nothing navigates by this id, so reusing the stored one
        reaches no code path. That is not authority to delete the method, which would be
        a second decision inside the commit that resolves G51 and G55."""
        ...

    async def get_by_project_id(self, project_id: str) -> ConnectedRepo | None: ...

    async def get_by_url(self, url: str) -> ConnectedRepo | None:
        """Keyed on the URL and NOT on a project, so `uq_connected_repos_project_id`
        does not constrain it: two *different* projects connecting the same repository
        still make this raise, for both of them, on the webhook path. That is **G102**,
        a separate gap that M8.7's constraint does not close (ADR-0039 decision 8)."""
        ...
