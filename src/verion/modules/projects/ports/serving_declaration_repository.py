from typing import Protocol

from verion.modules.projects.domain.serving_declaration import ServingDeclaration


class ServingDeclarationRepositoryPort(Protocol):
    """Persistence for ADR-0028 decision 1's declaration. One row per project.

    **This is a persistence port and deliberately not the verdict port.** ADR-0028
    decision 4's `ServingDeclarationPort` — the one-method `bool` that lets
    `correlation` read the rule's answer without holding a copy of the rule — is a
    different port that ships at M5.6 with its consumer, and **G48** records that
    gap on purpose. A consumer in another module must not reach this one instead:
    it returns the entity, so reading it would put the comparison in the consuming
    module, which is exactly what `ProjectAccessPort`'s docstring argues against for
    `ProjectMembershipRepositoryPort`.

    Async by rule 7, as every port in this package is.
    """

    async def get_by_project_id(self, project_id: str) -> ServingDeclaration | None:
        """None means "never declared", and there is no second absence to confuse it
        with — unlike `ScannerConfigRepositoryPort.get_by_project_id`, where "never
        configured" and "nothing enabled" are different states. A declaration either
        exists or does not; whether an existing one is still *in force* is
        `domain/serving_declaration.declaration_in_force`, never this method."""
        ...

    async def upsert(self, declaration: ServingDeclaration) -> None:
        """Inserts, or replaces the existing row for the same project_id.

        Upsert rather than add/update, on `ScannerConfigRepositoryPort.upsert`'s
        precedent and for its reason: there is exactly one row per project, and an
        owner re-declaring after a configuration change should not have to know
        whether the project has ever been declared before. Re-declaring is the
        expected act rather than an edge case — ADR-0028 decision 2 accepts that a
        cosmetic edit voids a declaration, which makes re-declaration routine.
        """
        ...
