from typing import Protocol


class ServingDeclarationPort(Protocol):
    """Whether a project's scanned URL is declared to serve its scanned tree — the verdict only.

    ADR-0028 decision 4, shipped at M5.6 commit 3 with its consumer (**G48**). The shape is
    `ProjectAccessPort`'s and deliberately not M5.4's: a `bool` crosses, and `projects` keeps
    the rule as `domain/serving_declaration.declaration_in_force`. Handing `correlation` the
    declaration, the `ScannerConfig` and the `ConnectedRepo` instead would put a copy of that
    rule one attribute access away in a module that must not hold one (rule 3).

    **Read from `correlation/application/`, never from `correlation/domain/`.**
    `layers-correlation` forbids the second, and `cross-module-correlation` does not forbid
    `projects.ports`, so the use case beside `ProjectAccessPort`'s call is the one legal site.

    **What `True` means, and it is narrower than it reads.** A person declared that this URL
    serves this repository and branch, and none of the three values has been edited since.
    The declaration voids on reconfiguration and never on drift (ADR-0028 decision 2): it
    does not assert which revision the deployment runs, and nothing in the system observes
    that — **G47**.

    Async by rule 7: evaluating the verdict reads three rows.
    """

    async def url_serves_scanned_tree(self, *, project_id: str) -> bool:
        """True iff the project's declaration exists and is in force.

        False covers "never declared", "declared and since voided", "no scanner
        configuration" and "no connected repository" alike. A consumer needs only whether
        cross-tool derivation is founded, and a vocabulary for which absence applied would
        invite it to re-derive the rule.
        """
        ...
