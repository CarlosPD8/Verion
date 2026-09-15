class ProjectNotFound(Exception):
    pass


class InsufficientPermissions(Exception):
    pass


class GitHubApiError(Exception):
    pass


class ConnectedRepoNotFound(Exception):
    pass


class UnsupportedRepoProvider(Exception):
    pass


class SecurityContextNotFound(Exception):
    pass


class InvalidScannerConfig(Exception):
    pass


class ServingDeclarationNotFound(Exception):
    pass


class SourceArchiveTooLarge(Exception):
    """A repository archive exceeded a compressed or decompressed size cap.

    Distinct from `SourceArchiveMalformed` because the two are different facts about a
    tree — one that is too big to read here and one whose shape is not what GitHub
    serves — and M5.6 commit 4 stores them as different `UnreadTree` values.
    """


class SourceArchiveMalformed(Exception):
    """A repository archive did not have the shape `fetch_source_archive` reads."""


class ServingDeclarationMismatch(Exception):
    """The declared values are not the ones currently configured.

    A compare-and-set precondition failing, not a malformed request — which is why
    the route answers 409 rather than joining `InvalidScannerConfig` on 400. See
    ADR-0028's 2026-09-09 amendment.
    """
