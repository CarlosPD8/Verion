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


class ServingDeclarationMismatch(Exception):
    """The declared values are not the ones currently configured.

    A compare-and-set precondition failing, not a malformed request — which is why
    the route answers 409 rather than joining `InvalidScannerConfig` on 400. See
    ADR-0028's 2026-09-09 amendment.
    """
