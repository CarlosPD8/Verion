class ProjectNotFound(Exception):
    pass


class ProjectAccessDenied(Exception):
    """The caller may not act on this project, and this type deliberately cannot say why.

    Raised for an absent project, a non-member and, when the action is starting a scan, a
    member who is not an owner, indistinguishably. The routes map it to **404** with a
    message built from the path id alone (ADR-0035 decisions 2 and 4), on
    `normalization`'s and `correlation`'s `ProjectAccessDenied` precedent. It is this
    module's own type because `projects`' `InsufficientPermissions` lives in another
    module's `domain/` (rule 3), and it replaced this module's own `InsufficientPermissions`
    at M8.8, when `TriggerScanUseCase` stopped telling the two denials apart.
    """


class UnsupportedRepoUrl(Exception):
    pass


class RepoCheckoutFailed(Exception):
    pass


class ScannerExecutionFailed(Exception):
    pass


class ScanNotFound(Exception):
    pass


class ConnectedRepoNotFound(Exception):
    pass


class GitHubConnectionNotFound(Exception):
    pass


class UnsupportedRepoProvider(Exception):
    pass


class UnsafeDastTarget(Exception):
    pass


class RepoNotConnected(Exception):
    pass


class InvalidWebhookPayload(Exception):
    pass


class NoScannersEnabled(Exception):
    pass


class UnknownScanner(Exception):
    """A configured tool name that no registered adapter answers to.

    A deployment/configuration error, not a tool outcome — so it fails the
    whole scan loudly rather than being recorded as one tool's failure. The
    write path validates against ScannerTool, so reaching this means config
    was written around it or an adapter was dropped from the worker registry.
    """
