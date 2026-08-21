class ProjectNotFound(Exception):
    pass


class InsufficientPermissions(Exception):
    pass


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
