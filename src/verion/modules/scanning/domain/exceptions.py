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


class ConnectedRepoNotFound(Exception):
    pass


class GitHubConnectionNotFound(Exception):
    pass


class UnsupportedRepoProvider(Exception):
    pass


class UnsafeDastTarget(Exception):
    pass
