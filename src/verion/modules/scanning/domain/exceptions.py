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
