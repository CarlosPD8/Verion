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
