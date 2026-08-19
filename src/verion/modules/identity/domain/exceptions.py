class InvalidEmail(ValueError):
    pass


class EmailAlreadyRegistered(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class InvalidAccessToken(Exception):
    pass


class InvalidOAuthState(Exception):
    pass


class GitHubApiError(Exception):
    pass
