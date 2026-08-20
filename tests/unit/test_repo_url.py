import base64

import pytest

from verion.modules.scanning.domain.exceptions import UnsupportedRepoUrl
from verion.modules.scanning.domain.repo_url import build_git_auth_env, parse_github_clone_url


def test_parses_owner_and_repo_from_a_valid_url():
    assert parse_github_clone_url("https://github.com/octocat/Hello-World") == (
        "octocat",
        "Hello-World",
    )


def test_strips_a_trailing_dot_git_suffix():
    assert parse_github_clone_url("https://github.com/octocat/Hello-World.git") == (
        "octocat",
        "Hello-World",
    )


@pytest.mark.parametrize(
    "repo_url",
    [
        "https://gitlab.com/octocat/Hello-World",
        "https://github.com.evil.com/octocat/Hello-World",
        "https://github.com@evil.com/octocat/Hello-World",
        "https://evil.com@github.com/octocat/Hello-World",
        "https://github.com/octocat",
        "https://github.com/octocat/Hello-World/extra",
        "https://github.com/",
        "file:///etc/passwd",
        "git://github.com/octocat/Hello-World",
        "http://github.com/octocat/Hello-World",
    ],
)
def test_rejects_urls_that_are_not_a_genuine_https_github_repo_url(repo_url: str):
    with pytest.raises(UnsupportedRepoUrl):
        parse_github_clone_url(repo_url)


def test_build_git_auth_env_never_leaks_the_raw_token():
    env = build_git_auth_env("super-secret-token")

    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.extraheader"
    assert "super-secret-token" not in env["GIT_CONFIG_VALUE_0"]

    expected_b64 = base64.b64encode(b"x-access-token:super-secret-token").decode()
    assert env["GIT_CONFIG_VALUE_0"] == f"AUTHORIZATION: basic {expected_b64}"
