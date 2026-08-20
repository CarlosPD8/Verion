import base64
from urllib.parse import urlparse

from verion.modules.scanning.domain.exceptions import UnsupportedRepoUrl


def parse_github_clone_url(repo_url: str) -> tuple[str, str]:
    """Validates repo_url is a genuine https://github.com/{owner}/{repo} URL
    and returns (owner, repo). Must run before repo_url ever reaches a
    subprocess call — this is the SSRF/injection gate for git_repo_checkout.

    Stricter than projects' _parse_github_owner_repo (which this mirrors in
    spirit, not by import — modules don't share domain/application code):
    also requires an https scheme. projects' validator is REST-API-scoped
    and never checks scheme; here an unchecked file:// or git:// URL could
    reach `git clone` as a subprocess argument and read/access arbitrary
    local paths on the runner.
    """
    parsed = urlparse(repo_url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme != "https" or parsed.netloc != "github.com" or len(path_parts) != 2:
        raise UnsupportedRepoUrl(
            f"'{repo_url}' is not a valid https://github.com/{{owner}}/{{repo}} URL"
        )
    owner, repo = path_parts
    return owner, repo.removesuffix(".git")


def build_git_auth_env(access_token: str) -> dict[str, str]:
    """GIT_CONFIG_* overrides that set http.extraheader to a Basic-auth
    header for the clone subprocess, scoped to that one invocation.

    Never embed a token in a clone URL: git writes a URL-embedded credential
    in plaintext into the cloned repo's .git/config, a disk-persistence leak
    that outlives even a killed process. GIT_CONFIG_COUNT/KEY_n/VALUE_n
    (a git feature since 2.31) passes config purely via the environment —
    it's never written to any file, and isn't visible via `ps aux` output
    the way an argv-embedded token would be.
    """
    credentials = base64.b64encode(f"x-access-token:{access_token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {credentials}",
    }
