import glob
import os
import tempfile

import pytest

from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import (
    GitRepoCheckout,
    _redact,
)
from verion.modules.scanning.domain.exceptions import RepoCheckoutFailed, UnsupportedRepoUrl

# Real network calls against GitHub's own canonical, stable, tiny public demo
# repo — the checkout mechanism's whole job is the network fetch, so unlike
# the GitHub REST API adapter tests (which use MockTransport specifically to
# avoid response-shape/pagination flakiness), mocking this out would leave
# the actual thing under test unverified. See ADR-011.
_PUBLIC_REPO = "https://github.com/octocat/Hello-World"


async def test_clones_a_real_public_repo_without_a_token():
    checkout = GitRepoCheckout()

    local_path = await checkout.checkout(_PUBLIC_REPO, access_token=None)
    try:
        assert os.path.isdir(local_path)
        assert os.path.isdir(os.path.join(local_path, ".git"))
    finally:
        await checkout.cleanup(local_path)

    assert not os.path.exists(local_path)


async def test_raises_and_cleans_up_when_repo_does_not_exist():
    checkout = GitRepoCheckout()
    leftover_before = _leftover_checkout_dirs()

    with pytest.raises(RepoCheckoutFailed):
        await checkout.checkout(
            "https://github.com/octocat/this-repo-does-not-exist-verion-test",
            access_token=None,
        )

    assert _leftover_checkout_dirs() == leftover_before


def _leftover_checkout_dirs() -> set[str]:
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "verion-scan-*")))


async def test_kills_subprocess_and_cleans_up_on_timeout():
    checkout = GitRepoCheckout(timeout_seconds=0.001)
    leftover_before = _leftover_checkout_dirs()

    with pytest.raises(RepoCheckoutFailed):
        await checkout.checkout(_PUBLIC_REPO, access_token=None)

    assert _leftover_checkout_dirs() == leftover_before


async def test_rejects_url_before_any_subprocess_call():
    checkout = GitRepoCheckout()

    with pytest.raises(UnsupportedRepoUrl):
        await checkout.checkout("file:///etc/passwd", access_token=None)


# Rule 12: no credential may appear in an exception message. The real clone
# failure path can't exercise this directly — build_git_auth_env keeps the
# token out of argv/the URL entirely, so it never reaches git's real stderr
# to begin with (the redaction below is defense-in-depth for that same
# reason). Test _redact itself directly, plus the real failure path as a
# regression check that the property holds end-to-end too, matching
# identity's test_no_plaintext_password_leaks_into_the_exception pattern.


def test_redact_scrubs_a_token_out_of_captured_output():
    text = (
        "fatal: unable to access 'https://x-access-token:super-secret-token"
        "@github.com/o/r/': The requested URL returned error: 403"
    )

    assert "super-secret-token" not in _redact(text, "super-secret-token")


def test_redact_is_a_no_op_without_a_token():
    assert _redact("some git error", None) == "some git error"


async def test_no_access_token_leaks_into_the_exception_on_a_real_failure():
    checkout = GitRepoCheckout()

    with pytest.raises(RepoCheckoutFailed) as exc_info:
        await checkout.checkout(
            "https://github.com/octocat/this-repo-does-not-exist-verion-test",
            access_token="super-secret-token",
        )

    assert "super-secret-token" not in str(exc_info.value)
