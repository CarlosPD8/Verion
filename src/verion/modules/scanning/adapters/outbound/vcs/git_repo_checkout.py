import asyncio
import contextlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable

from verion.modules.scanning.domain.exceptions import RepoCheckoutFailed
from verion.modules.scanning.domain.repo_url import build_git_auth_env, parse_github_clone_url

# Without this, a git clone can silently hang past our own timeout: on a
# machine with an ambient credential helper configured (e.g. Git Credential
# Manager), git may try to launch an interactive/UI credential prompt even
# for an unauthenticated public clone. That prompt process can inherit our
# subprocess's stdout/stderr pipe handles, so killing the immediate `git`
# child on timeout doesn't close those pipes — `communicate()` never sees
# EOF and our "hard timeout" stops being hard. Disabling all interactive
# prompting up front closes off the whole class of problem rather than
# racing against it. Verified empirically: a clone that stalled for minutes
# on this pattern before this env was added completed immediately after.
_NO_INTERACTIVE_AUTH_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GCM_INTERACTIVE": "Never",
}


class GitRepoCheckout:
    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self._timeout_seconds = timeout_seconds

    async def checkout(self, repo_url: str, access_token: str | None) -> str:
        # Validated before any subprocess call — the SSRF/injection gate.
        parse_github_clone_url(repo_url)

        target_dir = tempfile.mkdtemp(prefix="verion-scan-")
        env = {**os.environ, **_NO_INTERACTIVE_AUTH_ENV}
        if access_token:
            env.update(build_git_auth_env(access_token))

        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--depth",
                "1",
                repo_url,
                target_dir,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self._timeout_seconds
                )
            except TimeoutError:
                # asyncio.wait_for alone does not kill the underlying child —
                # without this, a timed-out clone keeps running as an orphan.
                process.kill()
                await process.wait()
                raise RepoCheckoutFailed(f"git clone of '{repo_url}' timed out") from None

            if process.returncode != 0:
                message = _redact(stderr.decode(errors="replace"), access_token)
                raise RepoCheckoutFailed(f"git clone of '{repo_url}' failed: {message}")
        except BaseException:
            _rmtree(target_dir)
            raise

        return target_dir

    async def cleanup(self, local_path: str) -> None:
        _rmtree(local_path)


def _redact(text: str, access_token: str | None) -> str:
    # Defensive redaction (rule 12) — the primary control is that the token
    # never reaches argv or a URL in the first place (see build_git_auth_env).
    if not access_token:
        return text
    return text.replace(access_token, "***")


def _rmtree(path: str) -> None:
    # git checkouts routinely contain read-only files (pack files, on
    # Windows especially) that plain shutil.rmtree can't remove — clear the
    # read-only bit and retry before giving up, instead of silently leaving
    # the directory behind (which ignore_errors=True alone would do).
    def _clear_readonly_and_retry(
        func: Callable[[str], object], path: str, exc: BaseException
    ) -> None:
        os.chmod(path, stat.S_IWRITE)
        func(path)

    with contextlib.suppress(OSError):
        shutil.rmtree(path, onexc=_clear_readonly_and_retry)
