import asyncio
import base64
import io
import re
import tarfile
import zlib
from urllib.parse import urlsplit

import httpx2

from verion.modules.projects.domain.exceptions import (
    GitHubApiError,
    SourceArchiveMalformed,
    SourceArchiveTooLarge,
)
from verion.modules.projects.ports.vcs_provider import RepoMetadata, SourceArchive

_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------------------
# `fetch_source_archive` — M5.6 commit 4, answering the design questions ADR-0029's
# 2026-09-15 amendment named and left open. **This is the only code in `projects` that
# parses bytes from the network**, so each bound below is stated at its site.
# ---------------------------------------------------------------------------------------

# GitHub answers `/tarball/{ref}` with a 302 to this host (docs.github.com, "Download a
# repository archive (tar)"). Pinned rather than followed blindly: the second request
# goes only to the host that serves archives, and anything else is a response this
# adapter does not understand.
_CODELOAD_HOST = "codeload.github.com"

# Compressed cap, counted on the wire while streaming, because codeload sends the body
# chunked with no `Content-Length` (measured 2026-09-15) — there is no header to check
# up front. 10 MiB is CHOSEN, not measured against a population of repositories: it is
# about 11 times this repository's own whole-tree tarball (922,736 bytes at 5a3b9f1) and
# about 13 times pallets/flask's (764,941 bytes, 2026-09-15). A tree over it is reported as
# `SourceArchiveTooLarge`, never truncated.
_MAX_COMPRESSED_BYTES = 10 * 1024 * 1024

# Decompressed cap. The three trees measured decompress at 2.7-3.8 times their
# compressed size, so an archive at the compressed cap is 27-38 MiB unpacked and this
# binds only on something built to expand — a decompression bomb, which the compressed
# cap alone cannot see.
#
# **It bounds zlib's OUTPUT, and that is not the same as bounding what a read returns.** A
# sparse tar member expands on read past the bytes it decompressed to (measured: a 283-byte
# gzip returned a 209,715,200-byte member), which is why `_read_members` refuses sparse
# members outright rather than relying on this cap. With them refused, every byte read comes
# out of the decompressed buffer, so this cap does bound it.
#
# **No single peak-memory figure is claimed.** An earlier version said "at most 60 MiB", which
# left out the body held briefly twice while streaming (buffer and `bytes` copy), the
# compressed body alive during decompression, and the decoded source strings. Each of those is
# bounded by a cap, which is the property that matters: none grows with a hostile archive.
_MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024

# One deadline over BOTH requests. httpx's `timeout` is per operation, so a server
# trickling one byte every nine seconds never trips it; this does. It is also what
# answers the five-minute expiry GitHub documents for private repositories' archive
# links: the link is used once, immediately, inside this deadline, and is never stored,
# returned or retried — so no code path can present it after it expires.
_ARCHIVE_DEADLINE_SECONDS = 60.0

# **An ALLOWLIST of member suffixes, and today it holds one entry.** Only these members
# are read out of the archive; everything else is skipped unread. It is written as a list
# rather than as "only Python source is read" on purpose: the natural next step — one
# archive read feeding the manifests `detect_stack` substring-matches as well as the
# routes (ADR-0029's commit-4 amendment, **G56**) — is then a list change with its own
# reasoning, and reads as one. Reading a manifest as text is not parsing it as code, so
# extending this list is not weakening a security rule.
_ARCHIVE_MEMBER_SUFFIXES = (".py",)

_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_ABBREVIATED_SHA_LENGTH = 7


class GitHubAdapter:
    def __init__(
        self,
        transport: httpx2.AsyncBaseTransport | None = None,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
    ) -> None:
        # Injection seam for tests (httpx2.MockTransport over fixture data);
        # None keeps real network behavior for production DI wiring.
        # AsyncBaseTransport, not BaseTransport: every method here builds an
        # AsyncClient, which accepts only the async variant — the two are
        # unrelated classes. The old annotation was wrong but harmless, since
        # MockTransport subclasses both and production passes None.
        self._transport = transport
        # webhook_url/webhook_secret are only required for register_webhook
        # (M3.6) — every other method on this adapter predates them and
        # doesn't touch either attribute.
        self._webhook_url = webhook_url
        self._webhook_secret = webhook_secret

    async def fetch_repo_metadata(self, access_token: str, owner: str, repo: str) -> RepoMetadata:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}",
                    headers=self._headers(access_token),
                )
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return RepoMetadata(
            default_branch=body["default_branch"], description=body.get("description") or ""
        )

    async def list_repo_files(self, access_token: str, owner: str, repo: str) -> list[str]:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/git/trees/HEAD",
                    params={"recursive": "1"},
                    headers=self._headers(access_token),
                )
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return [entry["path"] for entry in body["tree"] if entry["type"] == "blob"]

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str
    ) -> str | None:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                response = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                    headers=self._headers(access_token),
                )
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                body = response.json()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

        return base64.b64decode(body["content"]).decode("utf-8")

    async def fetch_source_archive(self, access_token: str, owner: str, repo: str) -> SourceArchive:
        """The default branch as one gzipped tarball, read in memory. See `SourceArchive`.

        Two requests, and the size of the answer is bounded before any of it is parsed:
        `_download_archive` enforces the compressed cap and the deadline, and
        `_read_archive` the decompressed cap and the member rules. Parsing runs outside
        the deadline because it is synchronous CPU work a timeout could not interrupt
        anyway, and its input is already capped.
        """
        timed_out = False
        try:
            async with asyncio.timeout(_ARCHIVE_DEADLINE_SECONDS):
                compressed = await self._download_archive(access_token, owner, repo)
        except TimeoutError:
            timed_out = True
        # Raised outside the handler, so the new exception carries no `__context__`
        # either — the same discipline `_download_archive` applies to the codeload leg.
        if timed_out:
            raise GitHubApiError("GitHub archive download timed out")
        return _read_archive(compressed)

    async def _download_archive(self, access_token: str, owner: str, repo: str) -> bytes:
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            # Leg 1: the API, with the bearer token. Redirects are NOT followed by the
            # client, so this adapter decides where the second request goes and what it
            # carries. That URL holds no secret, so chaining its exception is safe — the
            # same `from exc` as every other method on this adapter.
            try:
                redirect = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/tarball/HEAD",
                    headers=self._headers(access_token),
                    follow_redirects=False,
                )
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

            if redirect.is_error:
                raise GitHubApiError("GitHub API request failed")
            location = redirect.headers.get("location")
            if redirect.status_code != 302 or location is None or not _is_codeload(location):
                raise SourceArchiveMalformed("GitHub did not redirect to an archive download")

            # Leg 2: codeload. **The `Location` is treated as a credential**: GitHub's
            # documented private-repository links are temporary, and a link that grants
            # access for five minutes is one. So (rule 12) nothing below puts it in an
            # exception message, and a transport failure is re-raised OUTSIDE its handler,
            # which leaves the new exception with neither a `__cause__` nor a `__context__`
            # — an httpx exception whose text names the URL is dropped, not chained.
            try:
                return await _read_capped_body(client, location)
            except (httpx2.HTTPError, httpx2.InvalidURL, httpx2.StreamError):
                pass
        raise GitHubApiError("GitHub archive download failed")

    async def register_webhook(self, access_token: str, owner: str, repo: str) -> None:
        # List-then-create, not a bare POST: GitHub's docs don't state
        # whether POST /hooks dedupes an identical config.url, so this
        # queries existing hooks first and treats a config.url match as
        # already-registered (idempotent register — safe on reconnect/
        # redeploy without creating duplicate hooks).
        async with httpx2.AsyncClient(timeout=10.0, transport=self._transport) as client:
            try:
                existing = await client.get(
                    f"{_API_BASE}/repos/{owner}/{repo}/hooks",
                    headers=self._headers(access_token),
                )
                existing.raise_for_status()
                for hook in existing.json():
                    if hook.get("config", {}).get("url") == self._webhook_url:
                        return

                response = await client.post(
                    f"{_API_BASE}/repos/{owner}/{repo}/hooks",
                    headers=self._headers(access_token),
                    json={
                        "name": "web",
                        "config": {
                            "url": self._webhook_url,
                            "content_type": "json",
                            "secret": self._webhook_secret,
                            "insecure_ssl": "0",
                        },
                        "events": ["push"],
                        "active": True,
                    },
                )
                response.raise_for_status()
            except httpx2.HTTPError as exc:
                raise GitHubApiError("GitHub API request failed") from exc

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }


def _is_codeload(location: str) -> bool:
    """`https://codeload.github.com/...`, with no userinfo and no explicit port.

    `hostname` rather than a string prefix, so `https://codeload.github.com@evil.test/`
    — whose host is `evil.test` — is refused rather than matched.
    """
    try:
        parts = urlsplit(location)
        port = parts.port
    except ValueError:
        # `urlsplit` raises on a malformed IPv6 host (`https://[codeload.github.com/x`), measured
        # and reachable. That is a Location this adapter does not understand, so it is not
        # codeload and the caller raises MALFORMED. A bare ValueError escaping here would break
        # the port's three-exception contract and take the whole context build down with it.
        #
        # `.port` also raises on a non-numeric port, but through httpx2 that shape never gets
        # here: httpx2 validates a redirect's Location itself and raises RemoteProtocolError
        # inside the request, which leg 1 reports as GitHubApiError. It is inside this `try`
        # anyway, because `_is_codeload` is a function of a string and must not depend on its
        # caller's HTTP library to stay total.
        return False
    return (
        parts.scheme == "https"
        and parts.hostname == _CODELOAD_HOST
        and port is None
        and parts.username is None
        and parts.password is None
    )


async def _read_capped_body(client: httpx2.AsyncClient, location: str) -> bytes:
    """GET the archive with NO `Authorization`, stopping at the compressed cap.

    The bearer token is for api.github.com. It is not sent here because this request
    goes to another host and does not need it — a public archive is anonymous, and a
    private one carries its own short-lived grant in the link.

    **The bytes counted are the bytes decompressed later, held by two things.** With
    httpx's default `Accept-Encoding: gzip, deflate`, a server could apply a content
    encoding that `aiter_bytes` would silently expand before this counter saw it — a
    decompression step outside both caps. So the request asks for `identity`, a response
    that encodes anyway is refused before its body is touched, and the body is read with
    `aiter_raw`, which counts wire bytes whatever the headers claim. The refusal is what
    a test pins; `aiter_raw` is what still holds if that refusal is ever loosened.
    """
    async with client.stream("GET", location, headers={"Accept-Encoding": "identity"}) as response:
        if response.is_error:
            raise GitHubApiError("GitHub archive download failed")
        encoding = response.headers.get("content-encoding", "identity")
        if response.status_code != 200 or encoding != "identity":
            raise SourceArchiveMalformed("GitHub archive download had an unexpected shape")

        body = bytearray()
        async for chunk in response.aiter_raw():
            if len(body) + len(chunk) > _MAX_COMPRESSED_BYTES:
                raise SourceArchiveTooLarge("Repository archive exceeds the compressed size cap")
            body.extend(chunk)
    return bytes(body)


def _read_archive(compressed: bytes) -> SourceArchive:
    """Decompress under the cap, then read allowlisted regular members in memory.

    **Nothing is ever extracted to disk** — no `extract`, no `extractall` — so a member
    named `../../etc/x` cannot write anywhere: at worst it is a string, and it is refused
    below before it can become even that. Every member name is checked, including the
    ones that are not read, because an archive containing one is not an archive GitHub
    produced.
    """
    # `wbits=31` is 16 + MAX_WBITS: a gzip container and nothing else, so raw zlib or
    # deflate is refused. `max_length` makes the cap a property of the call rather than a
    # check after the damage: at most cap+1 bytes are ever produced.
    decompressor = zlib.decompressobj(wbits=31)
    try:
        raw = decompressor.decompress(compressed, _MAX_DECOMPRESSED_BYTES + 1)
    except zlib.error:
        raise SourceArchiveMalformed("Repository archive is not valid gzip") from None
    if len(raw) > _MAX_DECOMPRESSED_BYTES:
        raise SourceArchiveTooLarge("Repository archive exceeds the decompressed size cap")
    # Not at end-of-stream after all input: truncated. Bytes after it: a second gzip member
    # or trailing data, neither of which codeload sends.
    if not decompressor.eof or decompressor.unused_data:
        raise SourceArchiveMalformed("Repository archive is truncated or has trailing data")

    # `ValueError` as well as `TarError`, because `tarfile` does not confine itself to its own
    # hierarchy: a malformed sparse header (`GNU.sparse.realsize=abc`) raises a bare
    # `ValueError` from `int()` while headers are read — measured. Uncaught, it would escape the
    # port's three exceptions, which `BuildSecurityContextFromGitHubUseCase` relies on to
    # degrade. The catch is not a blanket: `_read_members` raises only this module's two domain
    # exceptions, which are not `ValueError`s, and handles `UnicodeDecodeError` (which is one)
    # itself. A 4,000-archive fuzz of the real capture's headers raised nothing outside these,
    # so the list is what crafted input reaches rather than what random corruption does.
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            return _read_members(archive)
    except (tarfile.TarError, ValueError):
        raise SourceArchiveMalformed("Repository archive is not a valid tar") from None


def _read_members(archive: tarfile.TarFile) -> SourceArchive:
    # **The full commit SHA comes from the pax global header**, which `git archive` writes
    # as `comment=<sha>` and codeload serves (measured on two repositories, 2026-09-15).
    # The top-level directory carries only the ABBREVIATED seven characters —
    # `CarlosPD8-verion-demo-target-c68caa7` — so it is used below as a cross-check and
    # never as the source.
    commit_sha = archive.pax_headers.get("comment", "")
    if not _FULL_SHA.fullmatch(commit_sha):
        raise SourceArchiveMalformed("Repository archive carries no commit SHA")

    members = archive.getmembers()
    if not members or not members[0].isdir() or "/" in members[0].name:
        raise SourceArchiveMalformed("Repository archive has no single top-level directory")
    top = members[0].name
    # `owner-repo-<sha7>`. A hyphen-anchored suffix, because owner and repo names may
    # themselves contain hyphens while a hex SHA cannot.
    if not top.endswith(f"-{commit_sha[:_ABBREVIATED_SHA_LENGTH]}"):
        raise SourceArchiveMalformed("Repository archive directory disagrees with its SHA")
    prefix = f"{top}/"

    files: dict[str, str] = {}
    undecodable_files: list[str] = []
    seen: set[str] = set()
    for member in members[1:]:
        # **The prefix is stripped, so every key is repo-relative**, which is what
        # `RouteSpan.file_path` has to meet (`Finding.location.file_path`, repo-relative
        # since G9). A member outside the top-level directory is refused, not re-rooted.
        if not member.name.startswith(prefix):
            raise SourceArchiveMalformed("Repository archive has a member outside its root")
        relative = member.name.removeprefix(prefix)
        if any(part in ("", ".", "..") for part in relative.split("/")):
            raise SourceArchiveMalformed("Repository archive has a non-canonical member path")
        # A duplicate name would make "which content is this key?" depend on member order.
        if relative in seen:
            raise SourceArchiveMalformed("Repository archive has a duplicate member")
        seen.add(relative)
        # **Sparse members are refused, and `isreg()` below does not do it**: a sparse member
        # IS regular. Its data region is a map plus a few bytes, and `extractfile().read()`
        # fills the declared holes, so the read returns far more than the archive decompressed
        # to and the decompressed cap no longer bounds it. `git archive` never writes one, so
        # an archive holding one is not an archive GitHub produced.
        if member.issparse():
            raise SourceArchiveMalformed("Repository archive has a sparse member")

        # **Regular files only.** `isreg()` is what refuses symlinks and hardlinks, and it
        # is load-bearing rather than tidy: `extractfile` on a link member RESOLVES the
        # link and returns its target's bytes, so without this check a link named `x.py`
        # would be read as source it is not.
        if not member.isreg() or not relative.endswith(_ARCHIVE_MEMBER_SUFFIXES):
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            continue
        content = extracted.read()
        try:
            files[relative] = content.decode("utf-8")
        except UnicodeDecodeError:
            undecodable_files.append(relative)

    return SourceArchive(
        commit_sha=commit_sha,
        files=files,
        undecodable_files=tuple(sorted(undecodable_files)),
    )
