import asyncio
import gzip
import io
import json
import tarfile
from pathlib import Path

import httpx2
import pytest

from verion.modules.projects.adapters.outbound.vcs import github_adapter as github_adapter_module
from verion.modules.projects.adapters.outbound.vcs.github_adapter import (
    _MAX_COMPRESSED_BYTES,
    _MAX_DECOMPRESSED_BYTES,
    GitHubAdapter,
)
from verion.modules.projects.domain.exceptions import (
    GitHubApiError,
    SourceArchiveMalformed,
    SourceArchiveTooLarge,
)

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Captured/schema-accurate GitHub API payloads for two representative repo
# shapes (Python/FastAPI, JS/Next.js) — not live network calls, per
# ROADMAP.md's M2.2 line: "Integration test against a handful of real sample
# repos (fixtures)."
_REPOS = {
    ("octocat", "fastapi-demo"): json.loads(
        (_FIXTURES_DIR / "github_fastapi_demo.json").read_text(encoding="utf-8")
    ),
    ("octocat", "nextjs-demo"): json.loads(
        (_FIXTURES_DIR / "github_nextjs_demo.json").read_text(encoding="utf-8")
    ),
}


def _fixture_handler(request: httpx2.Request) -> httpx2.Response:
    parts = request.url.path.strip("/").split("/")
    # /repos/{owner}/{repo}/git/trees/HEAD or /repos/{owner}/{repo}/contents/{path...}
    owner, repo, kind = parts[1], parts[2], parts[3]
    repo_data = _REPOS.get((owner, repo))
    if repo_data is None:
        return httpx2.Response(404, json={"message": "Not Found"})

    if kind == "git":
        return httpx2.Response(200, json=repo_data["tree"])

    if kind == "contents":
        path = "/".join(parts[4:])
        content = repo_data["contents"].get(path)
        if content is None:
            return httpx2.Response(404, json={"message": "Not Found"})
        return httpx2.Response(200, json=content)

    return httpx2.Response(500, json={"message": "unexpected fixture request"})


def _adapter() -> GitHubAdapter:
    return GitHubAdapter(transport=httpx2.MockTransport(_fixture_handler))


async def test_list_repo_files_returns_blob_paths_only_for_python_repo():
    adapter = _adapter()

    paths = await adapter.list_repo_files("gho_faketoken", "octocat", "fastapi-demo")

    assert set(paths) == {
        ".github/workflows/ci.yml",
        "src/main.py",
        "pyproject.toml",
        "Dockerfile",
        "README.md",
    }
    assert ".github" not in paths
    assert "src" not in paths


async def test_list_repo_files_returns_blob_paths_only_for_js_repo():
    adapter = _adapter()

    paths = await adapter.list_repo_files("gho_faketoken", "octocat", "nextjs-demo")

    assert set(paths) == {"pages/index.js", "package.json", "README.md"}


async def test_get_file_content_decodes_real_captured_content():
    adapter = _adapter()

    content = await adapter.get_file_content(
        "gho_faketoken", "octocat", "fastapi-demo", "pyproject.toml"
    )

    assert content == (
        '[project]\nname = "fastapi-demo"\ndependencies = ["fastapi>=0.100", "uvicorn"]\n'
    )


async def test_get_file_content_decodes_json_manifest():
    adapter = _adapter()

    content = await adapter.get_file_content(
        "gho_faketoken", "octocat", "nextjs-demo", "package.json"
    )

    manifest = json.loads(content)
    assert manifest["dependencies"] == {"next": "^14.0.0", "react": "^18.0.0"}


async def test_get_file_content_returns_none_for_a_missing_file():
    adapter = _adapter()

    content = await adapter.get_file_content(
        "gho_faketoken", "octocat", "fastapi-demo", "does-not-exist.txt"
    )

    assert content is None


async def test_list_repo_files_raises_github_api_error_for_an_unknown_repo():
    adapter = _adapter()

    with pytest.raises(GitHubApiError):
        await adapter.list_repo_files("gho_faketoken", "octocat", "unknown-repo")


_WEBHOOK_URL = "https://verion.example.com/scanning/webhooks/github"


def _webhook_adapter(existing_hooks: list[dict]) -> tuple[GitHubAdapter, list[httpx2.Request]]:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx2.Response(200, json=existing_hooks)
        return httpx2.Response(201, json={"id": 1})

    adapter = GitHubAdapter(
        transport=httpx2.MockTransport(handler),
        webhook_url=_WEBHOOK_URL,
        webhook_secret="test-secret",
    )
    return adapter, requests


async def test_register_webhook_creates_one_when_none_exists():
    adapter, requests = _webhook_adapter(existing_hooks=[])

    await adapter.register_webhook("gho_faketoken", "octocat", "fastapi-demo")

    methods = [request.method for request in requests]
    assert methods == ["GET", "POST"]
    post_body = json.loads(requests[1].content)
    assert post_body["config"]["url"] == _WEBHOOK_URL
    assert post_body["config"]["secret"] == "test-secret"
    assert post_body["events"] == ["push"]


async def test_register_webhook_is_a_no_op_when_an_identical_url_hook_already_exists():
    adapter, requests = _webhook_adapter(
        existing_hooks=[{"id": 42, "config": {"url": _WEBHOOK_URL}}]
    )

    await adapter.register_webhook("gho_faketoken", "octocat", "fastapi-demo")

    assert [request.method for request in requests] == ["GET"]


async def test_register_webhook_raises_github_api_error_on_failure():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(500, json={"message": "boom"})

    adapter = GitHubAdapter(
        transport=httpx2.MockTransport(handler),
        webhook_url=_WEBHOOK_URL,
        webhook_secret="test-secret",
    )

    with pytest.raises(GitHubApiError) as exc_info:
        await adapter.register_webhook("gho_faketoken", "octocat", "fastapi-demo")
    # Rule 12: the webhook secret must never leak into an exception message.
    assert "test-secret" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# fetch_source_archive (M5.6 commit 4)
#
# Two kinds of fixture with two jobs — fixtures/github_tarball/README.md says why they must
# not trade places. The REAL capture is the format contract: the tests against it are the
# only ones that can say "we read what GitHub actually sends". The SYNTHETIC tarballs are
# the adversarial cases and the caps, which GitHub never serves. No format assertion is
# made against a synthetic tarball, because it would only restate how that tarball was
# built.
# ---------------------------------------------------------------------------

_CAPTURE = (_FIXTURES_DIR / "github_tarball" / "verion-demo-target-c68caa7.tar.gz").read_bytes()
_CAPTURE_SHA = "c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850"
_BEARER = "gho_faketoken"
_CODELOAD_URL = "https://codeload.github.com/CarlosPD8/verion-demo-target/legacy.tar.gz/HEAD"


class _ChunkedBody(httpx2.AsyncByteStream):
    """A body that arrives in chunks, as codeload's does: chunked, with no `Content-Length`.

    `httpx2.Response(content=bytes)` arrives ALREADY READ, which no network response does,
    and `aiter_raw` refuses it with `StreamConsumed`. Serving a stream keeps these tests on
    the shape production actually receives, and makes the compressed-cap counter work
    across chunk boundaries rather than on one pre-read blob.
    """

    def __init__(self, body: bytes, chunk_size: int = 64 * 1024) -> None:
        self._body = body
        self._chunk_size = chunk_size

    async def __aiter__(self):
        for start in range(0, len(self._body), self._chunk_size):
            yield self._body[start : start + self._chunk_size]


def _archive_adapter(
    body: bytes,
    *,
    location: str = _CODELOAD_URL,
    api_status: int = 302,
    codeload_status: int = 200,
    codeload_headers: dict[str, str] | None = None,
) -> tuple[GitHubAdapter, list[httpx2.Request]]:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.url.host == "api.github.com":
            if api_status != 302:
                return httpx2.Response(api_status, json={"message": "Not Found"})
            return httpx2.Response(302, headers={"Location": location})
        return httpx2.Response(codeload_status, headers=codeload_headers, stream=_ChunkedBody(body))

    return GitHubAdapter(transport=httpx2.MockTransport(handler)), requests


async def _fetch(adapter: GitHubAdapter):
    return await adapter.fetch_source_archive(_BEARER, "CarlosPD8", "verion-demo-target")


# --- The format contract: the real capture ----------------------------------


async def test_the_commit_sha_is_the_full_sha_from_the_real_capture_s_pax_header():
    """The top-level directory says only `c68caa7`; the full SHA is in the pax header."""
    adapter, _ = _archive_adapter(_CAPTURE)

    archive = await _fetch(adapter)

    assert archive.commit_sha == _CAPTURE_SHA


async def test_the_real_capture_yields_only_repo_relative_python_source():
    """Prefix stripped and allowlist applied, against what GitHub actually serves.

    The capture holds `.gitignore`, `README.md`, `requirements.txt` and two templates besides
    `app.py`. **This is the only test in the suite that can catch a non-`.py` member being
    read**: `extract_routes` ignores keys that do not end in `.py`, so nothing downstream of
    this adapter would ever notice.
    """
    adapter, _ = _archive_adapter(_CAPTURE)

    archive = await _fetch(adapter)

    assert set(archive.files) == {"app.py"}
    assert archive.undecodable_files == ()


async def test_the_real_capture_s_app_py_carries_the_sink_at_line_28():
    adapter, _ = _archive_adapter(_CAPTURE)

    archive = await _fetch(adapter)

    lines = archive.files["app.py"].splitlines()
    assert lines[13] == '@app.route("/calculate")'
    assert lines[27].strip() == "result = eval(expr)"


async def test_the_bearer_token_goes_to_the_api_and_never_to_codeload():
    adapter, requests = _archive_adapter(_CAPTURE)

    await _fetch(adapter)

    api, codeload = requests
    assert api.url.host == "api.github.com"
    assert api.headers["Authorization"] == f"Bearer {_BEARER}"
    assert codeload.url.host == "codeload.github.com"
    assert "Authorization" not in codeload.headers
    # Counted bytes must be the bytes later decompressed — see `_read_capped_body`.
    assert codeload.headers["Accept-Encoding"] == "identity"


# --- The adversarial cases and the caps: synthetic tarballs -------------------

_SYNTHETIC_SHA = "0123456789abcdef0123456789abcdef01234567"
_SYNTHETIC_TOP = f"octocat-flask-demo-{_SYNTHETIC_SHA[:7]}"
_ROUTE_SOURCE = b'@app.route("/x")\ndef x():\n    return "x"\n'


def _regular(name: str, data: bytes) -> tuple[tarfile.TarInfo, io.BytesIO | None]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, io.BytesIO(data)


def _link(name: str, kind: bytes, target: str) -> tuple[tarfile.TarInfo, io.BytesIO | None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


def _synthetic(
    *members: tuple[tarfile.TarInfo, io.BytesIO | None],
    top: str = _SYNTHETIC_TOP,
    pax_headers: dict[str, str] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    headers = {"comment": _SYNTHETIC_SHA} if pax_headers is None else pax_headers
    with tarfile.open(
        fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT, pax_headers=headers
    ) as archive:
        directory = tarfile.TarInfo(top)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for info, fileobj in members:
            archive.addfile(info, fileobj)
    return gzip.compress(buffer.getvalue(), mtime=0)


async def test_symlink_and_hardlink_members_are_never_read_even_with_a_py_name():
    """`extractfile` RESOLVES a link member, so without `isreg()` both would read `app.py`."""
    body = _synthetic(
        _regular(f"{_SYNTHETIC_TOP}/app.py", _ROUTE_SOURCE),
        _link(f"{_SYNTHETIC_TOP}/soft.py", tarfile.SYMTYPE, "app.py"),
        _link(f"{_SYNTHETIC_TOP}/hard.py", tarfile.LNKTYPE, f"{_SYNTHETIC_TOP}/app.py"),
    )
    adapter, _ = _archive_adapter(body)

    archive = await _fetch(adapter)

    assert set(archive.files) == {"app.py"}


@pytest.mark.parametrize(
    "name",
    [
        f"{_SYNTHETIC_TOP}/../escape.py",
        f"{_SYNTHETIC_TOP}/pkg/../../escape.py",
        f"{_SYNTHETIC_TOP}//double.py",
        "elsewhere/outside.py",
    ],
)
async def test_a_member_path_that_is_not_canonical_under_the_root_is_malformed(name):
    adapter, _ = _archive_adapter(_synthetic(_regular(name, _ROUTE_SOURCE)))

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


def _sparse_pax_1_0(name: str, realsize: str) -> tuple[tarfile.TarInfo, io.BytesIO | None]:
    """A PAX 1.0 sparse member: a one-byte data region declared as `realsize` bytes."""
    data = "1\n0\n1\n".ljust(512, "\0").encode() + b"x"
    info = tarfile.TarInfo(name)
    info.pax_headers = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": name,
        "GNU.sparse.realsize": realsize,
    }
    info.size = len(data)
    return info, io.BytesIO(data)


def _sparse_pax_0_1(name: str, size: str) -> tuple[tarfile.TarInfo, io.BytesIO | None]:
    """A PAX 0.1 sparse member: one byte of data, a map, and a declared `size`."""
    info = tarfile.TarInfo(name)
    info.pax_headers = {
        "GNU.sparse.size": size,
        "GNU.sparse.numblocks": "1",
        "GNU.sparse.map": "0,1",
    }
    info.size = 1
    return info, io.BytesIO(b"x")


_JUST_OVER_THE_CAP = str(_MAX_DECOMPRESSED_BYTES + 1)


@pytest.mark.parametrize(
    "member",
    [
        _sparse_pax_1_0(f"{_SYNTHETIC_TOP}/big.py", _JUST_OVER_THE_CAP),
        _sparse_pax_0_1(f"{_SYNTHETIC_TOP}/big.py", _JUST_OVER_THE_CAP),
    ],
    ids=["pax-1.0", "pax-0.1"],
)
async def test_a_sparse_member_is_malformed_because_it_expands_past_the_decompressed_cap(member):
    """`isreg()` is True for a sparse member, and reading one fills its holes.

    Measured before the fix: a 283-byte gzip holding one sparse member declared at 200 MiB
    returned a 209,715,200-byte `big.py`, with the decompressed cap untouched because zlib
    produced only a few hundred bytes. The guardian found this.
    """
    body = _synthetic(member)
    assert len(body) < 1024
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


async def test_a_header_tarfile_rejects_with_a_bare_value_error_is_still_malformed():
    """The port raises three exceptions and the use case degrades on exactly those.

    `tarfile` raises a bare `ValueError` for `GNU.sparse.realsize=abc`. Escaping, it would have
    failed the whole context build instead of storing `MALFORMED`.
    """
    adapter, _ = _archive_adapter(_synthetic(_sparse_pax_1_0(f"{_SYNTHETIC_TOP}/big.py", "abc")))

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


async def test_a_duplicate_member_is_malformed():
    body = _synthetic(
        _regular(f"{_SYNTHETIC_TOP}/app.py", _ROUTE_SOURCE),
        _regular(f"{_SYNTHETIC_TOP}/app.py", b"print('second')\n"),
    )
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


@pytest.mark.parametrize(
    "pax_headers",
    [{}, {"comment": _SYNTHETIC_SHA[:7]}, {"comment": "not-a-sha"}],
    ids=["missing", "abbreviated", "garbage"],
)
async def test_an_archive_without_a_full_sha_in_its_pax_header_is_malformed(pax_headers):
    body = _synthetic(_regular(f"{_SYNTHETIC_TOP}/app.py", _ROUTE_SOURCE), pax_headers=pax_headers)
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


async def test_a_top_level_directory_that_disagrees_with_the_sha_is_malformed():
    top = "octocat-flask-demo-fffffff"
    body = _synthetic(_regular(f"{top}/app.py", _ROUTE_SOURCE), top=top)
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


@pytest.mark.parametrize(
    "body",
    [_CAPTURE[:-64], _CAPTURE[:-8], _CAPTURE + b"trailing"],
    ids=["truncated-into-the-tar", "gzip-trailer-cut", "trailing-bytes"],
)
async def test_an_archive_that_is_not_exactly_one_complete_gzip_stream_is_malformed(body):
    """Three shapes, and only the first is caught by `tarfile` on its own.

    Measured against the real capture: cutting 64 bytes truncates the tar and `tarfile`
    raises, but cutting only the 8-byte gzip trailer (CRC and size) and appending bytes
    after the stream BOTH still decompress to all 20,480 bytes and parse cleanly as eight
    members. Those two are refused only by the end-of-stream and unused-data check — which
    an earlier version of this test, holding the 64-byte case alone, left unpinned: removing
    that check survived it.
    """
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


async def test_a_python_member_that_is_not_utf8_is_named_rather_than_dropped():
    body = _synthetic(
        _regular(f"{_SYNTHETIC_TOP}/app.py", _ROUTE_SOURCE),
        _regular(f"{_SYNTHETIC_TOP}/latin1.py", "# café\n".encode("latin-1")),
    )
    adapter, _ = _archive_adapter(body)

    archive = await _fetch(adapter)

    assert set(archive.files) == {"app.py"}
    assert archive.undecodable_files == ("latin1.py",)


async def test_a_body_over_the_compressed_cap_is_too_large_and_never_decompressed():
    """Zeros are not gzip, so without the cap this would surface as Malformed instead."""
    adapter, _ = _archive_adapter(b"\0" * (_MAX_COMPRESSED_BYTES + 1))

    with pytest.raises(SourceArchiveTooLarge):
        await _fetch(adapter)


async def test_a_content_encoded_download_is_refused_before_its_body_is_read():
    """The request asks for `identity`; a server that encodes anyway is not read.

    Otherwise a transfer encoding would be a decompression step outside both caps.
    """
    adapter, _ = _archive_adapter(_CAPTURE, codeload_headers={"Content-Encoding": "gzip"})

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)


async def test_a_decompression_bomb_is_too_large():
    """One member of zeros just over the decompressed cap, which gzips to about 50 KB.

    Well inside the compressed cap, so only the decompressed cap can refuse it.
    """
    body = _synthetic(_regular(f"{_SYNTHETIC_TOP}/bomb.py", b"\0" * (_MAX_DECOMPRESSED_BYTES + 1)))
    assert len(body) < _MAX_COMPRESSED_BYTES
    adapter, _ = _archive_adapter(body)

    with pytest.raises(SourceArchiveTooLarge):
        await _fetch(adapter)


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/legacy.tar.gz/HEAD",
        "http://codeload.github.com/o/r/legacy.tar.gz/HEAD",
        "https://codeload.github.com@evil.example/legacy.tar.gz/HEAD",
        "https://codeload.github.com:8443/o/r/legacy.tar.gz/HEAD",
        # Makes `urlsplit` raise a bare ValueError, which must not escape the port.
        "https://[codeload.github.com/o/r/legacy.tar.gz/HEAD",
    ],
)
async def test_a_redirect_anywhere_but_codeload_is_malformed_and_never_followed(location):
    adapter, requests = _archive_adapter(_CAPTURE, location=location)

    with pytest.raises(SourceArchiveMalformed):
        await _fetch(adapter)

    assert [request.url.host for request in requests] == ["api.github.com"]


async def test_a_location_httpx_itself_refuses_is_a_fetch_failure_and_leaks_nothing():
    """A non-numeric port never reaches `_is_codeload`: httpx2 rejects it first.

    Measured: even with `follow_redirects=False`, httpx2 validates a redirect's `Location`
    while building the response and raises `RemoteProtocolError`. So this surfaces as
    `GitHubApiError` (stored as FETCH_FAILED), not MALFORMED. It is still one of the port's
    three exceptions, which is the property the use case relies on to degrade. Pinned here so
    the classification is a recorded fact rather than a surprise.

    The api.github.com leg chains its exception (`from exc`), so this also checks that a token
    carried in such a `Location` does not ride along in that chained cause.
    """
    location = "https://codeload.github.com:abc/o/r/legacy.tar.gz/HEAD?token=AAPRIVATELINKTOKEN"
    adapter, requests = _archive_adapter(_CAPTURE, location=location)

    with pytest.raises(GitHubApiError) as exc_info:
        await _fetch(adapter)

    assert [request.url.host for request in requests] == ["api.github.com"]
    assert "AAPRIVATELINKTOKEN" not in str(exc_info.value)
    assert "AAPRIVATELINKTOKEN" not in str(exc_info.value.__cause__)


async def test_an_api_error_on_the_tarball_request_is_a_github_api_error():
    adapter, _ = _archive_adapter(_CAPTURE, api_status=404)

    with pytest.raises(GitHubApiError):
        await _fetch(adapter)


async def test_a_download_that_outlasts_the_deadline_is_a_github_api_error(monkeypatch):
    """The archive link is only ever used inside one deadline.

    That deadline is half of the answer to the five-minute expiry GitHub documents for
    private links; the other half is that the link is never stored or retried. httpx's
    own timeout is per operation, so a body that stalls between chunks never trips it.
    The deadline is shortened here, because a real stall would take a minute.
    """
    monkeypatch.setattr(github_adapter_module, "_ARCHIVE_DEADLINE_SECONDS", 0.05)

    class _Stalling(httpx2.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(5)
            yield _CAPTURE

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "api.github.com":
            return httpx2.Response(302, headers={"Location": _CODELOAD_URL})
        return httpx2.Response(200, stream=_Stalling())

    adapter = GitHubAdapter(transport=httpx2.MockTransport(handler))

    with pytest.raises(GitHubApiError) as exc_info:
        await _fetch(adapter)

    assert exc_info.value.__context__ is None


# --- Rule 12: the archive link is a credential --------------------------------

_SECRET_LINK = f"{_CODELOAD_URL}?token=AAPRIVATELINKTOKEN"


async def test_a_failed_download_of_a_private_link_leaks_neither_the_link_nor_the_bearer():
    adapter, _ = _archive_adapter(_CAPTURE, location=_SECRET_LINK, codeload_status=500)

    with pytest.raises(GitHubApiError) as exc_info:
        await _fetch(adapter)

    assert "AAPRIVATELINKTOKEN" not in str(exc_info.value)
    assert _BEARER not in str(exc_info.value)


async def test_a_transport_error_on_a_private_link_is_not_chained_into_the_raised_error():
    """An httpx exception whose text names the URL must be DROPPED, not chained.

    `from exc` would keep it as `__cause__`, and even `from None` would keep it as
    `__context__` — either way a traceback logger prints the link. Both must be None.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "api.github.com":
            return httpx2.Response(302, headers={"Location": _SECRET_LINK})
        raise httpx2.ReadError(f"connection reset while reading {request.url}")

    adapter = GitHubAdapter(transport=httpx2.MockTransport(handler))

    with pytest.raises(GitHubApiError) as exc_info:
        await _fetch(adapter)

    assert "AAPRIVATELINKTOKEN" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
