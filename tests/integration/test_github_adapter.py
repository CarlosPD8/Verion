import json
from pathlib import Path

import httpx2
import pytest

from verion.modules.projects.adapters.outbound.vcs.github_adapter import GitHubAdapter
from verion.modules.projects.domain.exceptions import GitHubApiError

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
