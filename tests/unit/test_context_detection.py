from verion.modules.projects.domain.context_detection import detect_stack


def test_detects_python_fastapi_repo():
    files = {"pyproject.toml": 'dependencies = ["fastapi>=0.100", "uvicorn"]'}

    result = detect_stack(files)

    assert result.language == "python"
    assert result.framework == "fastapi"


def test_detects_javascript_nextjs_repo():
    files = {
        "package.json": '{"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}',
    }

    result = detect_stack(files)

    assert result.language == "javascript"
    assert result.framework == "next"


def test_nothing_detected_when_no_signatures_present():
    files = {"README.md": "# Hello"}

    result = detect_stack(files)

    assert result.language is None
    assert result.framework is None
    assert result.deployment_target is None
    assert result.ci_provider is None


def test_detects_docker_and_github_actions_independent_of_language():
    files = {
        "Dockerfile": "FROM python:3.12",
        ".github/workflows/ci.yml": "name: CI",
    }

    result = detect_stack(files)

    assert result.deployment_target == "docker"
    assert result.ci_provider == "github_actions"
    assert result.language is None


def test_first_matching_language_signature_wins_when_multiple_present():
    files = {
        "pyproject.toml": "[project]",
        "package.json": "{}",
    }

    result = detect_stack(files)

    assert result.language == "python"


def test_javascript_framework_is_matched_as_a_dependency_key_not_a_substring():
    files = {"package.json": '{"dependencies": {"nextly-plugin": "^1.0.0"}}'}

    result = detect_stack(files)

    assert result.language == "javascript"
    assert result.framework is None
