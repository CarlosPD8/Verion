import json
from dataclasses import dataclass

# Language signatures are checked in this fixed order and the first match
# wins — a repo with both a pyproject.toml and a package.json (e.g. a Python
# backend with a JS frontend in the same repo) is reported as "python", not
# both. Documented limitation, not a bug: MVP scope is single-language
# detection, not a multi-language matrix.
_LANGUAGE_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("python", ("pyproject.toml", "requirements.txt")),
    ("javascript", ("package.json",)),
    ("go", ("go.mod",)),
    ("ruby", ("Gemfile",)),
    ("java", ("pom.xml", "build.gradle")),
]

_PYTHON_FRAMEWORK_SIGNATURES = ("fastapi", "django", "flask")
_JAVASCRIPT_FRAMEWORK_SIGNATURES = ("next", "express", "react")

_CI_WORKFLOWS_PREFIX = ".github/workflows/"

# The fixed set of paths detect_stack actually inspects (language/framework
# signature files, plus Dockerfile and any CI workflow file) — used to avoid
# fetching a repo's entire file tree when only these ever affect detection.
_RELEVANT_FILENAMES = frozenset(
    {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "go.mod",
        "Gemfile",
        "pom.xml",
        "build.gradle",
        "Dockerfile",
    }
)


@dataclass(frozen=True)
class DetectionResult:
    language: str | None
    framework: str | None
    deployment_target: str | None
    ci_provider: str | None


def detect_stack(files: dict[str, str]) -> DetectionResult:
    language, matched_files = _detect_language(files)
    framework = _detect_framework(language, files, matched_files)
    deployment_target = "docker" if "Dockerfile" in files else None
    ci_provider = (
        "github_actions" if any(path.startswith(_CI_WORKFLOWS_PREFIX) for path in files) else None
    )

    return DetectionResult(
        language=language,
        framework=framework,
        deployment_target=deployment_target,
        ci_provider=ci_provider,
    )


def relevant_file_paths(all_paths: list[str]) -> list[str]:
    return [
        path
        for path in all_paths
        if path in _RELEVANT_FILENAMES or path.startswith(_CI_WORKFLOWS_PREFIX)
    ]


def _detect_language(files: dict[str, str]) -> tuple[str | None, tuple[str, ...]]:
    for language, candidate_paths in _LANGUAGE_SIGNATURES:
        matched = tuple(path for path in candidate_paths if path in files)
        if matched:
            return language, matched
    return None, ()


def _detect_framework(
    language: str | None, files: dict[str, str], matched_files: tuple[str, ...]
) -> str | None:
    if language == "python":
        return _detect_python_framework(files, matched_files)
    if language == "javascript":
        return _detect_javascript_framework(files)
    return None


def _detect_python_framework(files: dict[str, str], matched_files: tuple[str, ...]) -> str | None:
    for path in matched_files:
        content = files[path].lower()
        for framework in _PYTHON_FRAMEWORK_SIGNATURES:
            if framework in content:
                return framework
    return None


def _detect_javascript_framework(files: dict[str, str]) -> str | None:
    content = files.get("package.json")
    if content is None:
        return None

    try:
        manifest = json.loads(content)
    except json.JSONDecodeError:
        return None

    dependency_keys = {
        *manifest.get("dependencies", {}),
        *manifest.get("devDependencies", {}),
    }

    for framework in _JAVASCRIPT_FRAMEWORK_SIGNATURES:
        if framework in dependency_keys:
            return framework
    return None
