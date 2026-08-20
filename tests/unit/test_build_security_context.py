from datetime import UTC, datetime

import pytest

from verion.modules.projects.application.build_security_context import (
    BuildSecurityContextUseCase,
)
from verion.modules.projects.domain.context_detection import DetectionResult, detect_stack
from verion.modules.projects.domain.exceptions import ProjectNotFound
from verion.modules.projects.domain.project import Project


async def _seed_project(project_repository, clock, project_id="project-1", owner_id="owner-1"):
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    return project


def _use_case(project_repository, security_context_repository, clock, id_generator, detector):
    return BuildSecurityContextUseCase(
        projects=project_repository,
        security_contexts=security_context_repository,
        detector=detector,
        id_generator=id_generator,
        clock=clock,
    )


async def test_builds_and_persists_a_security_context(
    project_repository, security_context_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    use_case = _use_case(
        project_repository, security_context_repository, clock, id_generator, detect_stack
    )

    context = await use_case.execute(
        project_id=project.id,
        files={"pyproject.toml": 'dependencies = ["fastapi"]', "Dockerfile": "FROM python:3.12"},
    )

    assert context.project_id == project.id
    assert context.language == "python"
    assert context.framework == "fastapi"
    assert context.database is None
    assert context.deployment_target == "docker"
    assert context.ci_provider is None
    assert context.exposure_tags == []
    assert context.created_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert await security_context_repository.get_by_project_id(project.id) == context


async def test_raises_project_not_found_for_an_unknown_project(
    project_repository, security_context_repository, clock, id_generator
):
    use_case = _use_case(
        project_repository, security_context_repository, clock, id_generator, detect_stack
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(project_id="does-not-exist", files={})


async def test_uses_the_injected_detector_rather_than_a_hardcoded_one(
    project_repository, security_context_repository, clock, id_generator
):
    project = await _seed_project(project_repository, clock)
    stub_result = DetectionResult(
        language="rust", framework=None, deployment_target=None, ci_provider=None
    )
    use_case = _use_case(
        project_repository,
        security_context_repository,
        clock,
        id_generator,
        detector=lambda files: stub_result,
    )

    context = await use_case.execute(project_id=project.id, files={})

    assert context.language == "rust"
