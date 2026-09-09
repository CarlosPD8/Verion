"""`GetServingDeclarationUseCase` — member-gated, and it returns the verdict.

The verdict is the subject worth naming: a read that returned only the three stored
strings would make every caller re-implement `declaration_in_force`, which is the
copy-of-the-rule failure `ServingDeclarationRepositoryPort`'s docstring rules out one
boundary over. That is why `test_the_read_returns_the_verdict_not_only_the_stored_values`
exists rather than being folded into the round-trip case.
"""

from datetime import UTC, datetime

import pytest

from verion.modules.projects.application.get_serving_declaration import (
    GetServingDeclarationUseCase,
)
from verion.modules.projects.domain.exceptions import (
    InsufficientPermissions,
    ProjectNotFound,
    ServingDeclarationNotFound,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.modules.projects.domain.serving_declaration import ServingDeclaration

_PROJECT_ID = "project-1"
_OWNER_ID = "owner-1"
_MEMBER_ID = "member-1"
_STRANGER_ID = "stranger-1"
_AT = datetime(2026, 1, 1, tzinfo=UTC)

_TARGET = "https://staging.example.com"
_REPO_URL = "https://github.com/example/repo"
_BRANCH = "main"


def _use_case(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
) -> GetServingDeclarationUseCase:
    return GetServingDeclarationUseCase(
        projects=project_repository,
        memberships=membership_repository,
        serving_declarations=serving_declaration_repository,
        scanner_configs=scanner_config_repository,
        connected_repos=connected_repo_repository,
    )


async def _seed(
    project_repository,
    membership_repository,
    scanner_config_repository,
    connected_repo_repository,
    *,
    role: Role = Role.MEMBER,
    zap_target_url: str | None = _TARGET,
) -> str:
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=_AT)
    )
    user_id = _OWNER_ID if role is Role.OWNER else _MEMBER_ID
    await membership_repository.add(
        ProjectMembership(project_id=_PROJECT_ID, user_id=user_id, role=role)
    )
    await connected_repo_repository.add(
        ConnectedRepo(
            id="repo-1",
            project_id=_PROJECT_ID,
            provider="github",
            url=_REPO_URL,
            default_branch=_BRANCH,
        )
    )
    await scanner_config_repository.upsert(
        ScannerConfig(
            id="config-1",
            project_id=_PROJECT_ID,
            enabled_tools=(),
            zap_target_url=zap_target_url,
            updated_at=_AT,
        )
    )
    return user_id


def _declaration() -> ServingDeclaration:
    return ServingDeclaration(
        id="declaration-1",
        project_id=_PROJECT_ID,
        declared_target_url=_TARGET,
        declared_repo_url=_REPO_URL,
        declared_default_branch=_BRANCH,
        declared_at=_AT,
        declared_by=_OWNER_ID,
    )


async def test_a_member_reads_the_declaration_and_its_verdict(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    """Member-level, matching `GetSecurityContextUseCase`: this module's split is writes
    require OWNER and reads require membership."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
    )
    await serving_declaration_repository.upsert(_declaration())

    declaration, in_force = await _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
    ).execute(project_id=_PROJECT_ID, user_id=user_id)

    assert in_force is True
    assert declaration == _declaration()


async def test_the_read_returns_the_verdict_not_only_the_stored_values(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    """The same unchanged row reads differently once the live target moves.

    Nothing is written between the two reads — the row is identical and only the
    configuration around it changed, which is what makes ADR-0028 decision 2's rule
    read-time. A use case that returned the stored values alone could not express this,
    and every caller would have to rebuild the comparison to recover it.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
    )
    await serving_declaration_repository.upsert(_declaration())
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
    )

    _, before = await use_case.execute(project_id=_PROJECT_ID, user_id=user_id)
    await scanner_config_repository.upsert(
        ScannerConfig(
            id="config-1",
            project_id=_PROJECT_ID,
            enabled_tools=(),
            zap_target_url="https://prod.example.com",
            updated_at=_AT,
        )
    )
    stored, after = await use_case.execute(project_id=_PROJECT_ID, user_id=user_id)

    assert before is True
    assert after is False
    assert stored == _declaration()


async def test_a_project_that_never_declared_raises_rather_than_returning_a_null_row(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    """ "Nobody has declared anything" and "somebody declared something that has gone
    stale" call for different acts by the owner, so they are different answers rather
    than one `in_force: false`. `GetSecurityContextUseCase` raises for the same reason."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
    )

    with pytest.raises(ServingDeclarationNotFound):
        await _use_case(
            project_repository,
            membership_repository,
            serving_declaration_repository,
            scanner_config_repository,
            connected_repo_repository,
        ).execute(project_id=_PROJECT_ID, user_id=user_id)


async def test_a_non_member_cannot_read_the_declaration(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
    )
    await serving_declaration_repository.upsert(_declaration())

    with pytest.raises(InsufficientPermissions):
        await _use_case(
            project_repository,
            membership_repository,
            serving_declaration_repository,
            scanner_config_repository,
            connected_repo_repository,
        ).execute(project_id=_PROJECT_ID, user_id=_STRANGER_ID)


async def test_reading_authorizes_before_it_touches_any_of_the_three_post_gate_ports(
    project_repository,
    membership_repository,
    exploding_serving_declaration_repository,
    exploding_scanner_config_repository,
    exploding_connected_repo_repository,
):
    """The gate-placement property, on the read side. See
    `ExplodingServingDeclarationRepository`'s docstring for the two ports this cannot
    cover and why no use case in this module can."""
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=_AT)
    )

    with pytest.raises(InsufficientPermissions):
        await _use_case(
            project_repository,
            membership_repository,
            exploding_serving_declaration_repository,
            exploding_scanner_config_repository,
            exploding_connected_repo_repository,
        ).execute(project_id=_PROJECT_ID, user_id=_STRANGER_ID)


async def test_an_absent_project_is_reported_before_authorization(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    with pytest.raises(ProjectNotFound):
        await _use_case(
            project_repository,
            membership_repository,
            serving_declaration_repository,
            scanner_config_repository,
            connected_repo_repository,
        ).execute(project_id=_PROJECT_ID, user_id=_MEMBER_ID)


async def test_a_declaration_survives_its_configuration_being_cleared_and_reads_as_not_in_force(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
):
    """The row is not deleted when the thing it points at goes away — the read reports it
    with a false verdict, so an owner can see what was declared and re-declare rather than
    meeting a 404 that looks like they never declared at all."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        zap_target_url=None,
    )
    await serving_declaration_repository.upsert(_declaration())

    declaration, in_force = await _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
    ).execute(project_id=_PROJECT_ID, user_id=user_id)

    assert in_force is False
    assert declaration.declared_target_url == _TARGET
