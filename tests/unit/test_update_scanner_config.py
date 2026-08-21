import pytest

from verion.modules.projects.application.update_scanner_config import UpdateScannerConfigUseCase
from verion.modules.projects.domain.exceptions import (
    InsufficientPermissions,
    InvalidScannerConfig,
    ProjectNotFound,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.shared_kernel.scanner_tools import ScannerTool

_PROJECT_ID = "project-1"
_OWNER_ID = "owner-1"
_MEMBER_ID = "member-1"
_TARGET = "https://staging.acme.example"


def _use_case(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
) -> UpdateScannerConfigUseCase:
    return UpdateScannerConfigUseCase(
        projects=project_repository,
        memberships=membership_repository,
        scanner_configs=scanner_config_repository,
        id_generator=id_generator,
        clock=clock,
    )


async def _seed(project_repository, membership_repository, clock, role: Role = Role.OWNER):
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=clock.now())
    )
    user_id = _OWNER_ID if role is Role.OWNER else _MEMBER_ID
    await membership_repository.add(
        ProjectMembership(project_id=_PROJECT_ID, user_id=user_id, role=role)
    )
    return user_id


async def test_owner_can_enable_scanners(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["semgrep", "trivy"],
        zap_target_url=None,
    )

    assert config.enabled_tools == (ScannerTool.SEMGREP, ScannerTool.TRIVY)
    assert config.updated_at == clock.now()
    stored = await scanner_config_repository.get_by_project_id(_PROJECT_ID)
    assert stored == config


async def test_a_member_cannot_change_scanner_config(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """Owner-gated, matching M2.3: enabling a scanner costs real compute and
    can point an attack tool at a URL, so it is a write action."""
    member_id = await _seed(project_repository, membership_repository, clock, role=Role.MEMBER)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=_PROJECT_ID,
            user_id=member_id,
            enabled_tools=["semgrep"],
            zap_target_url=None,
        )

    assert await scanner_config_repository.get_by_project_id(_PROJECT_ID) is None


async def test_an_unknown_project_is_rejected(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(
            project_id="nope", user_id=_OWNER_ID, enabled_tools=["semgrep"], zap_target_url=None
        )


async def test_an_unknown_tool_name_is_rejected_with_the_known_ones_listed(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """Rejected at write rather than accepted and left to fail every later scan
    wholesale on a typo."""
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InvalidScannerConfig, match="Unknown scanner 'semgrp'"):
        await use_case.execute(
            project_id=_PROJECT_ID,
            user_id=_OWNER_ID,
            enabled_tools=["semgrp"],
            zap_target_url=None,
        )


async def test_enabling_zap_without_a_target_is_rejected(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InvalidScannerConfig, match="requires a zap_target_url"):
        await use_case.execute(
            project_id=_PROJECT_ID,
            user_id=_OWNER_ID,
            enabled_tools=["zap"],
            zap_target_url=None,
        )


@pytest.mark.parametrize("url", ["ftp://acme.example", "not-a-url", "https://"])
async def test_a_malformed_target_url_is_rejected(
    url, project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InvalidScannerConfig):
        await use_case.execute(
            project_id=_PROJECT_ID, user_id=_OWNER_ID, enabled_tools=["zap"], zap_target_url=url
        )


async def test_a_private_target_is_accepted_here_and_left_to_the_runtime_ssrf_gate(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """Deliberate, and the point of ADR-013's placement.

    Rejecting private targets here would make the stored URL look
    pre-approved — the reasoning that would later make ZapAdapter.run()'s gate
    seem redundant. It is not: DNS can rebind between configuring a target and
    scanning it, so the resolved-IP check has to run at scan time, every time.
    This test exists to stop someone "hardening" the write path and quietly
    creating that impression.
    """
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url="http://127.0.0.1:8080",
    )

    assert config.zap_target_url == "http://127.0.0.1:8080"


async def test_updating_an_existing_config_keeps_its_id_and_clears_a_stale_target(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )
    first = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_TARGET,
    )

    second = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["semgrep"],
        zap_target_url=None,
    )

    # One configuration per project being edited, not a new record each time.
    assert second.id == first.id
    # Disabling ZAP does not leave its target behind.
    assert second.zap_target_url is None
    stored = await scanner_config_repository.get_by_project_id(_PROJECT_ID)
    assert stored == second


@pytest.mark.parametrize(
    "url",
    [
        "https://admin:hunter2@app.acme.example",
        "https://admin@app.acme.example",
        # Credential-bearing *and* otherwise-invalid, one per remaining branch.
        # These are the cases branch ordering decides: if the userinfo check
        # ran after the scheme or hostname check, these would raise from a
        # branch that quotes the URL, and the credential would land in the
        # message. Parametrized rather than asserted once so the property is
        # pinned across the whole function, not just its happy path.
        "ftp://admin:hunter2@app.acme.example",
        "notaurl://admin:hunter2@",
    ],
)
async def test_a_credential_in_the_target_url_is_rejected_and_never_echoed(
    url, project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """Rule 12, for the persistence sink this issue introduces.

    `urlparse` leaves `.hostname` populated when userinfo is present, so the
    scheme and hostname checks both pass on `https://admin:hunter2@host` — and
    the value would then be stored in `scanner_configs.zap_target_url`,
    returned by this resource's own response schema, and (had it reached
    ZapAdapter) written into a persisted `ScanResult.failure_reason`. Three
    sinks rule 12 covers, from one missing check.

    The second assertion matters as much as the first: an error message that
    quotes the rejected URL back would leak the credential it exists to reject.
    """
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InvalidScannerConfig) as exc_info:
        await use_case.execute(
            project_id=_PROJECT_ID, user_id=_OWNER_ID, enabled_tools=["zap"], zap_target_url=url
        )

    assert "hunter2" not in str(exc_info.value)
    assert url not in str(exc_info.value)
    assert await scanner_config_repository.get_by_project_id(_PROJECT_ID) is None


async def test_duplicate_tool_names_are_collapsed(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["semgrep", "semgrep", "trivy"],
        zap_target_url=None,
    )

    assert config.enabled_tools == (ScannerTool.SEMGREP, ScannerTool.TRIVY)
