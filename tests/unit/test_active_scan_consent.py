"""ADR-0024 decisions 1, 2 and 3, over `UpdateScannerConfigUseCase` and the entity.

Separate from `test_update_scanner_config.py` rather than appended to it, because the
subject is different: that file is about scanner configuration, this one is about an
authorization act that happens to be stored beside it.

**What every test here is really about is one comparison** —
`ScannerConfig.active_scan_consent_in_force` — and the failure this file exists to
prevent is a green suite that passes whether or not that comparison runs.
"""

import dataclasses

import pytest

from verion.modules.projects.application.update_scanner_config import UpdateScannerConfigUseCase
from verion.modules.projects.domain.exceptions import (
    InsufficientPermissions,
    InvalidScannerConfig,
)
from verion.modules.projects.domain.project import Project, ProjectMembership, Role
from verion.modules.projects.domain.scanner_config import ScannerConfig

_PROJECT_ID = "project-1"
_OWNER_ID = "owner-1"
_MEMBER_ID = "member-1"
_STAGING = "https://staging.acme.example"
_PRODUCTION = "https://acme.example"


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


async def test_an_owner_grants_consent_against_the_target_in_the_same_request(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )

    assert config.active_scan_consent_in_force is True
    assert config.active_scan_consent_target == _STAGING
    assert config.active_scan_consent_granted_at == clock.now()
    assert config.active_scan_consent_granted_by == _OWNER_ID


async def test_a_member_cannot_grant_active_scan_consent(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """The sibling of `test_a_member_cannot_change_scanner_config`, and the reason
    ADR-0024 decision 2 needed no new argument: this is the same owner gate, applied
    to the stronger form of the act it already gates."""
    member_id = await _seed(project_repository, membership_repository, clock, role=Role.MEMBER)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InsufficientPermissions):
        await use_case.execute(
            project_id=_PROJECT_ID,
            user_id=member_id,
            enabled_tools=["zap"],
            zap_target_url=_STAGING,
            active_scan_consent=True,
        )

    assert await scanner_config_repository.get_by_project_id(_PROJECT_ID) is None


async def test_consent_granted_then_the_target_changed_is_not_in_force_and_raises_nothing(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """**ADR-0024 decision 3, and the whole reason that decision exists.** Consent
    granted for staging, target later repointed at production, no consent restated.

    Two assertions, and the second is not decoration: the row survives, so this is
    not "the grant was deleted" — it is the grant still sitting there and the verdict
    being false, which is the only version that also covers a reader who looks at the
    columns and concludes consent is present. And nothing raises: decision 3 is
    explicit that a changed target is a configuration act, not a failure.
    """
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )
    await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_PRODUCTION,
        active_scan_consent=None,
    )

    assert config.active_scan_consent_in_force is False
    assert config.active_scan_consent_target == _STAGING
    assert config.zap_target_url == _PRODUCTION
    stored = await scanner_config_repository.get_by_project_id(_PROJECT_ID)
    assert stored.active_scan_consent_in_force is False


async def test_consent_survives_a_write_that_leaves_the_target_unchanged(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """The only case in this file whose SUBJECT is the positive verdict.

    A `_resolve_consent` that cleared consent on every write does not slip past the rest
    of the file: `test_consent_granted_then_the_target_changed_is_not_in_force_and_raises_nothing`
    catches that mutant too. But it catches it incidentally, through an assertion about
    `active_scan_consent_target` rather than about `in_force`, so its going red says
    nothing about the property this test is for. That is G20's argument arriving in a
    test file.

    The original `granted_at` and `granted_by` are asserted rather than just the
    verdict, because re-stamping them on an unrelated edit would also read as True
    while destroying the only actor record this resource keeps (G43).
    """
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )
    granted = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap", "semgrep"],
        zap_target_url=_STAGING,
        active_scan_consent=None,
    )

    assert config.active_scan_consent_in_force is True
    assert config.active_scan_consent_granted_at == granted.active_scan_consent_granted_at
    assert config.active_scan_consent_granted_by == granted.active_scan_consent_granted_by


async def test_a_cosmetic_target_edit_voids_consent(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """ADR-0024 decision 3 names this residue explicitly rather than hedging it, so it
    is pinned here rather than discovered as a bug report. A trailing slash is the same
    target and a different string; equality is on the stored value verbatim, because a
    normalizer would be a second place for the two sides to disagree.
    """
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )
    await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING + "/",
        active_scan_consent=None,
    )

    assert config.active_scan_consent_in_force is False


async def test_an_explicit_withdrawal_clears_all_three_columns(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )
    await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )

    config = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=False,
    )

    assert config.active_scan_consent_in_force is False
    assert config.active_scan_consent_target is None
    assert config.active_scan_consent_granted_at is None
    assert config.active_scan_consent_granted_by is None


async def test_all_three_columns_null_is_the_same_state_as_never_granted(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    """ADR-0024 decision 1 requires "consent absent" and "consent withdrawn" to be one
    state. Asserted by comparing the two configs field for field rather than by
    checking each is falsy, since two different falsy shapes would pass that."""
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    never_granted = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=None,
    )
    await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=True,
    )
    withdrawn = await use_case.execute(
        project_id=_PROJECT_ID,
        user_id=_OWNER_ID,
        enabled_tools=["zap"],
        zap_target_url=_STAGING,
        active_scan_consent=False,
    )

    assert never_granted == withdrawn


async def test_granting_consent_without_a_target_is_rejected(
    project_repository, membership_repository, scanner_config_repository, id_generator, clock
):
    await _seed(project_repository, membership_repository, clock)
    use_case = _use_case(
        project_repository, membership_repository, scanner_config_repository, id_generator, clock
    )

    with pytest.raises(InvalidScannerConfig):
        await use_case.execute(
            project_id=_PROJECT_ID,
            user_id=_OWNER_ID,
            enabled_tools=["semgrep"],
            zap_target_url=None,
            active_scan_consent=True,
        )

    assert await scanner_config_repository.get_by_project_id(_PROJECT_ID) is None


def test_a_partially_populated_consent_is_not_in_force(clock):
    """Every one of the three columns is load-bearing, asserted one at a time.

    A hand-edited row, or a future write path that sets a target and forgets the
    actor, must not read as consent. Checking only the target would let both of the
    others rot into decoration.
    """
    complete = ScannerConfig(
        id="config-1",
        project_id=_PROJECT_ID,
        enabled_tools=(),
        zap_target_url=_STAGING,
        updated_at=clock.now(),
        active_scan_consent_target=_STAGING,
        active_scan_consent_granted_at=clock.now(),
        active_scan_consent_granted_by=_OWNER_ID,
    )
    assert complete.active_scan_consent_in_force is True

    for missing in (
        "active_scan_consent_target",
        "active_scan_consent_granted_at",
        "active_scan_consent_granted_by",
    ):
        partial = dataclasses.replace(complete, **{missing: None})
        assert partial.active_scan_consent_in_force is False, missing
