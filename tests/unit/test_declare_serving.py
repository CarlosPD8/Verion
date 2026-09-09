"""`DeclareServingUseCase` — the gate, the compare-and-set, and the URL check.

Three subjects, and the third is the one most likely to be mistaken for decoration:

- **Owner-gating and its placement.** ADR-0028 decision 3, and the ordering property
  `UpdateScannerConfigUseCase` established — a check that happens to run first is not the
  same as a check that must.
- **The compare-and-set.** ADR-0028's 2026-09-09 amendment A: a declaration whose values
  are not the live ones is refused rather than stored void from birth.
- **`validate_zap_target_url` on the declare path, which is NOT dead code.** Under the
  match requirement a malformed declared URL also mismatches, so the validator looks
  unreachable. It is not: "`zap_target_url` was validated when it was written" is a
  property of one caller, not of `ScannerConfigRepositoryPort`, which is a `Protocol`.
  Plant an unvalidated config through the fake and declare the identical string — the
  match holds and only the validator rejects. Measured rather than asserted: deleting the
  `validate_zap_target_url` call turns the **declare half of the set-equality pair** red
  along with `test_a_target_url_planted_unvalidated_is_still_rejected_on_the_declare_path`
  — and the config half stays green, which is the asymmetry that makes the pair a
  measurement.
"""

import operator

import pytest

from verion.modules.projects.application.declare_serving import DeclareServingUseCase
from verion.modules.projects.application.update_scanner_config import UpdateScannerConfigUseCase
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    InsufficientPermissions,
    InvalidScannerConfig,
    ProjectNotFound,
    ServingDeclarationMismatch,
)
from verion.modules.projects.domain.project import ConnectedRepo, Project, ProjectMembership, Role
from verion.modules.projects.domain.scanner_config import ScannerConfig

_PROJECT_ID = "project-1"
_OWNER_ID = "owner-1"
_MEMBER_ID = "member-1"

_TARGET = "https://staging.example.com"
_REPO_URL = "https://github.com/example/repo"
_BRANCH = "main"


def _use_case(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
) -> DeclareServingUseCase:
    return DeclareServingUseCase(
        projects=project_repository,
        memberships=membership_repository,
        serving_declarations=serving_declaration_repository,
        scanner_configs=scanner_config_repository,
        connected_repos=connected_repo_repository,
        id_generator=id_generator,
        clock=clock,
    )


async def _seed(
    project_repository,
    membership_repository,
    scanner_config_repository,
    connected_repo_repository,
    clock,
    *,
    role: Role = Role.OWNER,
    zap_target_url: str | None = _TARGET,
    repo_url: str = _REPO_URL,
    default_branch: str = _BRANCH,
    with_repo: bool = True,
    with_config: bool = True,
) -> str:
    """Seeds the live state a declaration is compared against.

    The scanner config is written **straight through the repository fake**, never through
    `UpdateScannerConfigUseCase`. That is deliberate and is the whole basis of the
    validator tests below: going through the use case would make every planted
    `zap_target_url` one that already passed `validate_zap_target_url`, so the declare
    path's own call could never be reached and its deletion could never be caught.
    """
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=clock.now())
    )
    user_id = _OWNER_ID if role is Role.OWNER else _MEMBER_ID
    await membership_repository.add(
        ProjectMembership(project_id=_PROJECT_ID, user_id=user_id, role=role)
    )
    if with_repo:
        await connected_repo_repository.add(
            ConnectedRepo(
                id="repo-1",
                project_id=_PROJECT_ID,
                provider="github",
                url=repo_url,
                default_branch=default_branch,
            )
        )
    if with_config:
        await scanner_config_repository.upsert(
            ScannerConfig(
                id="config-1",
                project_id=_PROJECT_ID,
                enabled_tools=(),
                zap_target_url=zap_target_url,
                updated_at=clock.now(),
            )
        )
    return user_id


async def _declare(use_case, user_id, **overrides):
    values = {
        "declared_target_url": _TARGET,
        "declared_repo_url": _REPO_URL,
        "declared_default_branch": _BRANCH,
    }
    values.update(overrides)
    return await use_case.execute(project_id=_PROJECT_ID, user_id=user_id, **values)


# --- the happy path ---------------------------------------------------------


async def test_an_owner_declaring_the_live_values_gets_a_row_that_is_in_force(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    declaration, in_force = await _declare(use_case, user_id)

    assert in_force is True
    assert declaration.declared_by == _OWNER_ID
    assert declaration.declared_at == clock.now()
    assert declaration.id == "fake-id-1"
    assert await serving_declaration_repository.get_by_project_id(_PROJECT_ID) == declaration


# --- the gate ---------------------------------------------------------------


async def test_a_member_cannot_declare(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """Owner-gated per ADR-0028 decision 3, and nothing is written on the refusal."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        role=Role.MEMBER,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InsufficientPermissions):
        await _declare(use_case, user_id)

    assert await serving_declaration_repository.get_by_project_id(_PROJECT_ID) is None


async def test_declaring_authorizes_before_it_touches_any_of_the_three_post_gate_ports(
    project_repository,
    membership_repository,
    exploding_serving_declaration_repository,
    exploding_scanner_config_repository,
    exploding_connected_repo_repository,
    id_generator,
    clock,
):
    """The gate must run first, not merely run.

    All three post-gate repositories raise on every call, so this fails if `require_owner`
    is moved below any of them — a refactor that would leave the denial working and every
    other test green.

    **What it does not prove**, stated because the fake's own docstring is where the bound
    lives and a test name cannot carry it: `projects.get_by_id` and
    `memberships.get_by_project_and_user` necessarily run *before* the gate in every use
    case in this module, since that is how 404-then-403 is produced. Only the three ports
    named here are covered.
    """
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=clock.now())
    )
    await membership_repository.add(
        ProjectMembership(project_id=_PROJECT_ID, user_id=_MEMBER_ID, role=Role.MEMBER)
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        exploding_serving_declaration_repository,
        exploding_scanner_config_repository,
        exploding_connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InsufficientPermissions):
        await _declare(use_case, _MEMBER_ID)


async def test_an_absent_project_is_reported_before_anything_else(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(ProjectNotFound):
        await _declare(use_case, _OWNER_ID)


# --- the compare-and-set ----------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("declared_target_url", "https://other.example.com"),
        ("declared_repo_url", "https://github.com/example/other"),
        ("declared_default_branch", "develop"),
    ],
)
async def test_a_declaration_that_does_not_match_the_live_values_is_refused_and_not_stored(
    field,
    value,
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """ADR-0028's 2026-09-09 amendment A, per field.

    Parametrized over all three so the check cannot be satisfied by comparing one pair.
    The refusal must also leave nothing behind: a stored-then-refused row would be the
    void-from-birth record the amendment exists to prevent, arriving by a different door.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(ServingDeclarationMismatch):
        await _declare(use_case, user_id, **{field: value})

    assert await serving_declaration_repository.get_by_project_id(_PROJECT_ID) is None


async def test_the_mismatch_message_quotes_none_of_the_declared_values(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """Rule 12, structurally rather than by branch ordering.

    **All three declared values are planted and all three are asserted absent.** An
    earlier version of this test overrode one field and asserted a literal for a second
    that it never passed in, so the second assertion could not fail — which made it read
    as covering ground it did not. The branch is what makes all three reachable at once:
    a well-formed but non-live target and a well-formed but non-live branch both survive
    the validators and land on the mismatch.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )
    planted_target = "https://target-that-is-not-live.example.com"
    planted_repo = "https://github.com/example/repo-that-is-not-live"
    planted_branch = "branch-that-is-not-live"

    with pytest.raises(ServingDeclarationMismatch) as caught:
        await _declare(
            use_case,
            user_id,
            declared_target_url=planted_target,
            declared_repo_url=planted_repo,
            declared_default_branch=planted_branch,
        )

    message = str(caught.value)
    assert planted_target not in message
    assert planted_repo not in message
    assert planted_branch not in message


async def test_declaring_without_a_connected_repository_is_refused(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """There is no tree side to declare against, which is a different answer from a
    mismatch. `declaration_in_force` folds both into `False` by design, so the two are
    separated here before it is called."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        with_repo=False,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(ConnectedRepoNotFound):
        await _declare(use_case, user_id)


@pytest.mark.parametrize("with_config", [True, False], ids=["cleared_target", "no_config_row"])
async def test_declaring_without_a_configured_target_is_refused(
    with_config,
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """M5.4's shape: a declaration against nothing would be stored, be immediately void,
    and read as "never declared" — the right answer arrived at by a route that tells the
    owner nothing. Both absences are covered, since a cleared target and a missing row
    reach the same branch by different routes."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        zap_target_url=None,
        with_config=with_config,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InvalidScannerConfig):
        await _declare(use_case, user_id)


async def test_re_declaring_replaces_the_previous_declaration(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """Re-declaring after a configuration change is the routine act, not the edge case —
    ADR-0028 decision 2 accepts that a cosmetic edit voids a declaration."""
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )
    await _declare(use_case, user_id)

    moved = "https://prod.example.com"
    await scanner_config_repository.upsert(
        ScannerConfig(
            id="config-1",
            project_id=_PROJECT_ID,
            enabled_tools=(),
            zap_target_url=moved,
            updated_at=clock.now(),
        )
    )
    declaration, in_force = await _declare(use_case, user_id, declared_target_url=moved)

    assert in_force is True
    stored = await serving_declaration_repository.get_by_project_id(_PROJECT_ID)
    assert stored is not None
    assert stored.declared_target_url == moved


# --- the URL check, and set equality with the scanner-config write path -----

# ONE table, driven through BOTH write paths below. Two hand-written lists would be free
# to drift, which is the thing this pins against: `declared_target_url` must accept
# exactly the set `zap_target_url` accepts. Wider and a URL could be declared that can
# never be configured, leaving a permanently void row with nothing saying why; narrower
# and a configurable target could not be declared.
_URLS = [
    ("https://staging.example.com", True),
    ("http://staging.example.com:8080/app", True),
    ("https://user:pass@staging.example.com", False),
    ("https://:pass@staging.example.com", False),
    ("ftp://staging.example.com", False),
    ("staging.example.com", False),
    ("https://", False),
    ("", False),
]


@pytest.mark.parametrize(("url", "accepted"), _URLS, ids=[repr(u) for u, _ in _URLS])
async def test_the_scanner_config_write_path_accepts_exactly_these_urls(
    url,
    accepted,
    project_repository,
    membership_repository,
    scanner_config_repository,
    id_generator,
    clock,
):
    """Half one of the set-equality pair. Same table, same expectations."""
    await project_repository.add(
        Project(id=_PROJECT_ID, owner_id=_OWNER_ID, name="Widgets", created_at=clock.now())
    )
    await membership_repository.add(
        ProjectMembership(project_id=_PROJECT_ID, user_id=_OWNER_ID, role=Role.OWNER)
    )
    use_case = UpdateScannerConfigUseCase(
        projects=project_repository,
        memberships=membership_repository,
        scanner_configs=scanner_config_repository,
        id_generator=id_generator,
        clock=clock,
    )

    async def call():
        return await use_case.execute(
            project_id=_PROJECT_ID, user_id=_OWNER_ID, enabled_tools=[], zap_target_url=url
        )

    if accepted:
        assert (await call()).zap_target_url == url
    else:
        with pytest.raises(InvalidScannerConfig):
            await call()


@pytest.mark.parametrize(("url", "accepted"), _URLS, ids=[repr(u) for u, _ in _URLS])
async def test_the_declare_write_path_accepts_exactly_the_same_urls(
    url,
    accepted,
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """Half two, and the fixture is what makes it a measurement rather than a tautology.

    **The live config is planted at the table's own value, through the repository fake.**
    So the compare-and-set always passes and the validator is the only thing that can
    reject — which is the point: driven through the two HTTP paths instead, the accept
    sets would be equal *by construction*, since the only route into `zap_target_url` is
    the config path and the declare path requires equality with it. That test would be
    green whether or not the validator was called at all.

    It doubles as the proof that the validator is reachable on this path: every rejected
    row here has a live `zap_target_url` equal to the declared one, so nothing but
    `validate_zap_target_url` refuses it.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        zap_target_url=url,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    async def call():
        return await _declare(use_case, user_id, declared_target_url=url)

    if accepted:
        _, in_force = await call()
        assert in_force is True
    else:
        with pytest.raises(InvalidScannerConfig):
            await call()


def test_the_two_write_paths_are_driven_by_one_table():
    """The precondition the pair above rests on, asserted rather than assumed.

    Two tables that happened to agree today would make the set-equality claim vacuous
    tomorrow, so what is asserted is object identity rather than equality — `operator.is_`
    says that in the assertion's own form rather than in a comment.

    **Deliberately not cited as a G8 case**, because it is not one: that entry's subject
    is a test whose meaning depends on operand order, which `ruff --fix`'s SIM300 can
    invert. `a is b` over two names is not a SIM300 candidate in either order, so citing
    G8 here would widen an entry whose enumeration of affected files is load-bearing.
    """
    config_table = test_the_scanner_config_write_path_accepts_exactly_these_urls.pytestmark[0].args[
        1
    ]
    declare_table = test_the_declare_write_path_accepts_exactly_the_same_urls.pytestmark[0].args[1]

    assert operator.is_(config_table, declare_table)
    assert operator.is_(config_table, _URLS)


async def test_a_target_url_planted_unvalidated_is_still_rejected_on_the_declare_path(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """The declare path does not inherit its safety from `UpdateScannerConfigUseCase`.

    Under the compare-and-set, a malformed declared URL also mismatches, so the validator
    looks unreachable and could be deleted without any other test noticing. It is not
    unreachable: "`zap_target_url` was validated when written" is a property of one
    caller, not of `ScannerConfigRepositoryPort`, which is a `Protocol` — and a manual
    database fix, a seed script or a future admin route all produce a row that caller
    never touched. Here the config is planted with userinfo and the identical string is
    declared, so the match holds and only `validate_zap_target_url` can refuse.

    The exception is `InvalidScannerConfig` rather than a mismatch, and that is the
    assertion: a mismatch here would mean the validator never ran.
    """
    credentialed = "https://tokenuser:s3cr3t@staging.example.com"
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        zap_target_url=credentialed,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InvalidScannerConfig) as caught:
        await _declare(use_case, user_id, declared_target_url=credentialed)

    assert "s3cr3t" not in str(caught.value)
    assert await serving_declaration_repository.get_by_project_id(_PROJECT_ID) is None


async def test_a_member_declaring_a_credentialed_url_is_refused_for_the_membership_not_the_url(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """The gate precedes the VALIDATORS, not only the repositories.

    The exploding-fake test above covers the three post-gate ports and says so. It cannot
    cover this: moving `validate_zap_target_url` or `validate_declared_repo_url` above
    `require_owner` touches no repository, so every other test in the suite stays green
    while an unauthorized caller starts learning whether their payload was well-formed.
    Verified by mutation — hoisting either validator above the gate turned this test red
    alone.

    Both URLs carry credentials, so a hoisted validator of either kind would surface
    `InvalidScannerConfig`. The assertion is that it does not.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
        role=Role.MEMBER,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InsufficientPermissions):
        await _declare(
            use_case,
            user_id,
            declared_target_url="https://tokenuser:s3cr3t@staging.example.com",
            declared_repo_url="https://tokenuser:s3cr3t@github.com/example/repo",
        )


async def test_a_declared_repo_url_carrying_credentials_is_refused_and_never_echoed(
    project_repository,
    membership_repository,
    serving_declaration_repository,
    scanner_config_repository,
    connected_repo_repository,
    id_generator,
    clock,
):
    """Rule 12's own requirement, on the field that needs it most.

    `declared_repo_url` is stored and then returned by a **member-level** read, which is a
    wider audience than `ConnectedRepo.url` itself has — both routes exposing that are
    owner-gated writes. And that value is stored completely unvalidated, so without
    `validate_declared_repo_url` a credential-bearing repository URL would be copied into
    a second table and served. Rule 12 requires a module handling such a field to ship an
    explicit test; this is it.
    """
    user_id = await _seed(
        project_repository,
        membership_repository,
        scanner_config_repository,
        connected_repo_repository,
        clock,
    )
    use_case = _use_case(
        project_repository,
        membership_repository,
        serving_declaration_repository,
        scanner_config_repository,
        connected_repo_repository,
        id_generator,
        clock,
    )

    with pytest.raises(InvalidScannerConfig) as caught:
        await _declare(
            use_case, user_id, declared_repo_url="https://tokenuser:s3cr3t@github.com/example/repo"
        )

    assert "s3cr3t" not in str(caught.value)
    assert "tokenuser" not in str(caught.value)
    assert await serving_declaration_repository.get_by_project_id(_PROJECT_ID) is None
