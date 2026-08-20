import pytest

from verion.modules.projects.domain.project import ConnectedRepo, Project
from verion.modules.scanning.application.handle_github_webhook import HandleGitHubWebhookUseCase
from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.exceptions import ProjectNotFound, RepoNotConnected


def _push_payload(owner: str = "octocat", repo: str = "Hello-World") -> dict:
    return {"ref": "refs/heads/main", "repository": {"name": repo, "owner": {"login": owner}}}


class _SpyConnectedRepoRepository:
    """Wraps a real fake, recording every get_by_url call — lets a test
    assert the dedup check runs *before* this lookup, not just that the
    final outcome (no scan) is correct."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.get_by_url_calls: list[str] = []

    async def add(self, connected_repo: ConnectedRepo) -> None:
        await self._inner.add(connected_repo)

    async def get_by_id(self, connected_repo_id: str):
        return await self._inner.get_by_id(connected_repo_id)

    async def get_by_project_id(self, project_id: str):
        return await self._inner.get_by_project_id(project_id)

    async def get_by_url(self, url: str):
        self.get_by_url_calls.append(url)
        return await self._inner.get_by_url(url)


class _SpyProjectRepository:
    def __init__(self, inner) -> None:
        self._inner = inner
        self.get_by_id_calls: list[str] = []

    async def add(self, project: Project) -> None:
        await self._inner.add(project)

    async def get_by_id(self, project_id: str):
        self.get_by_id_calls.append(project_id)
        return await self._inner.get_by_id(project_id)


async def _seed_connected_project(
    project_repository,
    connected_repo_repository,
    clock,
    id_generator,
    owner: str = "octocat",
    repo: str = "Hello-World",
    project_id: str = "project-1",
    owner_id: str = "owner-1",
) -> Project:
    project = Project(id=project_id, owner_id=owner_id, name="Verion", created_at=clock.now())
    await project_repository.add(project)
    await connected_repo_repository.add(
        ConnectedRepo(
            id=id_generator.new_id(),
            project_id=project_id,
            provider="github",
            url=f"https://github.com/{owner}/{repo}",
            default_branch="main",
        )
    )
    return project


def _use_case(webhook_deliveries, connected_repos, projects, trigger_scan):
    return HandleGitHubWebhookUseCase(
        webhook_deliveries=webhook_deliveries,
        connected_repos=connected_repos,
        projects=projects,
        trigger_scan=trigger_scan,
    )


async def test_a_new_push_delivery_triggers_a_scan_attributed_to_the_project_owner(
    webhook_delivery_repository,
    connected_repo_repository,
    project_repository,
    scan_repository,
    job_queue,
    id_generator,
    clock,
):
    project = await _seed_connected_project(
        project_repository, connected_repo_repository, clock, id_generator
    )
    trigger_scan = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    use_case = _use_case(
        webhook_delivery_repository, connected_repo_repository, project_repository, trigger_scan
    )

    scan = await use_case.execute(
        delivery_id="delivery-1", event_type="push", payload=_push_payload()
    )

    assert scan is not None
    assert scan.project_id == project.id
    assert scan.triggered_by == project.owner_id
    assert job_queue.enqueued_scan_ids == [scan.id]


async def test_a_redelivered_delivery_id_is_a_no_op_and_never_queries_project_resolution(
    webhook_delivery_repository,
    connected_repo_repository,
    project_repository,
    scan_repository,
    job_queue,
    id_generator,
    clock,
):
    await _seed_connected_project(
        project_repository, connected_repo_repository, clock, id_generator
    )
    trigger_scan = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    spy_connected_repos = _SpyConnectedRepoRepository(connected_repo_repository)
    spy_projects = _SpyProjectRepository(project_repository)
    use_case = _use_case(
        webhook_delivery_repository, spy_connected_repos, spy_projects, trigger_scan
    )
    first = await use_case.execute(
        delivery_id="delivery-1", event_type="push", payload=_push_payload()
    )
    assert first is not None
    spy_connected_repos.get_by_url_calls.clear()
    spy_projects.get_by_id_calls.clear()
    job_queue.enqueued_scan_ids.clear()

    second = await use_case.execute(
        delivery_id="delivery-1", event_type="push", payload=_push_payload()
    )

    assert second is None
    # The exact ordering requirement: dedup is the first and only check on
    # a redelivery — it must short-circuit before touching ConnectedRepo or
    # Project resolution at all, not just avoid re-triggering the scan.
    assert spy_connected_repos.get_by_url_calls == []
    assert spy_projects.get_by_id_calls == []
    assert job_queue.enqueued_scan_ids == []


async def test_a_ping_event_is_a_no_op(
    webhook_delivery_repository,
    connected_repo_repository,
    project_repository,
    scan_repository,
    job_queue,
    id_generator,
):
    trigger_scan = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    use_case = _use_case(
        webhook_delivery_repository, connected_repo_repository, project_repository, trigger_scan
    )

    scan = await use_case.execute(
        delivery_id="delivery-1", event_type="ping", payload={"zen": "hi"}
    )

    assert scan is None
    assert job_queue.enqueued_scan_ids == []


async def test_raises_repo_not_connected_for_an_unknown_repo(
    webhook_delivery_repository,
    connected_repo_repository,
    project_repository,
    scan_repository,
    job_queue,
    id_generator,
):
    trigger_scan = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    use_case = _use_case(
        webhook_delivery_repository, connected_repo_repository, project_repository, trigger_scan
    )

    with pytest.raises(RepoNotConnected):
        await use_case.execute(delivery_id="delivery-1", event_type="push", payload=_push_payload())
    assert job_queue.enqueued_scan_ids == []


async def test_raises_project_not_found_when_connected_repo_outlives_its_project(
    webhook_delivery_repository,
    connected_repo_repository,
    project_repository,
    scan_repository,
    job_queue,
    id_generator,
):
    # A ConnectedRepo referencing a project_id no real Project exists for —
    # no FK across module-owned tables (module-independence precedent), so
    # this data-integrity edge case is reachable and must fail loudly, not
    # silently trigger a scan for a phantom project.
    await connected_repo_repository.add(
        ConnectedRepo(
            id=id_generator.new_id(),
            project_id="does-not-exist",
            provider="github",
            url="https://github.com/octocat/Hello-World",
            default_branch="main",
        )
    )
    trigger_scan = TriggerScanUseCase(
        scans=scan_repository, job_queue=job_queue, id_generator=id_generator
    )
    use_case = _use_case(
        webhook_delivery_repository, connected_repo_repository, project_repository, trigger_scan
    )

    with pytest.raises(ProjectNotFound):
        await use_case.execute(delivery_id="delivery-1", event_type="push", payload=_push_payload())
    assert job_queue.enqueued_scan_ids == []
