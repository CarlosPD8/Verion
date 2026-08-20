# ConnectedRepoRepositoryPort/ProjectRepositoryPort belong to projects —
# importing their *ports* (not .domain/.adapters) is import-linter-legal
# (cross-module-scanning only forbids .domain/.adapters), same precedent as
# run_scan.py's cross-module port imports.
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.scanning.application.trigger_scan import TriggerScanUseCase
from verion.modules.scanning.domain.exceptions import ProjectNotFound, RepoNotConnected
from verion.modules.scanning.domain.scan import Scan
from verion.modules.scanning.domain.webhook_payload import parse_push_event_repo
from verion.modules.scanning.ports.webhook_delivery_repository import WebhookDeliveryRepositoryPort

_PUSH_EVENT = "push"


class HandleGitHubWebhookUseCase:
    def __init__(
        self,
        webhook_deliveries: WebhookDeliveryRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
        projects: ProjectRepositoryPort,
        trigger_scan: TriggerScanUseCase,
    ) -> None:
        self._webhook_deliveries = webhook_deliveries
        self._connected_repos = connected_repos
        self._projects = projects
        self._trigger_scan = trigger_scan

    async def execute(self, delivery_id: str, event_type: str, payload: dict) -> Scan | None:
        """Called only after the router has already verified the request's
        HMAC signature — this use case trusts `payload`, it never verifies
        it (that's a security gate, kept in the inbound adapter, not here).

        Order matters, deliberately: the dedup check runs before anything
        else — including the event-type branch and any DB lookup beyond
        itself — so a redelivery storm of the same X-GitHub-Delivery costs
        one indexed write attempt, not a repeated ConnectedRepo/Project
        query on every retry.
        """
        is_new_delivery = await self._webhook_deliveries.record_if_new(delivery_id)
        if not is_new_delivery:
            return None

        if event_type != _PUSH_EVENT:
            # e.g. "ping", sent automatically right after GitHub creates the
            # webhook — acknowledged, no scan triggered.
            return None

        owner, repo = parse_push_event_repo(payload)
        url = f"https://github.com/{owner}/{repo}"

        connected_repo = await self._connected_repos.get_by_url(url)
        if connected_repo is None:
            raise RepoNotConnected(f"No connected repo for '{owner}/{repo}'")

        project = await self._projects.get_by_id(connected_repo.project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{connected_repo.project_id}'")

        # No authenticated user on a webhook call. The project was already
        # deterministically resolved via the connected-repo URL lookup
        # above, and the router's signature check already proves GitHub
        # itself is the caller — attribute the scan to the project's actual
        # owner for audit purposes (PRODUCT_SPEC.md §11.5) and treat that
        # signature-verified call as equivalent trust to the owner who set
        # up the connection.
        return await self._trigger_scan.execute(
            project_id=project.id, user_id=project.owner_id, project_exists=True, is_owner=True
        )
