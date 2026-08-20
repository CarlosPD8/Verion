from urllib.parse import urlparse

from verion.modules.projects.application.build_security_context import BuildSecurityContextUseCase
from verion.modules.projects.domain.context_detection import relevant_file_paths
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.vcs_provider import VcsProviderPort


class BuildSecurityContextFromGitHubUseCase:
    def __init__(
        self,
        connected_repos: ConnectedRepoRepositoryPort,
        vcs_provider: VcsProviderPort,
        build_security_context: BuildSecurityContextUseCase,
    ) -> None:
        self._connected_repos = connected_repos
        self._vcs_provider = vcs_provider
        self._build_security_context = build_security_context

    async def execute(self, project_id: str, access_token: str) -> SecurityContext:
        connected_repo = await self._connected_repos.get_by_project_id(project_id)
        if connected_repo is None:
            raise ConnectedRepoNotFound(f"No connected repo for project '{project_id}'")

        owner, repo = _parse_github_owner_repo(connected_repo)

        all_paths = await self._vcs_provider.list_repo_files(access_token, owner, repo)
        files: dict[str, str] = {}
        for path in relevant_file_paths(all_paths):
            content = await self._vcs_provider.get_file_content(access_token, owner, repo, path)
            if content is not None:
                files[path] = content

        # GitHubApiError is already a projects-domain exception (not a raw
        # adapter exception, per vcs_provider.py's contract) — propagate
        # unchanged, same precedent as ConnectRepositoryViaGitHubUseCase.
        return await self._build_security_context.execute(project_id, files)


def _parse_github_owner_repo(connected_repo: ConnectedRepo) -> tuple[str, str]:
    if connected_repo.provider != "github":
        raise UnsupportedRepoProvider(
            f"Connected repo for project '{connected_repo.project_id}' uses "
            f"provider '{connected_repo.provider}', not 'github'"
        )

    parsed = urlparse(connected_repo.url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc != "github.com" or len(path_parts) != 2:
        raise UnsupportedRepoProvider(
            f"Connected repo url '{connected_repo.url}' is not a valid "
            f"github.com/{{owner}}/{{repo}} URL"
        )
    owner, repo = path_parts
    return owner, repo
