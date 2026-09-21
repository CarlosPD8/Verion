import dataclasses
from urllib.parse import urlparse

from verion.modules.projects.application.build_security_context import BuildSecurityContextUseCase
from verion.modules.projects.domain.authorization import require_owner
from verion.modules.projects.domain.context_detection import relevant_file_paths
from verion.modules.projects.domain.exceptions import (
    ConnectedRepoNotFound,
    GitHubApiError,
    ProjectNotFound,
    SourceArchiveMalformed,
    SourceArchiveTooLarge,
    UnsupportedRepoProvider,
)
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.route_extraction import (
    RouteMap,
    UnreadTree,
    extract_routes,
    extracts_routes_for,
)
from verion.modules.projects.domain.route_map_record import RouteMapRecord
from verion.modules.projects.domain.security_context import SecurityContext
from verion.modules.projects.ports.connected_repo_repository import ConnectedRepoRepositoryPort
from verion.modules.projects.ports.project_membership_repository import (
    ProjectMembershipRepositoryPort,
)
from verion.modules.projects.ports.project_repository import ProjectRepositoryPort
from verion.modules.projects.ports.route_map_repository import RouteMapRepositoryPort
from verion.modules.projects.ports.vcs_provider import VcsProviderPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


class BuildSecurityContextFromGitHubUseCase:
    def __init__(
        self,
        projects: ProjectRepositoryPort,
        memberships: ProjectMembershipRepositoryPort,
        connected_repos: ConnectedRepoRepositoryPort,
        vcs_provider: VcsProviderPort,
        build_security_context: BuildSecurityContextUseCase,
        route_maps: RouteMapRepositoryPort,
        id_generator: IdGeneratorPort,
        clock: ClockPort,
    ) -> None:
        self._projects = projects
        self._memberships = memberships
        self._connected_repos = connected_repos
        self._vcs_provider = vcs_provider
        self._build_security_context = build_security_context
        self._route_maps = route_maps
        self._id_generator = id_generator
        self._clock = clock

    async def execute(self, project_id: str, user_id: str, access_token: str) -> SecurityContext:
        project = await self._projects.get_by_id(project_id)
        if project is None:
            raise ProjectNotFound(f"No project with id '{project_id}'")

        # Checked here too, before any VcsProviderPort call — not just relying
        # on the composed BuildSecurityContextUseCase's own check at the end.
        # A non-owner's request must never reach GitHub: that would burn the
        # connected repo's API quota and let permission-less callers probe
        # repo existence/contents via timing or error responses.
        membership = await self._memberships.get_by_project_and_user(project_id, user_id)
        require_owner(membership)

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
        context = await self._build_security_context.execute(project_id, user_id, files)

        # M5.6 commit 4, ADR-0029: the route map is derived and stored HERE, at context
        # build, because this is the one place that is owner-triggered and already holds a
        # token. It is keyed on the framework just detected from the manifests above — a
        # separate, earlier read of the tip than the archive below, which is **G56**.
        route_map, commit_sha = await self._derive_route_map(
            access_token, owner, repo, context.framework
        )
        await self._route_maps.upsert(
            RouteMapRecord(
                id=self._id_generator.new_id(),
                project_id=project_id,
                framework=context.framework,
                source_archive_commit_sha=commit_sha,
                derived_at=self._clock.now(),
                route_map=route_map,
            )
        )
        return context

    async def _derive_route_map(
        self, access_token: str, owner: str, repo: str, framework: str | None
    ) -> tuple[RouteMap, str | None]:
        """The map and the commit its source came from, or a named reason it was not read.

        **No request at all for a framework the extractor does not read**, so a non-Flask
        project's build costs exactly what it did before this commit.

        **Every archive failure DEGRADES to a stored `UnreadTree`; none raises**, and the
        grounds are not all the same, so they are stated separately rather than borrowed:

        - `TOO_LARGE` and `MALFORMED` are about the tree itself, which arrives from
          somebody else's repository. That is ADR-0021 decision 4's degrade side, the
          ground `extract_routes` already uses for a file that does not parse.
        - `FETCH_FAILED` is network or rate limit, which is not upstream DATA, so that
          ground does not reach it. It degrades on a narrower one: the context above is
          already built and worth keeping, and the failure has a representation, so
          raising would discard a good context to report a missing map. The manifest fetch
          above still raises as it always has, because at that point nothing has been
          built and there is nothing to degrade to.

        """
        if not extracts_routes_for(framework):
            return extract_routes(framework=framework, files={}), None

        try:
            archive = await self._vcs_provider.fetch_source_archive(access_token, owner, repo)
        except GitHubApiError:
            return RouteMap.not_read(UnreadTree.FETCH_FAILED), None
        except SourceArchiveTooLarge:
            return RouteMap.not_read(UnreadTree.TOO_LARGE), None
        except SourceArchiveMalformed:
            return RouteMap.not_read(UnreadTree.MALFORMED), None

        route_map = extract_routes(framework=framework, files=archive.files)
        if archive.undecodable_files:
            # Folded into `unparsed_files` rather than given a fourth field: both are "this
            # file was not parsed", at the same per-file granularity, which is the line
            # route_extraction.py already draws between its two residue tuples.
            route_map = dataclasses.replace(
                route_map,
                unparsed_files=tuple(
                    sorted({*route_map.unparsed_files, *archive.undecodable_files})
                ),
            )
        return route_map, archive.commit_sha


def _parse_github_owner_repo(connected_repo: ConnectedRepo) -> tuple[str, str]:
    if connected_repo.provider != "github":
        raise UnsupportedRepoProvider(
            f"Connected repo for project '{connected_repo.project_id}' uses "
            f"provider '{connected_repo.provider}', not 'github'"
        )

    parsed = urlparse(connected_repo.url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc != "github.com" or len(path_parts) != 2:
        # Never quotes the URL: the route returns this message, and a row written before
        # `validate_connected_repo_url` existed can carry userinfo (rule 12).
        raise UnsupportedRepoProvider(
            f"Connected repo url for project '{connected_repo.project_id}' is not a valid "
            f"github.com/{{owner}}/{{repo}} URL"
        )
    owner, repo = path_parts
    return owner, repo
