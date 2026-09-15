from dataclasses import dataclass
from datetime import datetime

from verion.modules.projects.domain.route_extraction import RouteMap, UnreadTree


@dataclass(frozen=True)
class RouteMapRecord:
    """A project's stored route map and where it came from. M5.6 commit 4, ADR-0029.

    One per project, written at Security Context build time.

    **Effectively written once today, and that is G55's doing rather than this entity's.** A
    second detect does overwrite this record, but it also writes a duplicate
    `security_contexts` row, after which that project's context reads raise. So the map
    cannot be refreshed without breaking the project, and a failed archive fetch is in
    practice permanent for it.

    `framework` is the key `extract_routes` was called with, stored so an empty map for a
    non-Flask tree describes itself rather than depending on `SecurityContext.framework`,
    which a later exposure-tags edit can create as `None`.

    **`source_archive_commit_sha` describes the tree the ROUTE MAP was read from, and nothing
    else.** The framework and the manifests behind it come from a different, earlier request
    (**G56**), so this is not "the commit this context was built from". It is also not the
    commit any scanner read (**G25**), and nothing compares the two yet (**G52**). It is
    `None` whenever no archive was read: a non-Flask tree, or an `unread_tree` failure.
    """

    id: str
    project_id: str
    framework: str | None
    source_archive_commit_sha: str | None
    derived_at: datetime
    route_map: RouteMap

    def __post_init__(self) -> None:
        unread = self.route_map.unread_tree
        # `NOT_BUILT` means "no record exists"; a record claiming it would contradict itself.
        if unread is UnreadTree.NOT_BUILT:
            raise ValueError("A stored route map cannot be NOT_BUILT")
        if unread is not None and self.source_archive_commit_sha is not None:
            raise ValueError("A route map whose tree was not read cannot carry a commit SHA")
