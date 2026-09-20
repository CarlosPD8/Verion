from typing import Protocol
from urllib.parse import urlsplit

from verion.modules.correlation.domain.match_key import MatchKey, MatchKeyResult
from verion.shared_kernel.confidence import Confidence


class PathsServing(Protocol):
    """`correlation`'s description of `RouteMap.paths_serving`, which it may not name.

    The use case passes the bound method of a map it took by inference off `RouteMapPort`,
    so `mypy` compares this signature against `projects`' real one at that call. That makes it
    a SECOND conformance site beside `build_match_key`'s parameters — section (b)'s shape, for
    the one input that does not come off `Finding` — and, like `file_path` and `start_line`, it
    gets `mypy` and no conformance test (**G53**).
    """

    def __call__(self, *, file_path: str, line: int) -> tuple[str, ...]: ...


def build_match_key(
    *,
    project_id: str,
    package: str | None,
    url: str | None,
    file_path: str | None,
    start_line: int | None,
    paths_serving: PathsServing | None,
) -> MatchKeyResult:
    """Build one finding's `MatchKey` **and the provenance of its signal**. M8.5, ADR-0037.

    **The single conformance site for the finding's values**, and since M8.5 the site that
    also NAMES where the key's `url` came from. What each branch yields:

    | branch | key | confidence |
    |---|---|---|
    | the finding's own `url` | its path | `REPORTED` |
    | no `url`, a derived route | that route's path | `INFERRED` |
    | no `url`, a `package` | the package | `REPORTED` |
    | neither | no signal | `UNGROUPED` |

    So `UNGROUPED` is exactly `not key.has_signal`, and the other two are the branch. The
    meaning of each value is `CONFIDENCE_DEFINITION` in this module's `ports/`, declared
    where a consumer may name it; `tests/unit/test_match_key.py` asserts that the values this
    function can produce and the values `Confidence` declares are **the same set**, so a
    fourth branch cannot be added without deciding its provenance, and a member no branch
    reaches cannot be added either.

    ADR-0023's Decision puts key construction in `application/` and says why: this is the
    one place `mypy` compares correlation's description of `Finding` against the real one.
    A caller passes `finding.project_id` and `finding.location`'s `package`, `url`,
    `file_path` and `start_line` — values whose types come back through
    `FindingRepositoryPort`'s return annotation — into the parameters below, so a renamed,
    removed or re-typed source field fails the build here, at one site, with no test
    needed. **All six parameters are keyword-only and required**, so a caller cannot omit
    the derivation inputs and silently fall back to the pre-M5.6 key.

    **Scalars rather than a `Finding` parameter, and that is forced rather than chosen.**
    A parameter must be annotated under `mypy --strict`, and the annotation a `Finding`
    parameter would need is exactly the name `cross-module-correlation` forbids.

    **Two rules, and only the second is gated** (ADR-0029 decision 4, M5.6 commit 3):

    1. **A `url` is keyed on its PATH, always.** `urlsplit(url).path`, with an empty path read
       as `/` (HTTP's own reading of `http://host`), and nothing else touched: no trailing
       slash stripped, no case folded, no percent-escape decoded — Flask distinguishes all
       three. This is **G31**'s first out and a property of the key, not of whether a
       cross-tool comparison is founded, so it does not wait on the declaration: two ZAP
       alerts at `/calculate?expr=2*3` and `/calculate?expr=calculate` are one endpoint
       whether or not anybody declared anything. **This is the repository's single URL
       normalization site**; `route_extraction.py` refuses to be a second.
       Dropping scheme, host and port is lossless only while every alert in a project shares
       them, and what bounds that is the ZAP plan's structure rather than `ScannerConfig` —
       see **G53**'s dated note, which names the two places the plan does not bound it.
    2. **A finding with no `url` and no `package` gets a DERIVED path** when `paths_serving`
       is supplied — which the use case does only while `ServingDeclarationPort` says the
       declaration is in force — and when it returns **exactly one** path for
       `(file_path, start_line)`. Zero paths is a line no route serves. **Two or more is a
       line in a stacked view's shared body, and it derives NOTHING rather than picking
       one**: a key carries one `url`, a tie-break would be ADR-0019 decision 4's
       `instances[0]` scar again, and the under-count is the direction ADR-0019 decision 3
       prefers. What that costs is **G54**'s third member.

    **The provenance is NAMED at the site that narrows it — G53's closure.** For a derived
    key, `url` did not come off `Location.url`: it came off a route map. The annotations
    still meet (`str | None` into `str | None`), so section (b)'s check on that field stays
    green while its subject changes — section (c)'s *"semantic changes behind an unchanged
    signature"*, which ADR-0029 decision 4 entered deliberately and G53 recorded. Returning
    the provenance is what ends it: the meaning is now a value the signature carries, so it
    cannot change silently.

    **What that does NOT close, and it is its own entry rather than a note here.**
    `file_path`, `start_line` and `PathsServing` still get `mypy` at this site and **no
    conformance assertion**, because `test_match_key.py` derives its expectations from the
    **key's** fields and none of the three is one. A `Location.start_line` re-typed from
    `int | None` fails here and nowhere else; a *widened* annotation on either side fails
    nowhere at all. **G95.**

    `start_line` rather than `end_line`: a Semgrep finding's span starts where the matched
    code starts, and the route serving it is the one whose span holds that line.
    """
    if url is not None:
        return MatchKeyResult(
            key=MatchKey(project_id=project_id, package=package, url=urlsplit(url).path or "/"),
            confidence=Confidence.REPORTED,
        )

    if (
        package is None
        and paths_serving is not None
        and file_path is not None
        and start_line is not None
    ):
        paths = paths_serving(file_path=file_path, line=start_line)
        if len(paths) == 1:
            return MatchKeyResult(
                key=MatchKey(project_id=project_id, package=None, url=paths[0]),
                confidence=Confidence.INFERRED,
            )

    key = MatchKey(project_id=project_id, package=package, url=None)
    # `has_signal` rather than `package is not None`, so the two stay one statement: a key
    # that carries nothing to group on is `UNGROUPED`, whatever field would have carried it.
    return MatchKeyResult(
        key=key,
        confidence=Confidence.REPORTED if key.has_signal else Confidence.UNGROUPED,
    )
