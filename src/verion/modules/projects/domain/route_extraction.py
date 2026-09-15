import ast
from dataclasses import dataclass

# The framework this extractor understands, compared against what `detect_stack`
# reports. Verbatim, no case-folding, on `declaration_in_force`'s ground: a
# normalizer here would be a second place for the two sides to disagree, and
# `_PYTHON_FRAMEWORK_SIGNATURES` emits lowercase literals that nothing else writes.
_ROUTE_FRAMEWORK = "flask"

_PYTHON_SUFFIX = ".py"

# Every decorator attribute that declares a route. `route` is the shape ADR-0029
# decision 2 measured; the rest are Flask 2's method shortcuts, which are routes and
# are matched here rather than left silent — a file full of `@app.get` would otherwise
# produce no route AND no residue, making it indistinguishable from a file with no
# routes.
#
# **That is a claim about DECORATORS and not about every way Flask can declare a
# route**, which is worth stating exactly because the unqualified version is false:
# `app.add_url_rule("/x", view_func=f)` is a statement rather than a decorator, and
# this module produces no route and no residue for it. ADR-0029 decision 5 already
# lists it as untested by construction, and it under-counts, which is the direction
# ADR-0019 decision 3 prefers — so it is named here rather than registered.
#
# The cost, stated rather than discovered: `get` is a common attribute name, so
# `@cache.get("/x")` matches where `@cache.route(...)` never would. It is bounded by
# the framework key — nothing here runs unless `detect_stack` reported `flask` — and
# that bound is what makes the cost acceptable rather than absent.
_ROUTE_DECORATOR_ATTRS = ("route", "get", "post", "put", "patch", "delete")

# `VcsProviderPort.get_file_content` base64-decodes and `.decode("utf-8")`, neither of
# which strips a byte-order mark, and `ast.parse` rejects one with `SyntaxError:
# invalid non-printable character U+FEFF`. Stripping it is decoding hygiene, and is
# deliberately NOT the route-path normalization ADR-0029's Consequences keeps to a
# single site: it touches the source text before the parse, never a path this module
# emits. Without it a perfectly valid file is dropped into `unparsed_files`.
_BOM = "﻿"


@dataclass(frozen=True)
class RouteSpan:
    """One route declaration and the source span that serves it.

    **`path` is the decorator literal verbatim** — never stripped of a trailing
    slash, never lowercased, never expanded. ADR-0029 **decision 4** is what "makes
    the repository normalize a URL", singular, at the `build_match_key` call site;
    tidying a path here would create a second normalization site and quietly falsify
    that sentence.

    **A blueprint's `url_prefix` is not applied**, so a `@bp.route("/nested")` on a
    blueprint registered at `/api` is emitted as `/nested` and not as `/api/nested`.
    That prefix lives at the `register_blueprint` call rather than at the decorator,
    and this module reads decorators. It is the same structural shape as **G54** — an
    entry that is produced, looks complete, and can never equal a crawled path — and
    is recorded there rather than here.

    **`file_path` must be repo-relative**, because it exists to meet
    `Finding.location.file_path`, which is repo-relative only because G9 was resolved
    at M4.4 — before that every Semgrep path carried a per-scan `mkdtemp` prefix.
    This module cannot check that precondition: it is handed a mapping and has no way
    to know what the keys are relative to. The unchecked coupling is the second half
    of **G53** and is not re-registered here.

    **`start_line` is THIS route's own decorator line, not the `def` and not the
    lowest decorator**, and both ends are inclusive. See `extract_routes` for why.
    """

    path: str
    file_path: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class UnresolvedRoute:
    """A route decorator whose path this module could not read as a literal.

    Separate from `RouteMap.unparsed_files` because the two are different
    **granularities**, not two causes of one event: a file either parsed or it did
    not, while this is one route inside a file that parsed cleanly and may have
    yielded good routes alongside it.

    Carries the values the AST actually has. There is deliberately no synthesized
    identifier — an unresolved route has no path by definition, and inventing a
    `"file::function"` string would be a value nothing else in the system can join on.
    """

    file_path: str
    function_name: str
    decorator_line: int


@dataclass(frozen=True)
class RouteMap:
    """What a tree's routes are, plus what this module could not tell you about it.

    **The two residue tuples are what stop a silent loss.** A swallowed parse failure
    yielding an empty map would be indistinguishable from a tree that genuinely has
    no routes, and a group missing over such a file would look like evidence of
    absence. Both tuples exist so it is not.

    **They are split rather than merged, and `_persist` is the precedent for
    splitting rather than against it.** That function returns one list of skipped
    hashes for two conditions, and its docstring says why: `collapse_by_identity`
    "raises a bare `ValueError` for both conditions, so this handler cannot tell them
    apart", and catching one and re-raising the other "would mean matching on a
    message string, which is worse". It then names the better state outright — "what
    would need to change is the domain raising two distinct types so the reason can
    name the cause". Here there is no such limitation: a parse failure and a
    non-literal path are found in different code paths with no string matching
    anywhere. Merging them into one tuple of file paths would also name a file that
    yielded five good routes and one variable one as unmapped, which is false about
    that file.

    Every tuple is sorted, and that is load-bearing rather than tidy — see
    `extract_routes`.
    """

    routes: tuple[RouteSpan, ...]
    unparsed_files: tuple[str, ...]
    unresolved_routes: tuple[UnresolvedRoute, ...]


def extract_routes(*, framework: str | None, files: dict[str, str]) -> RouteMap:
    """Map a tree's Flask routes to the source spans that serve them. Pure: no I/O.

    ADR-0029 decision 2's function. `detect_stack`'s shape one module over — a
    `dict[str, str]` of file contents in, a frozen result out — and the parameter is
    named `files` for that reason, since it is the identical value from the identical
    port.

    **The framework arrives as an ARGUMENT rather than being detected here, and that
    is a boundary decision rather than a convenience.** `detect_stack` reads
    manifests; this parses source, and `relevant_file_paths` selects a disjoint set
    of files. An internally-detecting extractor would therefore need both dicts,
    which would encode the fetch strategy into a `domain/` function. It would also be
    a second detection site free to disagree with the persisted
    `SecurityContext.framework` a reader sees, and that disagreement is reachable
    today rather than hypothetical: `UpdateExposureTagsUseCase.execute` constructs a
    `SecurityContext` with `framework=None` when none exists, so a project annotated
    before detection ran holds `None` over a Flask tree.

    The cheaper shape — no parameter at all, gate at the caller, name this
    `extract_flask_routes` — is refused by decision 2's own wording, which says a
    non-Flask tree "returns an empty map rather than a guess". The empty map is this
    function's to return, so the framework has to reach it.

    **Inherited looseness worth knowing about:** `_detect_python_framework` matches
    by substring over a whole manifest, so a `requirements.txt` mentioning
    `flask-limiter`, or a comment naming Flask, reports `"flask"`. This runs over such
    a tree and finds no route decorators, which is harmless — but it is the answer to
    "why did this run over a Django repo".

    **A file that does not parse is SKIPPED and NAMED, never fatal.** ADR-0021
    decision 4 already draws this line: an unrecognised tool name raises because it is
    "deployment configuration this project controls", while an unrecognised severity
    degrades because it is upstream data a tool can change in any release. Source
    files arrive over `VcsProviderPort` from somebody else's repository, which puts
    them squarely on the degrade side — so `parse_enabled_tools` raising, one file
    over in this same module, is not a counter-precedent. Failing wholesale would
    also mean one Python 2 file, or one template with a `.py` extension, delivering
    nothing for an entire repository.

    **What this deliberately departs from is `_detect_javascript_framework`**, which
    swallows `json.JSONDecodeError` and returns `None`, leaving "no framework" and
    "the manifest was malformed" indistinguishable in `DetectionResult`. That is the
    silent version of this decision and the reason `unparsed_files` exists.

    Only `SyntaxError` is caught, and that is measured rather than assumed: measured
    on 3.12.14, Python 2 syntax, an indentation error, a tab/space mix, a Jinja
    template, a byte-order mark and an embedded null byte all raise `SyntaxError`,
    with `IndentationError` and `TabError` as subclasses. `.python-version` pins the
    minor (`3.12`) rather than that patch, and `ci.yml` reads the version from it and
    forbids a second source. An earlier
    draft also caught `ValueError`, because null bytes raised it on older CPython;
    that is out of scope under `requires-python = ">=3.12"`, and since `SyntaxError`
    is not a `ValueError` subclass the extra arm was a real widening rather than a
    redundant one.

    **The span starts at the route's OWN decorator line.** Decorator-inclusive,
    because a finding reported on `@app.route("/calculate")` is on the code that
    serves that route and excluding it would be a silent miss. But not the lowest
    decorator line, which is the version that looks equivalent and is not: with two
    stacked route decorators, a shared span puts a finding on `/a`'s own decorator
    inside `/b`'s span too, asserting a relation that does not exist. That is the
    fabrication side of ADR-0019 decision 3, whose preference for the failure that
    under-counts is exactly what rules it out. The residue falls the right way — an
    unrelated decorator ABOVE the route decorator (`@login_required`) maps to no
    route, which is the under-count.

    **Stacked routes therefore produce OVERLAPPING spans, and that is the correct
    answer rather than an ambiguity to be resolved.** A line in a body served by two
    routes genuinely serves both. A query for a line returns every route whose span
    contains it, and no tie-break exists here or belongs in a consumer: if one ever
    appears necessary, that is the signal that the query's return type was wrong — a
    single route where a set belongs — not that a rule is missing. Adding a `min()`,
    a "first match wins", or a sort-and-take-one would be ADR-0019 decision 4's
    `instances[0]` scar arriving a third time.

    **Output is sorted, and that is not tidiness.** `ast.walk` is breadth-first, so a
    route nested in an app factory is emitted after every module-level one; without a
    sort the result would depend on nesting depth and on the caller's dict insertion
    order, which is the non-deterministic-representative mistake this repository
    already carries twice.

    **Walking reaches more than decision 5 claims is proven**, and the difference is
    stated rather than inferred from behaviour: routes declared inside an app factory
    and methods decorated inside a class body are both found, while ADR-0029 decision
    5 lists app factories' cousin "routes spread across modules" and "class-based
    views" as untested by construction. Untested is not unsupported; a reader must
    not take either fact for the other.

    Keys that do not end in `.py` are ignored entirely and never reported, so a
    caller handing in a `README.md` cannot pollute `unparsed_files`.
    """
    if framework != _ROUTE_FRAMEWORK:
        return RouteMap(routes=(), unparsed_files=(), unresolved_routes=())

    routes: list[RouteSpan] = []
    unparsed_files: list[str] = []
    unresolved_routes: list[UnresolvedRoute] = []

    for file_path, source in files.items():
        if not file_path.endswith(_PYTHON_SUFFIX):
            continue
        try:
            tree = ast.parse(source.removeprefix(_BOM))
        except SyntaxError:
            unparsed_files.append(file_path)
            continue
        _collect_from_tree(tree, file_path, routes, unresolved_routes)

    return RouteMap(
        routes=tuple(sorted(routes, key=_route_order)),
        unparsed_files=tuple(sorted(unparsed_files)),
        unresolved_routes=tuple(sorted(unresolved_routes, key=_unresolved_order)),
    )


def _collect_from_tree(
    tree: ast.Module,
    file_path: str,
    routes: list[RouteSpan],
    unresolved_routes: list[UnresolvedRoute],
) -> None:
    """Accumulate one parsed module's routes into the caller's lists.

    `ast.walk` rather than `ast.iter_child_nodes`: the latter sees the module top
    level only, so it misses the app-factory shape — a `@bp.route`-decorated function
    defined inside `def create_app()` — which is ordinary Flask rather than an edge
    case.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue

        # `AsyncFunctionDef` is checked alongside `FunctionDef` because Flask 2
        # supports `async def` views; matching only the sync node would be a silent
        # miss with no receipt, which is what this module refuses everywhere else.
        #
        # typeshed declares `end_lineno` as `int | None` on statement nodes. The
        # fallback keeps `mypy --strict` honest without a suppression — CLAUDE.md
        # tracks those at a hard baseline of zero — and a node whose end is unknown
        # is at least one line long.
        end_line = node.end_lineno or node.lineno

        for decorator in node.decorator_list:
            # Not every decorator is a Call: `@staticmethod` is a bare `ast.Name` with
            # no `.func` attribute at all, so this guard is what stops an
            # AttributeError on entirely ordinary code.
            if not isinstance(decorator, ast.Call):
                continue

            # An `ast.Attribute` receiver, so `@app.route` and a blueprint's
            # `@bp.route` both match while a bare `@route(...)` from some other
            # library does not. Refusing the bare form under-counts, which is the
            # preferred direction.
            func = decorator.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in _ROUTE_DECORATOR_ATTRS:
                continue

            path = _literal_path(decorator)
            if path is None:
                unresolved_routes.append(
                    UnresolvedRoute(
                        file_path=file_path,
                        function_name=node.name,
                        decorator_line=decorator.lineno,
                    )
                )
                continue

            routes.append(
                RouteSpan(
                    path=path,
                    file_path=file_path,
                    start_line=decorator.lineno,
                    end_line=end_line,
                )
            )


def _literal_path(decorator: ast.Call) -> str | None:
    """The decorator's first positional argument, if it is a string literal.

    `None` means the caller records an `UnresolvedRoute`, and three distinct shapes
    reach it, each verified rather than assumed:

    - **no positional argument at all** — `@app.route()` and `@app.route(rule="/kw")`
      both parse to a `Call` with an empty `args`, so an unguarded `args[0]` would
      raise `IndexError` and take down the whole file. The keyword form is valid
      Flask; it is refused rather than given a `keywords` branch, and refusing it
      under-counts visibly instead of silently.
    - **not a constant** — `@app.route(PREFIX + "/x")` is a `BinOp`, an f-string is a
      `JoinedStr`, and `@app.route(*paths)` is a `Starred`. Implicit concatenation
      (`"/a" "/b"`) is folded by the parser into one `Constant` and resolves, which is
      correct.
    - **a constant that is not a string** — `@app.route(b"/bytes")` is an
      `ast.Constant` whose `.value` is `bytes`, so the type check is on the value and
      not on the node. `ast.Str` is deliberately not referenced: it is deprecated
      since 3.8 and scheduled for removal in **3.14**. *(An earlier version of this
      line said it was removed in 3.12, which is false — `hasattr(ast, "Str")` is
      still `True` on 3.12.14, with a DeprecationWarning. The code was right either
      way, since it tests `ast.Constant` and the value's type.)*
    """
    if not decorator.args:
        return None

    first = decorator.args[0]
    if not isinstance(first, ast.Constant):
        return None

    value = first.value
    if not isinstance(value, str):
        return None
    return value


def _route_order(route: RouteSpan) -> tuple[str, int, int, str]:
    """A total order over routes, so the output never depends on input order.

    The path is the final tiebreak and makes the order total rather than merely
    deterministic: two routes can share a file and a span only when they are stacked
    decorators on one view, and those carry distinct decorator lines already, so no
    two entries can tie on all four.
    """
    return (route.file_path, route.start_line, route.end_line, route.path)


def _unresolved_order(route: UnresolvedRoute) -> tuple[str, int, str]:
    return (route.file_path, route.decorator_line, route.function_name)
