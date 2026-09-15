"""The route extractor (M5.6 commit 2), against ADR-0029 decisions 1 and 2.

Four things here are not ordinary coverage and say so:

- the **span-boundary** test, which pins a choice ADR-0029 decision 5 recorded as one
  "no test checks". It is written as a constructed fixture precisely because the demo
  target cannot discriminate the two readings — Semgrep's line 28 is inside
  `calculate` whether or not the decorator is included;
- the **stacked-decorator** test, whose subject is that overlapping spans are the
  correct answer rather than an ambiguity. It asserts a body line is inside BOTH
  routes and that a decorator line is inside exactly one, so a later `min()` or
  "first match wins" fails here;
- the **residue** tests, whose subject is that "no routes here" stays distinguishable
  from "this file did not parse" and from "this file held a route I could not read".
  A swallowed failure returning an empty map is the shape this project tracks;
- the **order-independence** test, which pins the sort rather than `ast.walk`'s
  breadth-first output — the non-deterministic-representative mistake this repo
  already carries twice.

Inline source strings throughout, with one deliberate exception read from disk; see
`_SEMGREP_TARGET`. Nothing is stood up and no tree is cloned, so this file adds no
measurable time to the tracked CI step.
"""

from pathlib import Path

import pytest

from verion.modules.projects.domain.route_extraction import (
    RouteMap,
    extract_routes,
)

# The only file this suite reads from disk, and the first unit test to read one from
# OUTSIDE `tests/fixtures/scanners/`. Not the first to read one at all — the mapper
# unit tests have read committed captures through `tests/conftest.py`'s
# `scanner_fixture` since M4.1, and an earlier version of this comment said otherwise.
# What is new here is crossing into `tests/integration/fixtures/`, which follows
# `test_active_scan_finds_the_sink.py` reaching the other way for `zap_scan.json` with
# a module-level anchored path.
#
# It is used rather than an equivalent literal because the point of the case is that it
# is the REAL committed file: if somebody adds a route to it, this test is supposed to
# fail. A literal could not do that. That file carries a note naming both consumers.
_SEMGREP_TARGET = (
    Path(__file__).parents[1] / "integration" / "fixtures" / "semgrep_target" / "vulnerable.py"
)


def _flask(files: dict[str, str]) -> RouteMap:
    return extract_routes(framework="flask", files=files)


def _paths(route_map: RouteMap) -> list[str]:
    return [route.path for route in route_map.routes]


def _spans(route_map: RouteMap) -> list[tuple[str, int, int]]:
    return [(route.path, route.start_line, route.end_line) for route in route_map.routes]


# Line 1 is the first line of every source constant below, so the numbers asserted in
# the tests are the numbers `ast` reports. That is what the trailing backslash on each
# opening delimiter is for: without it every constant would gain a leading blank line
# and every asserted line number would be off by one.

_TWO_ROUTES = """\
@app.route("/")
def index():
    return "home"


@app.route("/calculate")
def calculate():
    return eval(request.args.get("expr", ""))
"""

_STACKED = """\
@app.route("/a")
@app.route("/b", methods=["GET"])
def ab():
    return render()
"""

_BROKEN = """\
def broken(:
    pass
"""

_MIXED = """\
@app.route("/ok")
def ok():
    return 1


@app.route(PREFIX + "/dynamic")
def dynamic():
    return 2
"""

_ASYNC = """\
@app.route("/async")
async def view():
    return 1
"""

_NON_ROUTE_DECORATORS = """\
@staticmethod
def helper():
    return 1


@app.errorhandler(404)
def not_found(error):
    return "nope"


@app.route()
def no_args():
    return 1


@app.route(rule="/kw")
def keyword_only():
    return 1
"""

_FACTORY_FIRST = """\
def create_app():
    @bp.route("/nested")
    def nested():
        return 1

    return bp


@app.route("/top")
def top():
    return 2
"""

_CONVERTER = """\
@app.route("/user/<int:id>")
def user(id):
    return 1
"""

_METHOD_SHORTCUTS = """\
@app.get("/items")
def list_items():
    return 1


@app.post("/items")
def create_item():
    return 2
"""


# ---------------------------------------------------------------------------
# The mechanism
# ---------------------------------------------------------------------------


def test_two_literal_routes_map_to_the_functions_that_serve_them():
    result = _flask({"app.py": _TWO_ROUTES})

    assert _spans(result) == [("/", 1, 3), ("/calculate", 6, 8)]
    assert {route.file_path for route in result.routes} == {"app.py"}
    assert result.unparsed_files == ()
    assert result.unresolved_routes == ()


def test_the_span_starts_at_the_route_decorator_and_not_at_the_def():
    """The choice ADR-0029 decision 5 recorded as one that no test checks.

    The demo target cannot discriminate the two readings, so this is a constructed
    fixture whose only job is to. `@app.route("/")` is line 1 and `def index():` is
    line 2, so decorator-inclusive and decorator-exclusive spans differ here by
    exactly the assertion below.
    """
    route = _flask({"app.py": _TWO_ROUTES}).routes[0]

    assert route.start_line == 1
    assert route.start_line != 2


def test_an_async_view_is_extracted():
    assert _spans(_flask({"app.py": _ASYNC})) == [("/async", 1, 3)]


def test_a_route_declared_inside_an_app_factory_is_found():
    """Pins `ast.walk` over `ast.iter_child_nodes`, which sees the module top level
    only and would miss this shape entirely."""
    assert "/nested" in _paths(_flask({"app.py": _FACTORY_FIRST}))


def test_the_flask_method_shortcuts_are_routes_too():
    """`@app.get` and friends declare routes, so leaving them unmatched would produce
    no route AND no residue — a file full of them indistinguishable from a file with
    none, which is the ambiguity this module refuses everywhere else."""
    result = _flask({"app.py": _METHOD_SHORTCUTS})

    assert _spans(result) == [("/items", 1, 3), ("/items", 6, 8)]
    assert result.unresolved_routes == ()


def test_a_converter_path_is_emitted_verbatim():
    """Never expanded, never stripped. ADR-0029 **decision 4** keeps URL normalization
    to a single site at the `build_match_key` call, and a tidy-up here would be a
    second one. That this path can then never equal a crawled `/user/123` is **G54**,
    which this test is the premise of rather than a fix for.
    """
    assert _paths(_flask({"app.py": _CONVERTER})) == ["/user/<int:id>"]


# ---------------------------------------------------------------------------
# Overlapping spans are the answer, not an ambiguity to be resolved
# ---------------------------------------------------------------------------


def test_stacked_route_decorators_produce_two_routes_with_distinct_starts():
    result = _flask({"app.py": _STACKED})

    assert _spans(result) == [("/a", 1, 4), ("/b", 2, 4)]


def test_a_body_line_belongs_to_every_stacked_route_and_a_decorator_line_to_one():
    """The subject is that overlapping spans are CORRECT, not that they need resolving.

    A line in the shared body genuinely serves both routes and the map says so. A line
    that is one route's own decorator serves that route alone — which is what the
    lowest-decorator reading gets wrong, attributing a finding on `/a`'s decorator to
    `/b` as well. No tie-break exists here or belongs in a consumer: if one ever looks
    necessary, the query's return type was wrong.
    """
    routes = _flask({"app.py": _STACKED}).routes

    def containing(line: int) -> list[str]:
        return sorted(route.path for route in routes if route.start_line <= line <= route.end_line)

    assert containing(4) == ["/a", "/b"]
    assert containing(1) == ["/a"]
    assert containing(2) == ["/a", "/b"]


# ---------------------------------------------------------------------------
# The residue — "no routes here" stays distinguishable from both failures
# ---------------------------------------------------------------------------


def test_a_route_free_python_file_yields_nothing_and_is_named_nowhere():
    """The miss case, over the real committed file rather than a literal.

    `tests/integration/fixtures/semgrep_target/vulnerable.py` declares no routes, so
    it must come back with an empty map AND appear in neither residue tuple — a file
    that parsed cleanly and simply has nothing to offer. Reading the real file means
    this test fails if somebody adds a route to it, which a literal could not do.
    """
    result = _flask({"vulnerable.py": _SEMGREP_TARGET.read_text(encoding="utf-8")})

    assert result.routes == ()
    assert result.unparsed_files == ()
    assert result.unresolved_routes == ()


def test_a_file_that_does_not_parse_is_named_and_the_other_files_still_come_through():
    """The load-bearing half: skipping must not become swallowing.

    One unparseable file — a Python 2 module, a template with a `.py` extension, a
    half-written file — must not cost the whole extraction, and must not vanish
    either. The shape `NormalizeScanUseCase.execute` states when it records
    "every other finding in this scan was persisted" for what `_persist` skipped.
    """
    result = _flask({"app.py": _TWO_ROUTES, "broken.py": _BROKEN})

    assert _paths(result) == ["/", "/calculate"]
    assert result.unparsed_files == ("broken.py",)
    assert result.unresolved_routes == ()


def test_a_non_literal_route_path_is_named_and_its_neighbours_in_that_file_survive():
    """The granularity the two residue tuples exist for.

    `app.py` parses cleanly and yields a good route, so naming the FILE as unmapped
    would be false about it. What is unmapped is one route inside it.
    """
    result = _flask({"app.py": _MIXED})

    assert _spans(result) == [("/ok", 1, 3)]
    assert result.unparsed_files == ()
    assert [
        (route.file_path, route.function_name, route.decorator_line)
        for route in result.unresolved_routes
    ] == [("app.py", "dynamic", 6)]


def test_decorators_that_declare_no_route_are_ignored_without_crashing():
    """`@staticmethod` is a bare `ast.Name` with no `.func` at all, and
    `@app.errorhandler(404)` is a Call this module must not claim. `@app.route()` and
    `@app.route(rule=...)` ARE route decorators with no readable path, so they are
    named rather than dropped."""
    result = _flask({"app.py": _NON_ROUTE_DECORATORS})

    assert result.routes == ()
    assert result.unparsed_files == ()
    assert [(route.function_name, route.decorator_line) for route in result.unresolved_routes] == [
        ("no_args", 11),
        ("keyword_only", 16),
    ]


def test_a_non_python_key_is_ignored_and_never_reported_as_unparsed():
    result = _flask({"README.md": "# not python at all {", "app.py": _ASYNC})

    assert _paths(result) == ["/async"]
    assert result.unparsed_files == ()


# ---------------------------------------------------------------------------
# The framework key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("framework", ["fastapi", "django", "next", None, "", "Flask"])
def test_a_tree_that_is_not_flask_returns_an_empty_map_rather_than_a_guess(framework):
    """`"Flask"` is in this list deliberately: the comparison is verbatim, on
    `declaration_in_force`'s ground that a normalizer would be a second place for the
    two sides to disagree. `_PYTHON_FRAMEWORK_SIGNATURES` only ever emits lowercase.
    """
    result = extract_routes(framework=framework, files={"app.py": _TWO_ROUTES})

    assert result == RouteMap(routes=(), unparsed_files=(), unresolved_routes=())


def test_a_non_flask_tree_is_not_even_parsed_so_a_broken_file_is_not_reported():
    result = extract_routes(framework="django", files={"broken.py": _BROKEN})

    assert result.unparsed_files == ()


# ---------------------------------------------------------------------------
# Order independence
# ---------------------------------------------------------------------------


def test_the_result_does_not_depend_on_the_order_the_files_arrive_in():
    """`ast.walk` is breadth-first, so without the sort the output would depend on
    nesting depth and on the caller's dict insertion order."""
    first = _flask({"b.py": _TWO_ROUTES, "a.py": _ASYNC})
    second = _flask({"a.py": _ASYNC, "b.py": _TWO_ROUTES})

    assert first == second
    assert [(route.file_path, route.path) for route in first.routes] == [
        ("a.py", "/async"),
        ("b.py", "/"),
        ("b.py", "/calculate"),
    ]


def test_routes_inside_one_file_come_back_in_line_order_not_in_walk_order():
    """`ast.walk` reaches the module-level `top` before the nested `nested`, even
    though `nested` is declared first in the source. The sort is what makes this
    stable."""
    assert _spans(_flask({"app.py": _FACTORY_FIRST})) == [("/nested", 2, 4), ("/top", 9, 11)]
