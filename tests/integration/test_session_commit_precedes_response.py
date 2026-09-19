"""A write route's transaction commits BEFORE its response is sent — M8.8 commit 1, G86.

`get_db_session` is the only yield dependency in `src/`, and its `commit()` runs in the code
after its `yield`. Where FastAPI runs that code decides what a 2xx means: exited on the request
stack it runs after `await response(...)`, so the client has its 201 before the row exists, and
a commit that raises arrives after a success has already been sent. `DbSessionDep` declares
`scope="function"`, which exits it after the response object is built and before it is sent.

**Why these tests call the ASGI app directly rather than through `httpx2.ASGITransport`.** That
transport awaits the whole application before it returns a response, so by the time a test holds
one, any code after the response has already run and row visibility at send time cannot be
observed. (The failed-commit half could be seen through it with `raise_app_exceptions=False`,
which no test in this suite passes; one harness serves both tests here.)

Here `send` is the observation point: it sees `http.response.start` at the moment the server
would put the status line on the wire, and it asks the database from a SECOND session at
that moment. That makes the check a point in the protocol rather than a timed wait, so it is
deterministic in both directions: without the scope, the row is invisible there every time.

Each test is killed by reverting `DbSessionDep`'s `scope="function"`. Both were run and seen
failing before that line was written.
"""

from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from verion.modules.identity.adapters.outbound.security.jwt_issuer import JwtAccessTokenIssuer
from verion.modules.projects.adapters.outbound.db.models import ProjectModel
from verion.platform import db
from verion.platform.app import app
from verion.platform.clock import SystemClock
from verion.platform.settings import get_settings


def _bearer(user_id: str) -> str:
    settings = get_settings()
    issuer = JwtAccessTokenIssuer(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expires_minutes,
        clock=SystemClock(),
    )
    return f"Bearer {issuer.issue(subject=user_id).value}"


async def _post_raw(
    path: str, body: bytes, authorization: str, on_start: Callable[[int], Awaitable[None]]
) -> None:
    """One HTTP request straight into the ASGI app; `on_start` runs at `http.response.start`."""
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"authorization", authorization.encode()),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("test", 1),
        "server": ("test", 80),
    }
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            await on_start(message["status"])

    await app(scope, receive, send)


def _create_project_body(name: str) -> bytes:
    return f'{{"name": "{name}"}}'.encode()


async def test_a_write_route_s_row_is_visible_to_a_second_session_when_the_response_starts(
    engine: AsyncEngine,
):
    name = f"commit-order-{uuid4().hex[:12]}"
    seen: dict[str, Any] = {}

    async def look_from_a_second_session(status: int) -> None:
        seen["status"] = status
        async with AsyncSession(engine) as second:
            row = await second.execute(select(ProjectModel.id).where(ProjectModel.name == name))
            seen["visible"] = row.first() is not None

    await _post_raw(
        "/projects/",
        _create_project_body(name),
        _bearer("user-commit-order"),
        look_from_a_second_session,
    )

    assert seen["status"] == 201
    assert seen["visible"], "the 201 was sent before the project row was committed"


class _CommitRaises(AsyncSession):
    async def commit(self) -> None:
        raise RuntimeError("injected commit failure")


async def test_a_commit_that_raises_produces_a_500_not_a_2xx(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
):
    """The failure is injected at the session: the real `get_db_session` runs, and asks the
    module-level `session_factory` for a session whose `commit` raises. Nothing in FastAPI is
    replaced.

    Starlette's `ServerErrorMiddleware` sends its 500 and then re-raises, so the exception is
    expected here in both directions; what differs is the status that reached the wire first.
    """
    monkeypatch.setattr(
        db,
        "session_factory",
        async_sessionmaker(engine, class_=_CommitRaises, expire_on_commit=False),
    )
    statuses: list[int] = []

    async def record(status: int) -> None:
        statuses.append(status)

    with pytest.raises(RuntimeError, match="injected commit failure"):
        await _post_raw(
            "/projects/",
            _create_project_body(f"commit-fails-{uuid4().hex[:12]}"),
            _bearer("user-commit-fails"),
            record,
        )

    assert statuses == [500], f"a failed commit answered {statuses} first"


# ---------------------------------------------------------------------------
# `after_commit` (M8.8 commit 3, ADR-0035 decision 5): callbacks run after a commit, and a
# rollback discards them. Driven through the real `get_db_session` generator, the way FastAPI
# drives it: `__anext__` for the yield, then `athrow` or a second `__anext__` for the exit.
# ---------------------------------------------------------------------------


async def test_after_commit_callbacks_run_once_the_session_has_committed():
    session_dependency = db.get_db_session()
    session = await session_dependency.__anext__()
    ran: list[str] = []

    async def callback() -> None:
        ran.append("sent")

    db.after_commit(session, callback)
    assert ran == [], "a callback ran before the commit"

    with pytest.raises(StopAsyncIteration):
        await session_dependency.__anext__()

    assert ran == ["sent"]


async def test_a_rollback_discards_after_commit_callbacks():
    """A handler that raises rolls the transaction back, and the job for a row that was
    never committed must not be sent. Kills running the callbacks on the `except` path."""
    session_dependency = db.get_db_session()
    session = await session_dependency.__anext__()
    ran: list[str] = []

    async def callback() -> None:
        ran.append("sent")

    db.after_commit(session, callback)

    with pytest.raises(RuntimeError, match="handler failed"):
        await session_dependency.athrow(RuntimeError("handler failed"))

    assert ran == []
