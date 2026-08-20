import verion.platform.app as app_module
from verion.platform.app import app

# M3.6 added this project's first FastAPI lifespan handler (platform/app.py's
# _lifespan), creating the arq redis pool exactly once at startup and closing
# it once at shutdown on app.state — di.py's get_job_queue only ever *reads*
# app.state.arq_redis, it never constructs a pool itself (see that
# function's own comment). ASGITransport (used by every route test in this
# suite) never runs the ASGI "lifespan" scope on its own, so this test
# exercises the lifespan context directly.


class _FakePool:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


async def test_lifespan_creates_the_pool_once_at_startup_and_closes_it_once_at_shutdown(
    monkeypatch,
):
    fake_pool = _FakePool()
    create_pool_calls = []

    async def fake_create_pool(redis_settings):
        create_pool_calls.append(redis_settings)
        return fake_pool

    monkeypatch.setattr(app_module, "create_pool", fake_create_pool)

    async with app.router.lifespan_context(app):
        # Not lazily built on first request — already present as soon as
        # the startup phase completes, before any request is served.
        assert app.state.arq_redis is fake_pool
        assert fake_pool.closed is False

    assert len(create_pool_calls) == 1
    assert fake_pool.closed is True


async def test_lifespan_creates_a_genuinely_working_pool_against_real_redis():
    # Companion to the mocked test above: proves the real (non-faked) path
    # also produces a pool that can actually talk to Redis, not just that
    # create_pool/aclose get called in the right order.
    async with app.router.lifespan_context(app):
        assert await app.state.arq_redis.ping() is True
