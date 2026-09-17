import json
from datetime import datetime

import httpx2

from verion.modules.risk_engine.application.explainable_decision import explainable_decision
from verion.modules.risk_engine.domain.scoring import SurfaceMember, score_surface
from verion.platform.di import get_clock, get_explanation_provider, get_id_generator
from verion.platform.settings import Settings
from verion.shared_kernel.scanner_tools import ScannerTool
from verion.shared_kernel.severity import Severity


def test_clock_resolves_to_a_working_adapter():
    clock = get_clock()

    assert isinstance(clock.now(), datetime)


def test_id_generator_resolves_to_a_working_adapter():
    id_generator = get_id_generator()

    assert id_generator.new_id() != id_generator.new_id()


def test_providers_are_cached_singletons():
    assert get_clock() is get_clock()
    assert get_id_generator() is get_id_generator()


async def test_explanation_provider_puts_the_settings_key_in_the_header_and_the_model_in_the_body(
    monkeypatch,
):
    """Through the REAL factory, to the wire (G65).

    `get_explanation_provider`'s return annotation is the only place `mypy` checks this
    wiring, and it checks shape: `api_key` and `model` are both `str`, so a factory passing
    them swapped type-checks and every adapter test — which builds the adapter directly —
    still passes. This test is the one thing that constructs the adapter the way production
    does and looks at which value went where.

    The adapter builds its own `AsyncClient` and the factory takes no transport, so the
    client class is patched to add a `MockTransport`. No network is reached.
    """
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            200,
            json={
                "model": "reported-model",
                "choices": [
                    {"message": {"content": "text", "refusal": None}, "finish_reason": "stop"}
                ],
            },
        )

    real_client = httpx2.AsyncClient

    def client_over_mock_transport(**kwargs):
        return real_client(**{**kwargs, "transport": httpx2.MockTransport(handler)})

    monkeypatch.setattr(httpx2, "AsyncClient", client_over_mock_transport)

    settings = Settings(
        app_env="local", openai_api_key="KEY-SENTINEL", openai_model="MODEL-SENTINEL"
    )
    decision = explainable_decision(
        score_surface(
            project_id="p",
            package=None,
            url="/x",
            members=[SurfaceMember(finding_id="f", source=ScannerTool.ZAP, severity=Severity.LOW)],
        )
    )

    await get_explanation_provider(settings).explain(decision=decision)

    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == "Bearer KEY-SENTINEL"
    assert json.loads(requests[0].content)["model"] == "MODEL-SENTINEL"
