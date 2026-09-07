"""`SemgrepAdapter` and `TrivyAdapter` accept `ScanOptions` and read nothing from it.

`ScannerPort.run` takes the value for every scanner (ADR-0024 decision 4) so dispatch
routes on data rather than on a `tool == "zap"` branch (rule 4). The cost of that shape
is that two adapters now take an argument they ignore, and "ignores it" is a claim
worth holding: an adapter that started branching on consent would be a second place
active-scanning policy lived, and nothing else would notice.

Unit tests, not integration: the subject is the argv the adapter builds, which is
settled without running either tool. That keeps this off the container-bound budget
`CLAUDE.md` tracks, and it is a stronger assertion than comparing two real scan
outputs, which could agree for reasons unrelated to the option.
"""

import asyncio

import pytest

from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.scanners.trivy_adapter import TrivyAdapter
from verion.modules.scanning.domain.scan_options import ScanOptions

_CONSENTED = ScanOptions(active_scan_consented=True)
_NO_CONSENT = ScanOptions(active_scan_consented=False)


class _FakeProcess:
    returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"{}", b""

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return 0


def _record_argv(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    calls: list[tuple] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(args)
        return _FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    return calls


async def test_semgrep_builds_the_same_command_with_consent_and_without(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    adapter = SemgrepAdapter(config="p/default")
    calls = _record_argv(monkeypatch)

    await adapter.run(str(tmp_path), _NO_CONSENT)
    await adapter.run(str(tmp_path), _CONSENTED)

    assert calls[0] == calls[1]


async def test_trivy_builds_the_same_command_with_consent_and_without(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    adapter = TrivyAdapter(skip_db_update=True)
    calls = _record_argv(monkeypatch)

    await adapter.run(str(tmp_path), _NO_CONSENT)
    await adapter.run(str(tmp_path), _CONSENTED)

    assert calls[0] == calls[1]
