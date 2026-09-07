import asyncio
import tempfile
from pathlib import Path

import pytest

from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.domain.exceptions import UnsafeDastTarget
from verion.modules.scanning.domain.scan_options import ScanOptions

# The default state: no project has granted active-scan consent, so this is what
# dispatch hands every scanner unless an owner opted in.
_NO_CONSENT = ScanOptions(active_scan_consented=False)
_CONSENTED = ScanOptions(active_scan_consented=True)


class _FakeDockerProcess:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def _patch_plan_dir(monkeypatch: pytest.MonkeyPatch, plan_dir: Path) -> None:
    # ZapAdapter.run() generates its own temp dir internally — pin it to a
    # pytest-managed tmp_path so a fake `docker run` can write the report
    # file the adapter reads back, without parsing the mount argv string
    # (which would be ambiguous on Windows, where the path itself contains
    # a drive-letter colon).
    monkeypatch.setattr(tempfile, "mkdtemp", lambda prefix="": str(plan_dir))


async def test_rejects_a_private_resolved_ip_before_spawning_any_subprocess(
    dns_resolver_factory, monkeypatch: pytest.MonkeyPatch
):
    resolver = dns_resolver_factory(["127.0.0.1"])
    adapter = ZapAdapter(dns_resolver=resolver)

    spawned: list[tuple] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        spawned.append(args)
        raise AssertionError("subprocess must not be spawned when the target is unsafe")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    with pytest.raises(UnsafeDastTarget):
        await adapter.run("https://example.com/", _NO_CONSENT)

    assert spawned == []
    assert resolver.resolve_calls == ["example.com"]


async def test_a_consented_private_target_is_still_refused_and_never_reaches_the_plan_builder(
    dns_resolver_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """ADR-0024 decision 6: consent is not a second path around ADR-013.

    **The plan-file clause is the new half and is what pins decision 4's placement.**
    Asserting only "no subprocess" would pass an implementation that read consent
    first, built an active plan, wrote it to disk and *then* ran the gates — the
    refusal would look identical from outside while the ordering property was gone.
    The plan file is the observable that distinguishes them, because
    `_build_plan_yaml`'s only call site sits downstream of both gates.

    The target is `_CONSENTED`, so this is the consented case specifically: ADR-013
    decides which targets may be reached, consent only what is done to one already
    admitted.
    """
    resolver = dns_resolver_factory(["127.0.0.1"])
    adapter = ZapAdapter(dns_resolver=resolver)
    _patch_plan_dir(monkeypatch, tmp_path)

    spawned: list[tuple] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        spawned.append(args)
        raise AssertionError("subprocess must not be spawned when the target is unsafe")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    with pytest.raises(UnsafeDastTarget):
        await adapter.run("https://example.com/", _CONSENTED)

    assert spawned == []
    assert list(tmp_path.iterdir()) == []


async def test_a_public_resolved_ip_lets_the_scan_reach_docker(
    dns_resolver_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    resolver = dns_resolver_factory(["93.184.216.34"])
    adapter = ZapAdapter(dns_resolver=resolver)
    _patch_plan_dir(monkeypatch, tmp_path)

    spawned: list[tuple] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        spawned.append(args)
        (tmp_path / "report.json").write_text('{"ok": true}')
        return _FakeDockerProcess(returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = await adapter.run("https://example.com/", _NO_CONSENT)

    assert result.tool == "zap"
    assert result.raw_output == '{"ok": true}'
    assert spawned and spawned[0][0] == "docker"


async def test_allow_private_targets_skips_the_ssrf_gate_entirely(
    dns_resolver_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    resolver = dns_resolver_factory(["127.0.0.1"])
    adapter = ZapAdapter(dns_resolver=resolver, allow_private_targets=True)
    _patch_plan_dir(monkeypatch, tmp_path)

    spawned: list[tuple] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        spawned.append(args)
        (tmp_path / "report.json").write_text('{"ok": true}')
        return _FakeDockerProcess(returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = await adapter.run("http://127.0.0.1:8000/", _NO_CONSENT)

    assert result.tool == "zap"
    assert spawned and spawned[0][0] == "docker"
    assert resolver.resolve_calls == []
