import asyncio
import tempfile
from pathlib import Path

import pytest

from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.domain.exceptions import UnsafeDastTarget


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
        await adapter.run("https://example.com/")

    assert spawned == []
    assert resolver.resolve_calls == ["example.com"]


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

    result = await adapter.run("https://example.com/")

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

    result = await adapter.run("http://127.0.0.1:8000/")

    assert result.tool == "zap"
    assert spawned and spawned[0][0] == "docker"
    assert resolver.resolve_calls == []
