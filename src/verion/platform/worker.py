from typing import Any

from arq.connections import RedisSettings

from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresScannerConfigRepository,
)
from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresScanRepository,
    PostgresScanResultRepository,
)
from verion.modules.scanning.adapters.outbound.dns.system_dns_resolver import SystemDnsResolver
from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.scanners.trivy_adapter import TrivyAdapter
from verion.modules.scanning.adapters.outbound.scanners.zap_adapter import ZapAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout
from verion.modules.scanning.application.run_scan import RunScanUseCase
from verion.modules.scanning.ports.repo_checkout import RepoCheckoutPort
from verion.modules.scanning.ports.scanner import ScannerPort
from verion.platform.clock import SystemClock
from verion.platform.db import engine, session_factory
from verion.platform.id_generator import UuidIdGenerator
from verion.platform.settings import get_settings
from verion.shared_kernel.scanner_tools import ScannerTool


async def on_startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    # Stateless, safe to build once and share across jobs.
    #
    # Annotated as the ports rather than assigned straight into ctx: arq's ctx
    # is dict[str, Any], so anything stored in it is invisible to mypy. These
    # lines are the only place an adapter meets its port here, and so the only
    # place the type checker can verify conformance at all — every other
    # adapter in the project gets that for free from platform/di.py's
    # port-annotated factories. The dict annotation is what carries that
    # forward now that there are three: it checks all three against ScannerPort,
    # including the `tool`/`target_kind` members ADR-016 added.
    #
    # Keyed by ScannerTool rather than by str so a typo here is a type error,
    # not an UnknownScanner raised at scan time. `allow_private_targets` is
    # left at its default False — ADR-013 forbids True in production wiring.
    scanners: dict[ScannerTool, ScannerPort] = {
        ScannerTool.SEMGREP: SemgrepAdapter(config=settings.semgrep_ruleset),
        ScannerTool.TRIVY: TrivyAdapter(),
        ScannerTool.ZAP: ZapAdapter(dns_resolver=SystemDnsResolver()),
    }
    repo_checkout: RepoCheckoutPort = GitRepoCheckout()
    ctx["scanners"] = scanners
    ctx["repo_checkout"] = repo_checkout


async def on_shutdown(ctx: dict[str, Any]) -> None:
    await engine.dispose()


async def run_scan(ctx: dict[str, Any], scan_id: str) -> None:
    """Thin arq wrapper: pulls dependencies from ctx and delegates to
    RunScanUseCase, which has zero arq/DB/Redis imports of its own (CLAUDE.md
    rule 2 — use cases orchestrate through ports, arq specifics stay here).

    This function's name (`run_scan`) is the arq job name arq matches jobs
    against — it must stay identical to the string ArqJobQueue.enqueue_scan
    already hardcodes (adapters/outbound/queue/arq_job_queue.py), since arq
    resolves jobs by this name, not by Python identity.
    """
    # Fresh session per job, from platform/db.py's shared factory — sessions
    # must not be shared across concurrently-running jobs, same reasoning as
    # get_db_session's per-request session.
    async with session_factory() as session:
        use_case = RunScanUseCase(
            scans=PostgresScanRepository(session),
            scan_results=PostgresScanResultRepository(session),
            scanners=ctx["scanners"],
            repo_checkout=ctx["repo_checkout"],
            connected_repos=PostgresConnectedRepoRepository(session),
            github_connections=PostgresGitHubConnectionRepository(session),
            scanner_configs=PostgresScannerConfigRepository(session),
            id_generator=UuidIdGenerator(),
            clock=SystemClock(),
        )
        # Deliberately not rollback-on-exception: RunScanUseCase's own
        # except-block already writes FAILED (only flushed, not committed)
        # before re-raising, specifically so it's visible for debugging. A
        # blanket rollback here would silently undo that write. commit()
        # unconditionally in `finally` instead, so both the COMPLETED and
        # the FAILED outcome get persisted, then let the exception (if any)
        # continue propagating to arq for its own retry/backoff.
        try:
            await use_case.execute(scan_id)
        finally:
            await session.commit()


class WorkerSettings:
    functions = [run_scan]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    # arq's default is 300s (arq/worker.py). Scanners now run concurrently, so
    # a full run is max() not sum() — but max() is ZapAdapter's own 300s
    # timeout, plus a checkout, so the default would kill a legitimate
    # three-scanner run at roughly the moment ZAP finishes, intermittently and
    # looking like a ZAP bug. Each adapter still enforces its own hard timeout
    # and process kill (ADR-011), so this is a backstop against a hung job
    # rather than the thing that bounds a scanner. See ADR-016 decision 1.
    job_timeout = 600
    on_startup = staticmethod(on_startup)
    on_shutdown = staticmethod(on_shutdown)
