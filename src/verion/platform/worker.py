from datetime import timedelta
from typing import Any

from arq import cron, func
from arq.connections import RedisSettings

from verion.modules.brief.adapters.outbound.db.repository import (
    PostgresBriefGenerationRepository,
    PostgresSecurityBriefRepository,
)
from verion.modules.brief.adapters.outbound.explanation.openai_adapter import (
    OpenAIExplanationProvider,
)
from verion.modules.brief.application.generate_security_brief import (
    GenerateSecurityBriefUseCase,
)
from verion.modules.brief.application.run_brief_generation import RunBriefGenerationUseCase
from verion.modules.brief.ports.explanation_provider import ExplanationProviderPort
from verion.modules.correlation.application.candidate_risk_provider import (
    CorrelationCandidateRisks,
)
from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.identity.adapters.outbound.db.repository import (
    PostgresGitHubConnectionRepository,
)
from verion.modules.normalization.adapters.outbound.db.repository import (
    PostgresFindingRepository,
    PostgresNormalizationRunRepository,
)
from verion.modules.normalization.adapters.outbound.queue.arq_normalization_queue import (
    ArqNormalizationQueue,
)
from verion.modules.normalization.application.normalize_scan import NormalizeScanUseCase
from verion.modules.normalization.application.sweep_pending_normalizations import (
    SweepPendingNormalizationsUseCase,
)
from verion.modules.normalization.ports.normalization_queue import NormalizationQueuePort
from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresConnectedRepoRepository,
    PostgresProjectAccessReader,
    PostgresRouteMapReader,
    PostgresScannerConfigRepository,
    PostgresServingDeclarationVerdictReader,
)
from verion.modules.risk_engine.application.compute_risk import ComputeRiskUseCase
from verion.modules.risk_engine.application.explainable_risk_provider import (
    ScoredExplainableRisks,
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
    # lines are ~~the only place an adapter meets its port here, and so~~ the only
    # place the type checker can verify conformance ~~at all~~ **for anything
    # that goes through ctx** — every other
    # adapter in the project gets that for free from platform/di.py's
    # port-annotated factories. The dict annotation is what carries that
    # forward now that there are three: it checks all three against ScannerPort,
    # including the `tool`/`target_kind` members ADR-016 added.
    #
    # *(Narrowed 2026-09-21, M8.6 commit 3, and measured rather than reasoned: the
    # guardian mutated four of `GenerateSecurityBriefUseCase`'s keyword arguments in
    # `generate_brief` below and `mypy` failed at that call site each time. So this
    # file now has conformance checks in two places — here, for what ctx carries, and
    # at every port-annotated constructor parameter a job fills. The unqualified "at
    # all" was the claim the same guardian round disproved in `di.py`; it is narrowed
    # here for the same reason. What stays true is the part that matters: a value read
    # back OUT of ctx is `Any`, so these annotations are the only thing standing
    # between a wrong adapter and a green type check for `scanners`, `repo_checkout`
    # and `explanations`.)*
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
    # M8.6, ADR-0038 decision 9. Stateless and session-free, so it belongs here beside
    # `scanners` rather than being rebuilt per job — and annotated as its port for the same
    # reason: this is the only place `mypy --strict` sees it in this process.
    #
    # **This line is what makes the WORKER process read `OPENAI_API_KEY`**, which until M8.6 only
    # the API did. No document said otherwise — ADR-0032's "every non-local deployment inherits
    # OPENAI_API_KEY" is process-agnostic — so this is new deployment surface, not a correction.
    # Rule 11 is satisfied as to `openai_api_key`, already `_DEV_ONLY_DEFAULTS`' fourth entry,
    # because the guard runs wherever `Settings` is constructed; rule 12 is the one that gains
    # surface, since a provider failure now renders in a worker log rather than an HTTP response,
    # and ADR-0032 decision 6's fixed messages raised `from None` are what hold it.
    explanations: ExplanationProviderPort = OpenAIExplanationProvider(
        api_key=settings.openai_api_key, model=settings.openai_model
    )
    ctx["scanners"] = scanners
    ctx["repo_checkout"] = repo_checkout
    ctx["explanations"] = explanations


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
            # Same session as every repository above, which is the whole point:
            # the ScanResult rows and the normalization handoff row commit
            # together or not at all (ADR-0017 decision 2). Conformance to
            # NormalizationRunRepositoryPort is checked here because
            # RunScanUseCase.__init__ annotates the parameter as that port —
            # unlike ctx["scanners"], which arrives as Any.
            normalization_runs=PostgresNormalizationRunRepository(session),
            id_generator=UuidIdGenerator(),
            clock=SystemClock(),
        )
        # Deliberately not rollback-on-exception: RunScanUseCase's own
        # except-block already writes FAILED (only flushed, not committed)
        # before re-raising, specifically so it's visible for debugging. A
        # blanket rollback here would silently undo that write. commit()
        # unconditionally in `finally` instead, so both the COMPLETED and
        # the FAILED outcome get persisted, then let the exception (if any)
        # continue propagating to arq, which marks the job failed. arq 0.28 does
        # not retry it: only Retry, RetryJob and CancelledError are retried (G87).
        try:
            await use_case.execute(scan_id)
        finally:
            await session.commit()

    # OUTSIDE the `async with`, and outside the try/finally, both deliberately.
    #
    # After the commit, because ADR-0017 decision 2 makes the normalization_runs
    # row the durable record and this enqueue only a latency optimization on top
    # of it. Enqueued before the commit, the job could be picked up before — or
    # instead of — the row it is about. RunScanUseCase cannot do this itself: it
    # does not own the transaction and has no way to express "after the commit".
    #
    # Skipped on the exception path, because reaching it means either the
    # transaction aborted (so there is no row) or an unanticipated exception
    # committed a pending row the sweep will collect. Branching on which would add
    # a case nobody can test cheaply to buy latency in a rare one. (Until M8.8 this
    # also said arq retries run_scan, so a successful retry arrives here anyway; arq
    # 0.28 retries no ordinary exception, so it does not, and the sweep is the
    # whole recovery for the committed-row case: G87.)
    await _enqueue_normalization(ctx, scan_id)


async def _enqueue_normalization(ctx: dict[str, Any], scan_id: str) -> None:
    # Annotated as the port for the same reason on_startup annotates `scanners`:
    # ctx is dict[str, Any], so `ctx["redis"]` arrives as Any and this is the only
    # place mypy can check that the adapter satisfies NormalizationQueuePort.
    queue: NormalizationQueuePort = ArqNormalizationQueue(ctx["redis"])
    try:
        await queue.enqueue_normalization(scan_id)
    except Exception:
        # Deliberately swallowed, and deliberately broad — the same shape as
        # RunScanUseCase._run_scanner's catch and for a related reason: what is
        # downstream of this point must not be able to fail work that has already
        # succeeded.
        #
        # The normalization_runs row committed above IS the record of owed work
        # (ADR-0017 decision 2). Raising here would make Redis a correctness
        # dependency of a scan that is already durably complete, and would hand
        # arq a retry that re-runs every enabled scanner (ADR-016 decision 1) to
        # fix a message that was never the record in the first place.
        #
        # What it costs, stated because it is real and currently invisible: while
        # Redis is unreachable EVERY scan degrades to sweep latency — up to
        # `normalization_sweep_stale_after_seconds` (900s) — with no trace at all,
        # because `src/` has no logging and this issue does not add any. That is
        # accepted: findings arrive late, never wrong and never lost. If it ever
        # needs to be observable, the fix is a metric or a log line HERE. It is
        # not a raise. Pinned by test_worker_run_scan.py's enqueue-failure case,
        # which asserts the scan still commits COMPLETED and the row is pending.
        return


async def normalize_scan(ctx: dict[str, Any], scan_id: str) -> None:
    """Thin arq wrapper for NormalizeScanUseCase. Name is the arq job name.

    Must stay identical to the string ArqNormalizationQueue hardcodes, since arq
    resolves jobs by name rather than by Python identity — the same coupling
    `run_scan` documents.

    **Two sessions, and the split is the state machine rather than tidiness.** The
    claim commits alone, before the work starts. In one transaction `RUNNING`
    would be written and overwritten before anything could observe it, which makes
    a job killed mid-flight indistinguishable from one that never started — and
    that distinction is the whole reason the sweep can recover a stuck run.
    Transaction boundaries are this module's job, the same way `run_scan`'s
    commit-in-`finally` is; the decision of whether there is anything to claim
    lives in `claim` itself, and this function only branches on its answer.
    """
    async with session_factory() as claim_session:
        run = await PostgresNormalizationRunRepository(claim_session).claim(
            scan_id=scan_id, now=SystemClock().now()
        )
        await claim_session.commit()

    if run is None:
        # Either no row (the scan failed before persisting anything, so there is
        # nothing to normalize — ADR-0017 decision 3) or already COMPLETED (a
        # redelivered job). Both mean the same thing to this function.
        return

    async with session_factory() as session:
        use_case = NormalizeScanUseCase(
            scan_results=PostgresScanResultRepository(session),
            findings=PostgresFindingRepository(session),
            normalization_runs=PostgresNormalizationRunRepository(session),
            id_generator=UuidIdGenerator(),
            clock=SystemClock(),
        )
        # Same commit-in-`finally`, same reason as run_scan: the use case writes
        # `failed` before re-raising and a blanket rollback here would silently
        # undo it. On a DB error the commit raises PendingRollbackError instead
        # and the row stays `running`, which the sweep collects.
        try:
            await use_case.execute(run)
        finally:
            await session.commit()


async def generate_brief(ctx: dict[str, Any], generation_id: str) -> None:
    """Thin arq wrapper for `RunBriefGenerationUseCase`. M8.6, ADR-0038.

    This function's name is the arq job name, and it must stay identical to the string
    `ArqBriefGenerationQueue` hardcodes — the same coupling `run_scan` and `normalize_scan`
    document, since arq resolves jobs by name and not by Python identity.

    **Two sessions, and the split is the state machine rather than tidiness** — `normalize_scan`'s
    shape, for its reason. The claim commits alone, before the work starts, so a job killed
    mid-flight is distinguishable from one that never started. Here that distinction buys less
    than it does for normalization, which has a sweep to act on it; it is kept anyway, because a
    redelivered job must not run twice and `claim`'s conditional UPDATE is what refuses it.

    **The graph below is built per job, from `session_factory()`.** Six session-bound
    repositories share one session, which is the whole point: everything this job reads sees one
    consistent snapshot, and the `brief_generations` write lands in the same transaction as
    nothing else, because the Brief's own write is the only other one. The provider comes from
    `ctx` (ADR-0038 decision 9), and it is the ONE dependency a test can replace, which is why
    the integration tests hand-build `ctx` rather than reaching for `app.dependency_overrides` —
    that rewrites FastAPI's request graph and this function has no FastAPI in it at all.

    **What `mypy` does and does not check here, measured rather than assumed.** `ctx` is
    `dict[str, Any]`, so every read from it is unchecked — the hole `on_startup`'s comment
    describes for `scanners`. Everything else below **is** checked: the constructors are called
    by keyword into use cases whose parameters are port-annotated, so
    `GenerateSecurityBriefUseCase.__init__` verifies **five** of its six arguments here
    (swapping `briefs=` for the generation repository fails `mypy` at this call site), and
    `CorrelateFindingsUseCase`'s and `RunBriefGenerationUseCase`'s parameters do the same for
    theirs. The sixth, `explanations=ctx["explanations"]`, is `Any` and satisfies its annotation
    vacuously; `on_startup`'s annotation on assignment is what covers that one, which is the
    whole reason it is written there rather than assigned straight into `ctx`.
    """
    async with session_factory() as claim_session:
        generations = PostgresBriefGenerationRepository(claim_session)
        claimed = await generations.claim(generation_id)
        await claim_session.commit()

    if claimed is None:
        # No such row, already claimed by another worker, or already terminal. All three mean
        # the same thing here, as `normalize_scan`'s `run is None` does.
        return

    async with session_factory() as session:
        findings = PostgresFindingRepository(session)
        correlate = CorrelateFindingsUseCase(
            project_access=PostgresProjectAccessReader(session),
            findings=findings,
            serving=PostgresServingDeclarationVerdictReader(session),
            route_maps=PostgresRouteMapReader(session),
        )
        use_case = RunBriefGenerationUseCase(
            generations=PostgresBriefGenerationRepository(session),
            generate=GenerateSecurityBriefUseCase(
                # `CorrelateFindingsUseCase` is where the verdict is taken, with the `user_id`
                # `RunBriefGenerationUseCase` reads off the stored row. That is the second of
                # ADR-0038 decision 4's two gates, and the only one in this process.
                explainable_risks=ScoredExplainableRisks(
                    ComputeRiskUseCase(
                        candidate_risks=CorrelationCandidateRisks(correlate), findings=findings
                    )
                ),
                findings=findings,
                explanations=ctx["explanations"],
                briefs=PostgresSecurityBriefRepository(session),
                clock=SystemClock(),
                ids=UuidIdGenerator(),
            ),
        )
        # Same commit-in-`finally`, same reason as `run_scan` and `normalize_scan`: the use case
        # writes its terminal row (succeeded or failed) before returning, and a blanket rollback
        # here would silently undo it. An exception the use case does not name propagates past
        # this to arq, which marks the job failed and — arq 0.28 — does not retry it, leaving the
        # row `running` with nothing to re-drive it. That is **G87**, and ADR-0038 decision 11
        # states the cost rather than adding a sweep.
        try:
            await use_case.execute(claimed)
        finally:
            await session.commit()


async def sweep_pending_normalizations(ctx: dict[str, Any]) -> int:
    """Re-enqueue normalization for owed work that is not progressing.

    Registered as a cron job rather than a self-rescheduling task: `arq.cron`'s
    `unique=True` default makes each tick's job id unique to its intended
    execution time, so running N workers produces one sweep per tick rather than
    N — the singleton comes from arq rather than from a lock this project builds.
    """
    settings = get_settings()
    async with session_factory() as session:
        queue: NormalizationQueuePort = ArqNormalizationQueue(ctx["redis"])
        use_case = SweepPendingNormalizationsUseCase(
            normalization_runs=PostgresNormalizationRunRepository(session),
            queue=queue,
            clock=SystemClock(),
            stale_after=timedelta(seconds=settings.normalization_sweep_stale_after_seconds),
            batch_size=settings.normalization_sweep_batch_size,
        )
        return await use_case.execute()


class WorkerSettings:
    # `normalize_scan` is registered with keep_result=0, and that is the sweep's
    # threshold actually meaning what it says rather than a tuning preference.
    #
    # arq refuses `enqueue_job` for an id that already exists as either the
    # in-progress key OR the RESULT key (arq/connections.py), and `keep_result`
    # defaults to 3600s — so a job that was killed by job_timeout keeps its id
    # reserved for an hour after it died. That is precisely the row ADR-0021
    # decision 2 added `running` to the sweep for: the first tick at 900s would
    # get a silent `None` from the enqueue and recovery would slip to ~3600s,
    # while `normalization_sweep_stale_after_seconds` advertised 900. Measured
    # against the pinned arq, not inferred from the docs.
    #
    # Setting it to 0 costs nothing here: nobody reads a normalize_scan result.
    # The normalization_runs row is the record (ADR-0017 decision 2), and it
    # carries strictly more than arq's result would. Dedup against a job that is
    # queued or genuinely in flight is unaffected — that is the in-progress key,
    # not the result key.
    #
    # `generate_brief` is registered with `keep_result=0` too, and ADR-0038 decision 10 argues
    # it rather than copying the flag: the reason above has two clauses, and BOTH hold here
    # because of decision 2. Nobody reads a `generate_brief` result — the poll reads the
    # `brief_generations` row — and that row is the record, carrying strictly more than arq's
    # result would. The in-progress dedup is unaffected, which is the half that matters for a
    # redelivered job.
    functions = [
        run_scan,
        func(normalize_scan, keep_result=0),
        func(generate_brief, keep_result=0),
    ]
    # Every 5 minutes. The sweep is a backstop, not the trigger — the enqueue in
    # run_scan is what makes normalization prompt — so the interval only bounds
    # how late a LOST message is noticed, and a tick over an empty backlog is one
    # indexed query. `unique=True` (arq's default) is what keeps N workers from
    # producing N sweeps per tick.
    cron_jobs = [cron(sweep_pending_normalizations, minute=set(range(0, 60, 5)))]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    # arq's default is 300s (arq/worker.py). Scanners now run concurrently, so
    # a full run is max() not sum() — but max() is ZapAdapter's own timeout,
    # 540s since M5.4, plus a 30s checkout, so the default would kill a
    # legitimate three-scanner run long before ZAP finishes, intermittently and
    # looking like a ZAP bug. 540 + 30 = 570 against this 600 leaves 30s for the
    # rest of the job, which is the margin ZapAdapter's own comment derives and
    # is why raising a scanner timeout is not a local decision. Each adapter
    # still enforces its own hard timeout
    # and process kill (ADR-011), so this is a backstop against a hung job
    # rather than the thing that bounds a scanner. See ADR-016 decision 1.
    job_timeout = 600
    on_startup = staticmethod(on_startup)
    on_shutdown = staticmethod(on_shutdown)
