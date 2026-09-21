from verion.modules.brief.application.generate_security_brief import GenerateSecurityBriefUseCase
from verion.modules.brief.domain.brief_generation import (
    BriefGeneration,
    BriefGenerationFailureKind,
)
from verion.modules.brief.domain.exceptions import BriefMemberMissing, ExplanationUnavailable
from verion.modules.brief.ports.brief_generation_repository import BriefGenerationRepositoryPort

# `risk_engine`'s PORT, never its application or domain (rule 3, **G35**).
from verion.modules.risk_engine.ports.explainable_risk import (
    ExplainableRiskAccessDenied,
    ExplainableRiskInconsistent,
    NoCurrentRisk,
)


class RunBriefGenerationUseCase:
    """Run one claimed generation to a terminal state. M8.6, ADR-0038.

    **This owns the state machine; `GenerateSecurityBriefUseCase` owns the narration and is
    unchanged.** The split is not tidiness: that use case is also reachable from nothing else
    now, and folding the two would put five `except` clauses into the code path a unit test
    exercises for its call order.

    **It lives in `application/` rather than in `platform/worker.py`** because `worker.py`'s job
    functions declare themselves thin arq wrappers whose business is arq specifics (rule 2), and
    because the mapping below is a decision about what a client does, not about a queue.

    **Every terminal exception maps to one of three kinds, and the mapping is decision 6's
    table.** Five failures, three client actions:

    - `NoCurrentRisk` → `SURFACE_CHANGED` — re-read `/scored-risks` and ask again.
    - `ExplanationUnavailable` (and its subclass `WhatHappenedRejected`) → `PROVIDER_UNAVAILABLE`
      — retry.
    - `ExplainableRiskInconsistent`, `BriefMemberMissing` → `INTERNAL_ERROR` — do not retry.

    **`ExplainableRiskAccessDenied` also terminates under `SURFACE_CHANGED`, and is not a fourth
    kind.** Naming a denial in a response body is what **G17** forbids; the poll refuses that
    caller on its own verdict, so the value is unobservable while the revocation stands, and the
    row still reaches a terminal state so decision 7's CHECK holds and nothing sits `running`
    forever. A re-granted membership makes it readable again reporting `surface_changed`, which
    is the right action for that caller anyway.

    **Nothing else is caught.** An unnamed exception propagates to arq, which marks the job
    failed and does not retry it (arq 0.28 retries only `Retry`, `RetryJob` and `CancelledError`),
    leaving the row `RUNNING` with nothing to re-drive it — **G87**, and the reason decision 11
    states the cost rather than denying it. Swallowing it here would write a terminal row
    claiming a classification this code did not make.
    """

    def __init__(
        self,
        generations: BriefGenerationRepositoryPort,
        generate: GenerateSecurityBriefUseCase,
    ) -> None:
        self._generations = generations
        self._generate = generate

    async def execute(self, generation: BriefGeneration) -> None:
        """Run one ALREADY CLAIMED generation. `NormalizeScanUseCase.execute(run)`'s shape.

        It takes the claimed row rather than an id, and does not claim: the claim commits alone,
        in its own transaction, before the work starts, and transaction boundaries are
        `platform/worker.py`'s job. A claim here as well would be a second one against a row this
        code has already moved out of `pending`, which returns `None` and silently does nothing.
        """
        generation_id = generation.id
        try:
            brief = await self._generate.execute(
                project_id=generation.project_id,
                # **The STORED requesting user, and this line is the second authorization gate**
                # (decision 4). `explainable_risk` authorizes and selects in one call, so passing
                # this id is what re-runs the verdict in the worker — and it is what catches a
                # membership revoked between enqueue and run, which `StartScanUseCase`'s
                # authorize-once path cannot. Passing any other id here would answer a question
                # nobody asked and store a Brief for a caller who may no longer read the project.
                user_id=generation.user_id,
                finding_ids=generation.finding_ids,
            )
        except (NoCurrentRisk, ExplainableRiskAccessDenied):
            await self._generations.fail(
                generation_id=generation_id,
                failure_kind=BriefGenerationFailureKind.SURFACE_CHANGED,
            )
        except ExplanationUnavailable:
            # Also `WhatHappenedRejected`, its subclass: a narrative failing output validation
            # is, to the caller, no usable narrative (ADR-0034 decision 5). The exception's
            # message is NOT stored — `detail` is derived from the kind at the adapter — so a
            # provider's status code cannot reach a column or a response (rule 12, **G71**).
            await self._generations.fail(
                generation_id=generation_id,
                failure_kind=BriefGenerationFailureKind.PROVIDER_UNAVAILABLE,
            )
        except (ExplainableRiskInconsistent, BriefMemberMissing):
            await self._generations.fail(
                generation_id=generation_id,
                failure_kind=BriefGenerationFailureKind.INTERNAL_ERROR,
            )
        else:
            await self._generations.succeed(generation_id=generation_id, brief_id=brief.id)
