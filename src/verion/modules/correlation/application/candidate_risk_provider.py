from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.domain.exceptions import ProjectAccessDenied
from verion.modules.correlation.domain.matching import MatchGroup
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied


class CorrelationCandidateRisks:
    """`CandidateRiskPort` over `CorrelateFindingsUseCase` — the published capability (M6.2).

    **A wrapper rather than letting the use case satisfy the Protocol structurally**, which
    it very nearly does: its `execute(*, project_id, user_id) -> list[MatchGroup]` has the
    right shape already, and a Protocol declaring `execute` would be satisfied with no new
    code at all. Two reasons not to:

    - `execute` is not a published name. `await port.candidate_risks(...)` says what the
      consumer is asking for at the call site; `await port.execute(...)` says nothing.
    - A Protocol keyed on a method named `execute` would be satisfied **incidentally** by
      any class in this repository with a matching `execute` — and every use case here has
      one. The structural check would then pass by coincidence rather than by intent, which
      is the `mypy` conformance site telling a reviewer less than it appears to.

    **The translation below is the load-bearing line**, not boilerplate: it converts this
    module's `domain` exception into the port's own, because the consumer may not name
    anything under `correlation.domain` (rule 3, and `cross-module-risk-engine` in CI). See
    `CandidateRiskAccessDenied` for why that class is declared in `ports/`.

    Holds no state and takes no session — the use case it wraps owns both.
    """

    def __init__(self, correlate: CorrelateFindingsUseCase) -> None:
        self._correlate = correlate

    async def candidate_risks(self, *, project_id: str, user_id: str) -> list[MatchGroup]:
        try:
            return await self._correlate.execute(project_id=project_id, user_id=user_id)
        except ProjectAccessDenied as denied:
            # `from denied` keeps the original in the traceback. The message is
            # `correlation`'s own and names only the project id the caller supplied.
            raise CandidateRiskAccessDenied(str(denied)) from denied
