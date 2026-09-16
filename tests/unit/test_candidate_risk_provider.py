"""`CorrelationCandidateRisks` — the wrapper its own docstring calls load-bearing.

**Written because the `architecture-guardian` showed the translation could be deleted with
the entire suite still green.** `test_compute_risk.py` fakes the *port*, so it exercises the
published contract and never this implementation; nothing else constructs this class except
`platform/di.py`. Deleting the `try/except` would let `correlation.domain`'s own
`ProjectAccessDenied` escape the published port, and M6.3's route could then handle a denial
only by importing `correlation.domain` — the rule 3 violation the port exists to prevent,
which `cross-module-risk-engine` does not catch (**G35**).
"""

import pytest

from verion.modules.correlation.application.candidate_risk_provider import (
    CorrelationCandidateRisks,
)
from verion.modules.correlation.application.correlate_findings import CorrelateFindingsUseCase
from verion.modules.correlation.domain.exceptions import CorrelationError, ProjectAccessDenied
from verion.modules.correlation.ports.candidate_risk import CandidateRiskAccessDenied

PROJECT = "proj-1"
USER = "user-1"


def _provider(project_access, finding_repository, serving_declaration_port, route_map_port):
    return CorrelationCandidateRisks(
        CorrelateFindingsUseCase(
            project_access=project_access,
            findings=finding_repository,
            serving=serving_declaration_port,
            route_maps=route_map_port,
        )
    )


async def test_a_denial_crosses_the_port_as_the_ports_own_exception_not_the_domains(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The assertion that makes deleting the translation fail.

    `project_access` permits nothing, so the wrapped use case raises `ProjectAccessDenied`.
    What must come out of the port is `CandidateRiskAccessDenied` — and must NOT be an
    instance of the domain exception, since the consumer may not name that type.
    """
    provider = _provider(
        project_access, finding_repository, serving_declaration_port, route_map_port
    )

    with pytest.raises(CandidateRiskAccessDenied) as raised:
        await provider.candidate_risks(project_id=PROJECT, user_id=USER)

    assert not isinstance(raised.value, ProjectAccessDenied)
    # The original is kept as the cause, so a traceback still shows where the refusal came
    # from — `raise ... from denied`.
    assert isinstance(raised.value.__cause__, ProjectAccessDenied)


def test_the_ports_denial_is_still_one_of_correlations_own_failures():
    """It is published, not foreign: `except CorrelationError` in this module must catch it."""
    assert issubclass(CandidateRiskAccessDenied, CorrelationError)


async def test_a_permitted_caller_gets_the_use_cases_groups_unchanged(
    project_access, finding_repository, serving_declaration_port, route_map_port
):
    """The wrapper renames the method and translates one exception. It transforms nothing."""
    project_access.permit(PROJECT, USER)
    provider = _provider(
        project_access, finding_repository, serving_declaration_port, route_map_port
    )

    groups = await provider.candidate_risks(project_id=PROJECT, user_id=USER)

    assert groups == []
