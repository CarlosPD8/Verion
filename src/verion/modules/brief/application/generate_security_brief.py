import re
import unicodedata

from verion.modules.brief.domain.brief_member import MAX_MEMBERS, BriefMember
from verion.modules.brief.domain.exceptions import BriefMemberMissing, WhatHappenedRejected
from verion.modules.brief.domain.security_brief import SecurityBrief
from verion.modules.brief.ports.explanation_provider import ExplanationProviderPort
from verion.modules.brief.ports.security_brief_repository import SecurityBriefRepositoryPort

# `normalization`'s PORT, never its domain (rule 3). `Finding` is taken by inference off
# `get_by_id`'s annotation and never named, so the fill below is the one place `mypy` compares
# `BriefMember` against it (ADR-0034 decision 2, ADR-0023 section (b)).
from verion.modules.normalization.ports.finding_repository import FindingRepositoryPort

# `risk_engine`'s PORT, never its application or domain (rule 3, G35).
from verion.modules.risk_engine.ports.explainable_risk import ExplainableRiskPort
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort

# M6's length check. **Unmeasured**: the capture in ADR-0034 decision 7 measures real lengths.
MAX_WHAT_HAPPENED_CHARS = 2_000

_PRIORITY_TOKEN = re.compile(r"fix[_ ]now", flags=re.IGNORECASE)


def _check_what_happened(text: str, members: tuple[BriefMember, ...]) -> None:
    """M6: validate `describe`'s output, and **never reject on text the members supplied**.

    A rejection keyed on member-supplied text would let whoever controls a scanned repository
    make a surface's Brief permanently ungeneratable, by naming a file `fix_now.py` (ADR-0034
    decision 5). So each check is one a member cannot trigger:

    - **(i)** A control or format character other than `\\n`. Members cannot supply one: M1
      strips them before rendering.
    - **(ii)** Length over `MAX_WHAT_HAPPENED_CHARS`. Members cannot supply length.
    - **(iii)** `fix_now` or `fix now`, only where that spelling appears in NO member's rendered
      value. `describe`'s prompt holds no decision, so such a token is what the model ADDED.

    `plan`, `monitor` and `priority` are not checked: they are ordinary English (the known gap).
    """
    if any(unicodedata.category(c) in {"Cc", "Cf"} and c != "\n" for c in text):
        raise WhatHappenedRejected("what_happened carries a control or format character")
    if len(text) > MAX_WHAT_HAPPENED_CHARS:
        raise WhatHappenedRejected(
            f"what_happened is longer than {MAX_WHAT_HAPPENED_CHARS} characters"
        )
    # Per value, never across a join of them: "...fix" ending one value and "now..." starting
    # the next is not a token any member supplied.
    supplied = {
        match.lower()
        for member in members
        for value in member.rendered_values()
        for match in _PRIORITY_TOKEN.findall(value)
    }
    added = {match.lower() for match in _PRIORITY_TOKEN.findall(text)} - supplied
    if added:
        raise WhatHappenedRejected("what_happened names a priority bucket the members did not")


class GenerateSecurityBriefUseCase:
    """Narrate one current scored Risk twice and store the result. FR-8, M7.2, M7.3.

    **Order is a property, and nothing is written unless every step succeeds** (ADR-0033,
    ADR-0034 decision 3):

    1. **The port.** It authorizes before reading anything, then selects the surface by exact
       member set and fails closed on a changed set (ADR-0033 decision 1).
    2. **The member reads**, at most `MAX_MEMBERS`, after the verdict and before any billed
       call. A missing member raises `BriefMemberMissing`.
    3. **`describe`, then M6's validation.** First, because it is the call whose output can be
       rejected, so a rejection costs one billed call rather than two.
    4. **`explain`**, whose prompt holds no scanned content.
    5. **The write**, append-only (ADR-0033 decision 3).

    A failure at 3 means `explain` is never called; a failure at 4 bills one call. Either way
    nothing is stored. A unit test pins the order, because the route's session would roll back
    an early `add` and an integration test could not see it.

    **Authorization is member-level, inherited through the port** (ADR-0033 decision 7). It
    coincides with owner-gating only because nothing in `src/` creates a non-owner membership
    (**G75**). The member reads rely on that verdict and take no second one: they carry data,
    keyed by the ids the ENGINE returned and scoped by project (ADR-0034 decision 2).

    **Synchronous**, and billed twice per Brief. The request's session stays open across both
    provider calls, and nothing bounds repeats (**G73**). Generation does not refuse while
    normalization is unfinished (ADR-0033 decision 5, **G76**).
    """

    def __init__(
        self,
        explainable_risks: ExplainableRiskPort,
        findings: FindingRepositoryPort,
        explanations: ExplanationProviderPort,
        briefs: SecurityBriefRepositoryPort,
        clock: ClockPort,
        ids: IdGeneratorPort,
    ) -> None:
        self._explainable_risks = explainable_risks
        self._findings = findings
        self._explanations = explanations
        self._briefs = briefs
        self._clock = clock
        self._ids = ids

    async def _members(
        self, *, project_id: str, finding_ids: tuple[str, ...]
    ) -> tuple[BriefMember, ...]:
        """The first `MAX_MEMBERS` of the engine's sorted ids, read and sanitized.

        **The one fill site of `BriefMember`.** `finding` is never named: its type comes off
        `get_by_id`'s annotation, which is what keeps `cross-module-brief` satisfied.
        """
        members: list[BriefMember] = []
        for finding_id in finding_ids[:MAX_MEMBERS]:
            finding = await self._findings.get_by_id(project_id=project_id, finding_id=finding_id)
            if finding is None:
                raise BriefMemberMissing(
                    f"Finding '{finding_id}' is in a scored Risk but could not be read back"
                )
            location = finding.location
            members.append(
                BriefMember.from_scalars(
                    finding_id=finding.id,
                    source=finding.source,
                    title=finding.title,
                    file_path=location.file_path,
                    start_line=location.start_line,
                    end_line=location.end_line,
                    package=location.package,
                    installed_version=location.installed_version,
                    url=location.url,
                    http_method=location.http_method,
                    parameter=location.parameter,
                )
            )
        return tuple(members)

    async def execute(
        self, *, project_id: str, user_id: str, finding_ids: tuple[str, ...]
    ) -> SecurityBrief:
        risk = await self._explainable_risks.explainable_risk(
            project_id=project_id, user_id=user_id, finding_ids=finding_ids
        )
        members = await self._members(project_id=project_id, finding_ids=risk.finding_ids)
        what_happened = await self._explanations.describe(
            members=members, member_count=len(risk.finding_ids)
        )
        _check_what_happened(what_happened.text, members)
        explanation = await self._explanations.explain(decision=risk.decision)
        brief = SecurityBrief(
            id=self._ids.new_id(),
            project_id=project_id,
            # The ENGINE's members, never the request's: what was scored is what is stored.
            finding_ids=risk.finding_ids,
            decision=risk.decision,
            explanation=explanation,
            what_happened=what_happened,
            generated_at=self._clock.now(),
        )
        await self._briefs.add(brief)
        return brief
