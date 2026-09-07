from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

from verion.modules.projects.domain.exceptions import InvalidScannerConfig
from verion.shared_kernel.scanner_tools import ScannerTool

_ALLOWED_TARGET_SCHEMES = ("http", "https")


@dataclass(frozen=True)
class ScannerConfig:
    """Which scanners a project runs, and the configuration they need.

    Deliberately not fields on SecurityContext. The two have different
    lifecycles: SecurityContext is a *detected and user-confirmed description
    of the application*, re-derived by BuildSecurityContextUseCase whenever
    repo content changes; this is *operational configuration* that has to
    survive that re-derivation. `exposure_tags` in particular is user-confirmed
    exposure annotation owned by UpdateExposureTagsUseCase, not a place to
    record configuration.

    It lives in `projects` because it is project configuration, and `scanning`
    reads it through ScannerConfigRepositoryPort (rule 3), the same way
    RunScanUseCase already reads ConnectedRepoRepositoryPort — not moved into
    `scanning` merely because `scanning` is its only consumer today.

    `zap_target_url` is honest debt: tool-specific configuration in a generic
    entity. The exit condition is concrete rather than "when it feels messy" —
    migrate to a normalized (project_id, tool) table when a SECOND tool needs
    tool-specific settings. Per PRODUCT_SPEC.md §9 that trigger may never fire
    inside MVP scope, which is exactly why normalizing now would be paying
    complexity for hypothetical flexibility (ADR-016 decision 3).

    Note what is *not* here: which scanners run when a project has no config
    row. That default is `scanning`'s (see `scanning/domain/scanner_dispatch.py`),
    because its rationale is a property of the scanners themselves — Semgrep
    and Trivy take no user-supplied target and so have no SSRF surface — which
    is scanning's knowledge, not this module's. This entity records only what a
    user actually chose.
    """

    id: str
    project_id: str
    enabled_tools: tuple[ScannerTool, ...]
    zap_target_url: str | None
    updated_at: datetime

    # Active-scanning consent (ADR-0024 decision 1). Three nullable columns and
    # deliberately no boolean: the target value IS the record, and a boolean
    # beside it would be a second source of truth for the same fact.
    #
    # Defaulted to None rather than required at every construction site, because
    # the default is the answer ADR-0024 decision 2 already gives for a project
    # with no row at all — no consent — and because a default can only ever fail
    # in the under-authorising direction. A caller that forgets these gets a
    # config that will not be attacked, never one that will.
    active_scan_consent_target: str | None = None
    active_scan_consent_granted_at: datetime | None = None
    active_scan_consent_granted_by: str | None = None

    @property
    def active_scan_consent_in_force(self) -> bool:
        """Whether an active scan is authorised against `zap_target_url` right now.

        **ADR-0024 decision 3's rule, and the single place it is evaluated.** Consent
        is in force only while the target it was granted against is still the target
        configured; when they differ it is absent, with no error, because changing a
        target is a configuration act rather than a failure.

        **A property rather than a stored column, for `Finding.dedup_hash`'s reason:**
        letting a caller supply this value is the thing to prevent. A stored boolean
        could disagree with the three fields it summarises and the target it compares
        them against — four values in all — and the disagreement would
        favour whichever the caller wrote — which for this value means attack traffic
        against a host whose consent was voided.

        **And a verdict rather than the data behind it**, which is what lets `scanning`
        consume it without holding a copy of this module's rule (rule 3). ADR-0022
        decision 2 crosses a module boundary the same way, and calls that shape the one
        its successors copy. `scanning` reads this bool; the comparison stays here.

        Equality is on the stored string verbatim, deliberately not normalized —
        ADR-0024 decision 3 records the residue that follows, that a cosmetic edit to
        the target voids consent and the owner re-grants. A normalizer would be a
        second place for the two sides to disagree.
        """
        return (
            self.active_scan_consent_target is not None
            and self.active_scan_consent_granted_at is not None
            and self.active_scan_consent_granted_by is not None
            and self.active_scan_consent_target == self.zap_target_url
        )


def parse_enabled_tools(names: Sequence[str]) -> tuple[ScannerTool, ...]:
    """Rejects a name no scanner answers to, rather than accepting it and
    letting every later scan fail wholesale on a typo."""
    parsed: list[ScannerTool] = []
    for name in names:
        try:
            tool = ScannerTool(name)
        except ValueError:
            known = ", ".join(sorted(tool.value for tool in ScannerTool))
            raise InvalidScannerConfig(
                f"Unknown scanner '{name}'. Known scanners: {known}"
            ) from None
        if tool not in parsed:
            parsed.append(tool)
    return tuple(parsed)


def validate_zap_target_url(url: str) -> None:
    """Well-formedness only — an http(s) scheme and a hostname.

    **This is deliberately not an SSRF check, and it does not pre-approve the
    target.** ADR-013's gate — including the resolved-IP DNS-rebinding check —
    runs as the first lines of `ZapAdapter.run()`, at scan time, every time.

    The restraint is the point. A write-time check that rejected private and
    loopback targets would make the stored URL *look* pre-approved, which is
    exactly the reasoning that would later make the runtime gate seem
    redundant — and it would be wrong, because DNS can rebind between
    configuring a target and scanning it. So a target that is well-formed but
    internal is accepted here and rejected at scan time, surfacing as that
    tool's `failure_reason`. Slightly later feedback, in exchange for one gate
    that is unambiguously the only gate.
    """
    parsed = urlparse(url)

    # First, and note this is *not* an exception to the paragraph above.
    # Refusing `user:pass@host` says nothing about where the target resolves,
    # so it pre-approves nothing and the runtime gate stays the only address
    # check. It is a rule-12 concern, not an SSRF one: this value is persisted,
    # returned by this resource's response schema, and — if it ever reached
    # ZapAdapter — echoed into a stored failure_reason. `hostname` stays
    # populated when userinfo is present, so the checks below would not catch
    # it. Ordered first for the same reason as its counterpart in
    # `scanning/domain/target_url.py`: once this branch has rejected the shape
    # that makes quoting unsafe, no later branch can leak a credential by
    # quoting the URL, whether or not it happens to today. This message
    # deliberately does not quote the URL back, or it would carry the
    # credential it exists to reject.
    if parsed.username is not None or parsed.password is not None:
        raise InvalidScannerConfig(
            "ZAP target URL must not contain userinfo (user:pass@host) — "
            "credentials must not be stored in a target URL"
        )

    if parsed.scheme not in _ALLOWED_TARGET_SCHEMES:
        raise InvalidScannerConfig(
            f"ZAP target URL must use one of {_ALLOWED_TARGET_SCHEMES}, got '{parsed.scheme}'"
        )
    if not parsed.hostname:
        raise InvalidScannerConfig("ZAP target URL must include a hostname")
