from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

from verion.modules.projects.domain.exceptions import InvalidScannerConfig
from verion.modules.projects.domain.project import ConnectedRepo
from verion.modules.projects.domain.scanner_config import ScannerConfig


@dataclass(frozen=True)
class ServingDeclaration:
    """A person's claim that the scanned URL serves the scanned tree.

    ADR-0028 decision 1. Its own entity and its own table rather than a column on
    either side, because **the claim is about a pair**: the URL side lives on
    `ScannerConfig.zap_target_url` and the tree side on `ConnectedRepo.url` /
    `ConnectedRepo.default_branch`. A column on either one is a claim about the
    other, so the row holding the claim would not be the row somebody edits when
    the claim stops being true.

    **Both sides are stored by value**, which is what gives `declaration_in_force`
    anything to compare — the same reason `ScannerConfig` stores
    `active_scan_consent_target` rather than a boolean (ADR-0024 decision 1).
    A by-value copy of another entity's field is not naturally a column on this one,
    which is the second half of why this is an entity.

    Note what is *not* here, and where each lives instead:

    - **No `in_force` field or property.** `ScannerConfig` can carry
      `active_scan_consent_in_force` as a property because both values it compares
      live on that entity. Here they do not, so the rule is the module-level function
      below — `domain/authorization.py`'s `may_read` is the shape, and ADR-0028
      decision 1 names it as such.
    - **No commit, and no revision of anything.** ADR-0028 decision 2 is explicit
      that this binds only to what is observable: it voids on **reconfiguration**
      and never on **drift**, and nothing in this system observes what the target is
      actually running. **G47** carries that residue.
    - **Who may declare it.** Owner-gated per ADR-0028 decision 3, enforced by the
      use case (M5.5 commit 2) through `domain/authorization.require_owner`, not by
      this entity. `declared_by` records who, and is not itself a permission check.

    `id` comes from `IdGeneratorPort.new_id()` (rule 9) and `declared_at` from
    `ClockPort` (rule 14); both are supplied by the use case that constructs this,
    which is commit 2's. This entity takes the values and validates neither, exactly
    as `ScannerConfig` takes `updated_at`.
    """

    id: str
    project_id: str
    declared_target_url: str
    declared_repo_url: str
    declared_default_branch: str
    declared_at: datetime
    declared_by: str


def declaration_in_force(
    *,
    declaration: ServingDeclaration | None,
    scanner_config: ScannerConfig | None,
    connected_repo: ConnectedRepo | None,
) -> bool:
    """Whether this project's declaration still describes its current configuration.

    **ADR-0028 decision 2's rule, and the single place it is evaluated.** Three pairs,
    all of which must hold: `declared_target_url` against `ScannerConfig.zap_target_url`,
    `declared_repo_url` against `ConnectedRepo.url`, and `declared_default_branch`
    against `ConnectedRepo.default_branch`. Any one of them differing voids the
    declaration, with no error, because changing either side is a configuration act
    rather than a failure — the treatment `active_scan_consent_in_force` already gives
    a changed target.

    **Equality is on the stored strings verbatim, deliberately not normalized.**
    ADR-0024 decision 3's ground, copied with its residue: a normalizer would be a
    second place for the two sides to disagree, and the cost is that a cosmetic edit to
    a URL or a branch name voids the declaration and the owner re-declares. Stripping
    or case-folding here would make this function quietly disagree with the strings the
    rest of the system stores and compares.

    **A verdict rather than the data behind it**, which is what will let `correlation`
    consume it without holding a copy of this module's rule (rule 3). The port that
    crosses that verdict is ADR-0028 decision 4's and ships at M5.6 with its consumer —
    **G48** is the entry that records the gap deliberately, so writing it here would be
    the thing that entry exists to make visible.

    **Keyword-only, and that is a safety property rather than a style.** Three arguments
    of three different types, two of them optional, is precisely the call site where a
    swapped pair type-checks under some future refactor and silently compares the wrong
    things. **G8** is this repository's record of tests whose subject is operand order;
    this removes the failure at the call site instead of testing for it.

    A missing `scanner_config` or `connected_repo` is not in force and is not an error:
    there is no live value to compare against, so the claim cannot be current. A missing
    `declaration` is the ordinary "never declared" case. `zap_target_url` being `None`
    falls out of the same comparison — `declared_target_url` is a non-optional `str`, so
    it never equals `None`, and a project that has cleared its target has thereby voided
    its declaration.
    """
    if declaration is None or scanner_config is None or connected_repo is None:
        return False

    return (
        declaration.declared_target_url == scanner_config.zap_target_url
        and declaration.declared_repo_url == connected_repo.url
        and declaration.declared_default_branch == connected_repo.default_branch
    )


def validate_declared_repo_url(url: str) -> None:
    """Refuses `user:pass@host` in a declared repository URL. Rule 12, nothing else.

    **Added at M5.5 commit 2 for a reason that only exists once this value is stored and
    returned.** `declared_target_url` inherits `validate_zap_target_url`, whose first
    branch makes the same refusal for the same reason. `declared_repo_url` had no
    counterpart, and it needs one more urgently rather than less: `ConnectedRepo.url` is
    stored **completely unvalidated** — `ConnectRepositoryUseCase` takes a `str` and
    constructs the entity with no parse — so a credential-bearing repository URL is
    storable today, and a declaration copies that string into a second table which
    `GET /projects/{id}/serving-declaration` returns to any **member**. That is a wider
    audience than `ConnectedRepo.url` itself reaches, since both routes exposing it are
    owner-gated writes.

    **Only the userinfo branch, deliberately.** No scheme check and no hostname check:
    this value is compare-and-set against `ConnectedRepo.url`, which this module accepts
    in any shape, so a well-formedness check here would refuse declarations for
    repositories the system is otherwise happy to hold and scan. The one thing that is
    refused is the one thing rule 12 is about.

    **The residue, stated rather than discovered:** a project whose connected repository
    URL already carries userinfo cannot declare at all, because the value it would have
    to declare is the value this refuses. That is the safe direction and it surfaces a
    real defect rather than hiding one — but it is a refusal the owner cannot resolve
    from this route, since nothing lets them edit a connected repository (**G51**).

    Like its counterpart, the message does not quote the URL back, or it would carry the
    credential it exists to reject.
    """
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        raise InvalidScannerConfig(
            "Declared repository URL must not contain userinfo (user:pass@host) — "
            "credentials must not be stored in a declared URL"
        )
