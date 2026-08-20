# ADR-014: GitHub webhook signature verification and delivery handling

## Status

Accepted

## Context

M3.6 ("CI-triggered scanning") adds this codebase's first inbound webhook endpoint — the first unauthenticated-by-default HTTP endpoint that triggers real work (persisting a `Scan`, enqueuing a job that clones a repo and runs a scanner). `ARCHITECTURE.md` already anticipated this adapter category ("GitHub webhook receiver — translates push/PR events into `TriggerScanUseCase` calls"), but no existing ADR covers verifying an inbound webhook payload before trusting it. `PRODUCT_SPEC.md` §11 does not mention webhook signatures either — this is a real gap in the spec's security-principles list, closed here rather than left implicit.

Four sub-decisions, researched against GitHub's real webhook documentation (not memory, per this project's ADR-009 standard):

1. How to verify a payload is genuinely from GitHub before trusting any of its content.
2. How to survive GitHub's own redelivery behavior without duplicating work.
3. Where webhook *registration* belongs, and how to avoid creating duplicate hooks on reconnect.
4. Where the shared signing secret lives.

## Decision

**Signature verification.** GitHub signs every delivery with HMAC-SHA256 over the raw request body, sent as `X-Hub-Signature-256: sha256=<hex digest>`. `scanning/domain/webhook_signature.py::verify_signature` recomputes this digest and compares with `hmac.compare_digest` (GitHub's own docs explicitly warn against a plain `==`, which leaks timing information). This runs as the literal first thing the inbound router does with the raw request body — before `X-GitHub-Delivery`/`X-GitHub-Event` are even read and before any JSON parsing — mirroring ADR-0011/ADR-0013's "gate runs before any I/O or trusted-content use" pattern. The body must be read as raw bytes for this check: a parse-then-reserialize round-trip would not reproduce the exact bytes GitHub signed.

**Redelivery idempotency.** `TriggerScanUseCase` mints a new `scan.id` on every call — it has no idempotency of its own, and `ArqJobQueue`'s job-id dedup only protects a single already-generated `scan_id`, not repeat webhook deliveries of the same push. A new `WebhookDeliveryRepositoryPort`, keyed on GitHub's `X-GitHub-Delivery` GUID, dedupes at the delivery level. `HandleGitHubWebhookUseCase.execute` runs this check *first* — before the event-type branch, before payload parsing, before any `ConnectedRepo`/`Project` lookup — so a redelivery storm costs one indexed write attempt, not a repeated project-resolution query per retry. The Postgres implementation uses `INSERT ... ON CONFLICT DO NOTHING` plus a rowcount check, not `INSERT` + catch `IntegrityError`: the latter would leave the session in a failed-transaction state needing its own rollback, entangling with the request-scoped session's own commit/rollback lifecycle.

**Webhook registration ownership.** `ARCHITECTURE.md` already documented `VcsProviderPort`'s responsibility as "read repo metadata, register webhooks" — so registration is added to `projects`' existing port/adapter (`GitHubAdapter.register_webhook`), not a new scanning-owned port, and composes directly onto the existing `ConnectRepositoryViaGitHubUseCase` flow as its last step, reusing the `scope=repo` OAuth token already granted at connect time (M1.5a) — no new user-facing authorization step. Registration is list-then-create (`GET /repos/{owner}/{repo}/hooks`, skip if a hook with a matching `config.url` already exists, otherwise `POST`): GitHub's docs don't state whether a duplicate `config.url` is rejected or silently accepted as a second hook, so this stays defensive and idempotent rather than assuming either.

**Scan attribution.** A webhook has no authenticated user, but `TriggerScanUseCase.execute` requires `user_id`/`is_owner`. Since the project is already deterministically resolved via `ConnectedRepoRepositoryPort.get_by_url` and the router's signature check already proves GitHub itself is the caller, `HandleGitHubWebhookUseCase` calls `TriggerScanUseCase.execute(user_id=project.owner_id, is_owner=True, ...)` — attributing the scan to the project's real owner for audit purposes (`PRODUCT_SPEC.md` §11.5) rather than a placeholder string.

**Secret storage.** A single application-level `Settings.github_webhook_secret`, following the exact `jwt_secret_key`/`github_client_secret` pattern (rule 11's fail-fast-outside-`local` dict), rather than a per-project generated secret. Simpler MVP choice: no new storage/repository/port is needed, and every connected repo's webhook already funnels into the same inbound route regardless of project — a per-project secret would only pay off if different projects needed independently rotatable trust boundaries, which nothing in the current spec calls for.

## Consequences

The signature gate is fully unit-testable without any HTTP layer — `verify_signature` takes raw bytes and a secret, no framework dependency. The router-level "signature invalid → use case never called" property is tested by tracing actual call order (a spy use-case dependency override), the same standard ADR-0013's SSRF-gate tests use. The delivery-dedup ordering is tested the same way, with spy repository wrappers asserting zero calls on a redelivery.

This project's first FastAPI `lifespan` handler (`platform/app.py`) is a direct consequence of this ADR: the webhook route needs to enqueue arq jobs from the API process, which previously had no arq pool of its own (M3.3 only wired one into the worker process, since nothing needed it in the API process before now). The pool is created exactly once at startup and closed once at shutdown on `app.state` — `di.py`'s `get_job_queue` only ever reads it, never constructs one, preserving `ArqJobQueue`'s existing "pool creation is the caller's responsibility, no lazy-init race" contract.

## Alternatives considered

**A new scanning-owned `WebhookRegistrarPort`** instead of extending `projects`' `VcsProviderPort`. Rejected: `ARCHITECTURE.md` already documented webhook registration as part of `VcsProviderPort`'s responsibility, and putting it there keeps registration co-located with the OAuth token and the existing `ConnectRepositoryViaGitHubUseCase` flow it depends on, rather than duplicating a GitHub-HTTP-client adapter in a second module.

**A per-project generated webhook secret** instead of one application-level secret. Rejected for MVP: meaningfully more complexity (its own storage, its own repository/port, secret distribution at registration time) for isolation nothing in the current spec requires. Revisit if a future requirement calls for independently rotatable per-project trust boundaries.

**Threading the webhook URL/secret through `VcsProviderPort.register_webhook`'s call signature** instead of adapter constructor config. Rejected: this codebase's existing precedent (`SemgrepAdapter(config=settings.semgrep_ruleset)`) is config-via-constructor for adapter-level settings; threading platform config through every use-case call signature that eventually reaches the adapter would leak deployment concerns into application-layer code that doesn't otherwise need them.
