# ADR-0035 — A route that starts a scan: who may start one, what the caller gets back, and when the job may run

## Status

Accepted — 2026-09-19 (M8.8). Written and accepted before M8.8's route code is committed, on
ADR-0030's and ADR-0033's precedent. M8.8's first commit, `465d036`, already landed the one
platform change this ADR builds on (decision 5).

## Context

M8's exit condition opens with *"a user starts a scan"*. No route starts one:
`TriggerScanUseCase` is built by `get_trigger_scan_use_case` in `platform/di.py`, and its only caller
is `HandleGitHubWebhookUseCase` (**G70**). ADR-0014 made the webhook the one way in, and ADR-0017's
Context recorded that there is *"no manual-trigger route and no scan-read route"*.

**Observed at HEAD `465d036`**, by reading the code and the installed packages:

- `TriggerScanUseCase.execute(project_id, user_id, project_exists, is_owner)` raises
  `ProjectNotFound` or `InsufficientPermissions`. That is the existence/permission split ADR-0022
  decision 2 refused for cross-module reads. The webhook passes both flags as `True`.
- `ProjectAccessPort` publishes one verdict, `may_read_project`, whose rule is
  `projects/domain/authorization.may_read`: a membership exists.
- `RunScanUseCase._checkout_repo` reads the GitHub connection of `scan.triggered_by`, under the
  comment *"triggered_by is always the project owner — TriggerScanUseCase requires is_owner=True"*.
  So who may start a scan also decides whose GitHub token clones the repository.
- `TriggerScanUseCase` flushes the `Scan` and then enqueues its job. The request's session commits
  later. A worker that takes the job first finds no row, `RunScanUseCase` raises `ValueError`, and
  `ArqJobQueue`'s `_job_id=scan_id` stops the job from being enqueued again.
- arq 0.28.0 retries a job only on `Retry`, `RetryJob` or `CancelledError`
  (`arq/worker.py`'s job runner). Any other exception finishes the job as failed.
  `RunScanUseCase`'s docstring, ADR-0016's Consequences and ADR-0017's Context all say the
  opposite for scanning, and `NormalizeScanUseCase` and ADR-0021 decision 4 say it for
  normalization.
- `ScanRepositoryPort` has `add`, `get_by_id` and `update`, and no route reads a `Scan`.
- `RepoCheckoutFailed` carries git's stderr with only the access token redacted. `git clone`
  writes `Cloning into '<target_dir>'...` there, and `target_dir` is an absolute `verion-scan-…`
  path. Three route test files already assert `verion-scan-` never appears in their responses.
- Nothing prevents two scans of one project from running at once. ADR-0014 states that
  `TriggerScanUseCase` *"has no idempotency of its own"*, and `scans` has no uniqueness on
  `project_id`.

ADR-0033 decision 7 authorized Brief generation, a write, with the read verdict, and said in so
many words: *"This reason does not decide G70."* Its grounds are that ADR-0016 decision 3 gated
a write that costs real compute and can point an attack tool at a URL, *"with both conditions
together"*, and that: *"A scan trigger also mutates `Scan` state under consent that is itself
owner-gated (G49)."*

## Decision

### 1. Two routes in `scanning`, mounted under `/projects`

```
POST /projects/{project_id}/scans              → 202  {id, status}
GET  /projects/{project_id}/scans/{scan_id}    → 200  {id, status, failure_reason}
```

- A second router object in `scanning/adapters/inbound/api/router.py`, mounted with prefix
  `/projects` like the findings, risks and Briefs routers. The webhook keeps `/scanning`.
- No path ends in a slash, because a slash-terminated path does not survive the frontend's
  rewrite (ADR-0031's trailing-slash limitation).
- **202**, because the scan runs as an arq job: the webhook already answers 202 when it enqueues.
- The POST returns the scan's `id`, because a caller cannot poll a scan it cannot address, and its
  `status`, which is always `pending` on this path.
- Both response schemas are rule-10 schemas local to the adapter, and both key sets are pinned by
  equality assertions.

### 2. Authorization: a second verdict, `may_manage_project`

```python
class ProjectAccessPort(Protocol):
    async def may_read_project(self, *, project_id: str, user_id: str) -> bool: ...
    async def may_manage_project(self, *, project_id: str, user_id: str) -> bool: ...
```

- **The rule stays in `projects`**, as `domain/authorization.may_manage`: a membership exists
  **and** its role is `OWNER`. It agrees with `require_owner` by construction, as `may_read`
  agrees with `require_member`.
- **Why "manage" and not "write".** ADR-0033 decision 7 already lets a member write, by generating
  a Brief, on the read verdict. "Write" does not mean owner in this system, and M8.1's dismissal of
  a Risk would misuse the name.
- **What "manage" covers:** owner-class actions under ADR-0016 decision 3, those that cost real
  compute **and** can point an attack tool at a URL, both conditions together as ADR-0033
  decision 7 reads it. **Brief generation is not one**: it costs money and points nothing at
  anything.
- **One 404 for every denial.** `may_manage_project` is `False` for an absent project, a
  non-member and a member who is not an owner, and the route answers all three with one message
  built from the path id alone.
- **Rejected:** accepting the read verdict, for the reasons in the Context; and reading
  `ProjectMembershipRepositoryPort` or `Project.owner_id` from `scanning`, which is contract-legal
  and is the second copy of one rule that ADR-0022 decision 2 exists to prevent.
- **Consequences:**
  - ADR-0022 decision 2 is amended, 2026-09-19: one method per verdict, each a bool.
  - **G75**'s trigger fires (*"G70's port decision, if it adds an owner verdict"*). It is recorded
    and not acted on. Brief generation stays on the read verdict, and moving it is G75's decision,
    outside this issue.
  - **G17**: both routes answer 404 for both denials. They are the seventh and eighth such
    routes, against `projects`' eight that answer 403.

### 3. `TriggerScanUseCase` takes one flag and raises one exception

```python
async def execute(self, project_id: str, user_id: str, *, authorized: bool) -> Scan
```

- **One exception**, `ProjectAccessDenied` in `scanning/domain/exceptions.py`, on the pattern of
  `normalization`'s and `correlation`'s class of that name. `scanning`'s `InsufficientPermissions`
  loses its only users and is deleted. `projects`' class of the same name is a different class and
  stays.
- **The route's caller is `StartScanUseCase`**, which asks `may_manage_project` and passes the
  answer as `authorized`. Two callers each derive the flag: the route from the verdict, the webhook
  from the signature.
- **The webhook passes `authorized=True` and `user_id=project.owner_id`**, as ADR-0014's
  attribution decision already has it.
- **So `triggered_by` is still always an owner**, and `run_scan.py`'s comment stays true.

### 4. The status read

- `GetScanUseCase` asks `may_read_project` **before** it reads the repository. Members may read a
  scan's status.
- The scan's `project_id` must equal the path's. A scan of another project and an absent scan both
  raise `ScanNotFound`. Both denials answer 404.
- It returns `status` and `failure_reason`. `failure_reason` can carry a user id (*"No GitHub
  connection for user '…'"*), which is not a credential under rule 12.
- **`GitRepoCheckout` also redacts `target_dir`** from the failure message, beside the token. The
  rule-12 test drives a real failed clone and asserts that neither the token nor `verion-scan-`
  reaches the response.
- **That test covers two named patterns and nothing else.** `failure_reason` is redacted by a
  deny-list, and the structural fix is a fixed category per failure class. It is registered as
  **G89**, because it is a vocabulary on `Scan` and a schema decision that M8.3 owns when it
  renders the field.

### 5. The job is enqueued after the commit, by the layer that owns the transaction

Modeled on `platform/worker.py`'s normalization handoff, which enqueues after
`await session.commit()`, outside the transaction, because the use case cannot express "after the
commit" (ADR-0017's M4.4 amendment).

- **`platform/db.py` gains `after_commit(session, callback)`.** It registers a callback in
  `session.info`. `get_db_session` commits, then awaits the registered callbacks in order. On
  rollback they are discarded.
- **`AfterCommitJobQueue(inner, session)`**, in `scanning/adapters/outbound/queue/`, implements
  `JobQueuePort`. Its `enqueue_scan` registers `inner.enqueue_scan(scan_id)` through that hook.
- **`get_job_queue` depends on the session** and on a new `get_arq_pool`, and returns
  `AfterCommitJobQueue(ArqJobQueue(pool), session)`. The webhook shares it and gets the same fix.
- **With `465d036`'s function-scoped session**, the order is **commit, then enqueue, then the
  response**. A 202 means the row exists and the job is queued.
- **Failure modes.** A commit that raises runs no callback and answers 500. An enqueue that raises
  after the commit answers 500 and leaves a `PENDING` row that nothing re-drives (**G87**).

### 6. arq does not retry what the code says it retries

In arq 0.28.0 a pre-tool failure is not retried. Neither is any exception `RunScanUseCase` does not
name, including G51's `MultipleResultsFound`, which leaves the scan committed as `RUNNING`. The
behaviour is **G87**: the user starts another scan.

The same fact reaches normalization. A transient failure in `NormalizeScanUseCase` is left `failed`
on its first attempt, and the sweep does not select `failed`. That is **G15**, strengthened.

- **Amended the same day:** ADR-0016's Consequences, ADR-0017's Context and ADR-0021 decision 4.
- **Corrected in M8.8's code commit:** the nine src sites that assert a retry happens:
  - `run_scan.py`: the class docstring, the ordering comment before `normalization_runs.request`,
    and the except-block comment;
  - `platform/worker.py`: the comment above `use_case.execute` in `run_scan`, and the comment
    before `_enqueue_normalization`;
  - `normalize_scan.py`: the class docstring's transient branch, and the comment in its broad
    `except`;
  - `sweep_pending_normalizations.py`: "once arq exhausts `max_tries`";
  - normalization's `adapters/inbound/api/schemas.py`: "exhausts arq's retries".
- **Left as written:** five sentences that say what a retry, if one happened, would do or must
  be safe against:
  - the claim-race and re-claim rationale in `ports/normalization_run_repository.py`;
  - the refresh requirement in `ports/finding_repository.py`;
  - the upsert comment in the normalization repository;
  - `_enqueue_normalization`'s *"would hand arq a retry"* in `platform/worker.py`, which argues
    against raising there.

  A retry still happens on `CancelledError`, and the sweep re-enqueues, so the idempotency they
  demand is still needed.

### 7. Two scans of one project may run at once, and this issue does not stop it

Two POSTs, or a POST while a webhook scan runs, produce two concurrent scans. Registered as
**G88**. The cheap guard of returning the in-flight scan instead of minting one is **not taken**,
for three reasons:

- It needs a read of scans by project, which is M8.2's port.
- Placed in `TriggerScanUseCase`, it would change the webhook, where a new push must scan the new
  commit.
- Without a staleness rule, a scan stuck `PENDING` or `RUNNING` (G87) would block every later
  trigger.

It cannot be done honestly in about twenty lines.

### 8. FR-4's "on-push via GitHub Actions" is qualified

On-push is the signed push webhook (ADR-0014). No GitHub Actions adapter exists, and none is
scheduled. `PRODUCT_SPEC.md` FR-4 carries a dated line. §4's Journey 2, §8's *"Scans (manual +
CI-triggered)"* and §13's stack row *"GitHub API / GitHub Actions | Repo connection, CI-triggered
scans"* use the same wording, and are read under FR-4's qualification.

## Consequences

- **The route makes three latent pipeline defects user-reachable**, and each is registered rather
  than fixed here: **G87** (nothing re-drives a scan), **G88** (two scans at once), **G89** (the
  deny-list). **G15** is strengthened by the same arq fact, on the normalization side. The first two are triggered by **M9.2**, whose re-scan action is the user's
  re-trigger.
- **G51** becomes reachable from a button: a second connected repository makes the checkout's read
  raise `MultipleResultsFound`, which leaves the scan `RUNNING`. M8.7 carries the fix.
- **Rule 16.** The route, response-schema and authorization clauses fire. This ADR is the citation.
- **Local runs.** For a project with a connected GitHub repository and a repository scanner
  enabled (the default), a scan fails at `GitHubConnectionNotFound` when its owner has no GitHub
  connection. With no connected repository it fails earlier, at `ConnectedRepoNotFound`. Either
  way the GET will show it as `failed` with its reason. The demo
  seed script remains the laptop path (G70's note).
- **Out of scope:** re-scan (M9.2), scan history (M8.2), onboarding (M8.4), a CI-hook adapter (cut
  by decision 8), a concurrency migration, the frontend.

## Alternatives considered

- **Accept the read verdict with a stated reason.** Rejected in decision 2. It would let a
  non-owner's GitHub token clone the repository, and ADR-0033 decision 7 already declined to
  extend its reason to scans.
- **A route in `projects` calling `require_owner`, then a trigger port published by `scanning`.**
  Contract-legal, and it keeps the rule in `projects`. Rejected: the route would answer 403 like
  `projects`' own routes and join **G18**'s leak, and it adds a port where a verdict suffices.
- **Keep the two flags and map one bool onto both.** Rejected in decision 3. One exception becomes
  unreachable on the route's path, and if both stay reachable their messages tell the denials apart.
- **Enqueue in a `BackgroundTask`.** Rejected in decision 5. Since `465d036`, a background task
  would run after the commit, but Starlette runs it inside the response call, after the body is
  sent. A 202 would then not mean "queued", and an enqueue that failed would never reach the
  client.
- **A single-scan status read deferred to M8.2.** Rejected in decision 4. M8.2 comes late in M8's
  execution order, and a 202 with nothing to poll is a promise the UI cannot keep.
