# ADR-0024 — Where active-scanning consent lives, what it is bound to, and the bounds on the `activeScan` job

## Status

Accepted — 2026-08-27 (M5.4).

Written and reviewed **before any of M5.4's code existed**, the ordering ADR-0023's 2026-08-26
amendment adopted and ADR-0025 followed: a decision taken by the session that also writes its
tests is taken by whatever makes those tests pass.

## Context

`ROADMAP.md`'s M5.4 bullet reserves this number and names what it must decide. G24 records why
the decision could not be taken by the capture issue that found the gap: *"enabling `activeScan`
changes what production scans do, and that is not a capture issue's decision to take."* That
entry's `Deferral rationale:` also names the clause this ADR discharges — that an active scan
*"would also need its own decision about scan policy and duration bounds"*.

Three prior decisions bear directly and are **cited, not re-argued**: ADR-013 (the SSRF gate,
including its 2026-08-27 `## Amendments`), ADR-016 decision 3 (`ScannerConfig`'s shape, its
owner-gated write path, and its refusal to pre-approve a target at write time), and ADR-016
decision 4 (`target_kind`, and the `zap_target_url` wart it names).

**M5.4 makes the SAST↔DAST pair obtainable; it does not obtain one.** The capture, the CI test
and the measured step are M5.9. Nothing here decides what the active scan will *find* — the
probe's detection figures are deliberately absent, and belong to the issue that commits an
artifact making them checkable.

## Decision

### 1. Consent is three fields on `ScannerConfig`, not its own entity

```
scanner_configs
  ...
  active_scan_consent_target    String NULL   -- the zap_target_url consent was granted against
  active_scan_consent_granted_at DateTime(timezone=True) NULL
  active_scan_consent_granted_by String(36) NULL   -- users.id
```

Consent is present when all three are non-`NULL`; absent otherwise. There is no boolean. The
target value **is** the record, for the reason decision 3 gives, and a boolean beside it would be
a second source of truth for the same fact.

Not its own entity, and not a `consents` table. The one-row-per-project shape
(`uq_scanner_configs_project_id`) already gives consent the cardinality it needs — one grant per
project, replaced rather than accumulated — and a separate entity would need its own repository,
its own port and its own read path to express a fact that is already keyed by exactly the same
column. ADR-016 decision 3 chose explicit columns over a normalized `(project_id, tool)` table on
missing-row ambiguity; the same argument applies here and more strongly, because *"consent row
absent"* and *"consent withdrawn"* must mean the same thing and with three nullable columns they
structurally do.

**The G2 ruling, which this ADR is the place for.** `ScannerConfig`'s docstring sets the exit
condition for `zap_target_url` as *"migrate to a normalized (project_id, tool) table when a SECOND
tool needs tool-specific settings"*, and the M5.4 reconnaissance established that `SECOND` is
ambiguous between counting tools and counting settings. **It counts tools. This change does not
fire the trigger.** ZAP remains the only tool with tool-specific settings; consent is a second
setting for that same first tool. The normalized shape exists to say *which tool* a setting
belongs to, and with one tool there is nothing to disambiguate — normalizing now would be the
pre-normalizing-for-a-hypothetical ADR-016 decision 3 already rejected, with one more column as
the only new argument for it. ADR-016 decision 3's parenthetical is consistent with this reading
and does not settle it: its worked example is a per-project Semgrep ruleset, which is a *second
tool* acquiring settings.

**What this costs, stated rather than left to be discovered: G2's blast radius widens.** That
entry is about a per-integration *value* inside generic dispatch, and there are now two of them
rather than one. Decision 4 is what keeps the widening out of `RunScanUseCase.execute`'s
signature, so the widening is in meaning rather than in shape — but a future `ScannerTargetKind.URL`
scanner would now be silently handed ZAP's target *and* ZAP's consent. G2's `Confirmed:` gains
this issue.

### 2. The owner grants it. Withdrawal is deliberately not symmetric

Granting goes through the existing owner-gated write path — `UpdateScannerConfigUseCase`,
`require_owner(membership)`, `PUT /projects/{project_id}/scanner-config`. ADR-016 decision 3
owner-gates that path because enabling a scanner *"can point an attack tool at a URL"*; consenting
to an active scan is that argument's stronger form and does not need a new one.

**Withdrawal is strictly easier than granting, and that asymmetry is the decision.** Consent is
withdrawn by an explicit owner act, and *also* implicitly whenever the target changes (decision 3).
Nothing else in `ScannerConfig` behaves this way. The reason is that the two errors are not
comparable: accidentally withdrawing consent produces a scan that runs passively, which is the
system's current behaviour and harms nothing; accidentally retaining it produces real attack
traffic against a host nobody agreed to attack. Where a design has to be wrong, it is wrong in the
direction that under-authorises — the same principle ADR-0019 decision 3 states for identity,
*"prefer the failure that under-counts over the failure that fabricates events"*.

Consent is not granted by any other actor, not inherited from project membership, and not
defaultable. A project with no `scanner_configs` row has no consent, which is the same answer
ADR-016 decision 3's default gives for ZAP itself being off.

### 3. Consent is bound to the project and **voided by** the target it was granted against

This is the decision with the most ways to get it wrong, and it is the one the brief for this
issue nominated as hardest.

**The rule.** `active_scan_consent_target` stores the `zap_target_url` in force when consent was
granted. At scan time, consent is in force **only if** `active_scan_consent_target` equals the
current `zap_target_url`. When they differ, consent is absent and the scan is passive, with no
error — a changed target is a configuration act, not a failure.

**Consent is bound to the project; the stored target is used only to invalidate, never to
approve.** That direction is the whole content of this decision. A record that *approved* a host
would be the thing `validate_zap_target_url`'s docstring refuses to create — that function
declines to reject private targets at write time precisely so the stored URL does not *"look
pre-approved"*, since *"DNS can rebind between configuring a target and scanning it"*. **This ADR
extends that reasoning rather than departing from it.** A stored consent target says nothing about
where the target resolves and pre-approves no address; both ADR-013 gates still run at scan time
against the resolved IP, exactly as they do without consent. What the stored value carries is a
different claim entirely — not *"this host is safe"* but *"the thing the owner agreed to attack is
still the thing configured"*.

The failure it closes is concrete: consent granted for a staging host, target later repointed at
production, and attack traffic arriving at a host nobody consented to. One row, one use case, one
`PUT` — the two values are mutable together today and nothing would notice.

**What it does not close, and this is a real residue rather than a hedge.** String equality is a
weaker relation than host identity. `https://a.example` and `https://a.example/` are different
strings and the same target, so a cosmetic edit voids consent and the owner re-grants. That is the
under-authorising direction of decision 2, taken knowingly: a false void costs a re-grant, a false
retain costs attack traffic. Equality is on the stored value verbatim and is deliberately not
normalized, because a normalizer is a second place for the two sides to disagree.

### 4. Consent is read at the `_build_plan_yaml` call site, inside `ZapAdapter.run()`

`_build_plan_yaml` is a module-level function in
`scanning/adapters/outbound/scanners/zap_adapter.py` taking one parameter, `target: str`. It gains
a second, and its sole call site — inside `run()`, after both ADR-013 gates and before
`asyncio.create_subprocess_exec` — is where consent is read.

**Why there.** It is the only one of the three candidate placements that is downstream of both
gates by construction. Five statements separate the second gate from the spawn and none reaches
the network or starts a process, so nothing can be inserted between "the target passed the gates"
and "the plan is written" without being visible as a new statement in that span.

**`ZapAdapter.__init__`, beside `allow_private_targets`, is structurally impossible** and not
merely undesirable. `platform/worker.py`'s `on_startup` builds `scanners: dict[ScannerTool,
ScannerPort]` once and shares it across every job — its own comment says *"Stateless, safe to build
once and share across jobs"*. One `ZapAdapter` instance serves every project, so a per-project value
cannot live on it. A constructor flag there would be a per-project fact stored per-process.

**`RunScanUseCase` is legal and still wrong, and that is the one worth writing down.** It already
reads `ScannerConfig`, so a consent check there would type-check, pass review and work. It is wrong
for two reasons that compound. First, it decides scan behaviour *upstream* of the gates: a consent
check in `execute` sits before `_run_scanner`, before `run()`, and therefore before either gate
runs, so the ordering property decision 6 relies on would no longer be structural — it would hold
only as long as nobody moved a line. Second, it puts per-integration behaviour inside generic
dispatch, which is what rule 4 forbids and what G2 already records as debt in that exact function.

**How the value arrives, without a second `zap_target_url`.** `RunScanUseCase` builds one frozen
`ScanOptions` value from `ScannerConfig` and passes it to every selected scanner through a second
parameter on `ScannerPort.run`; each adapter reads the fields it understands and Semgrep and Trivy
read none. This is `target_kind`'s pattern from ADR-016 decision 4 — the *shape* of dispatch stays
generic and carries no `tool == "zap"` branch — applied to a value rather than to routing. That
decision's code block shows `run` taking `target` alone, so it is superseded here and says so in
that ADR's 2026-08-27 `## Amendments`. It is
deliberately not a third positional parameter on `execute` beside `zap_target_url`: that would
widen G2 in signature as well as in meaning, and G2's `Blocks-if-unresolved:` is specifically about
that signature.

### 5. The `activeScan` job, its bounds, and what it is permitted to do

Inserted after `passiveScan-wait` and before `report`, and **only when consent is in force**:

```yaml
- type: activeScan
  parameters:
    context: verion-target
    maxRuleDurationInMins: 1
    maxScanDurationInMins: 3
    threadPerHost: 2
```

**The operative outer bound is not in this plan, and stating the caps without it would be
decorative.** `ZapAdapter.__init__` declares `timeout_seconds: float = 300.0` and
`platform/worker.py`'s `on_startup` constructs `ZapAdapter(dns_resolver=SystemDnsResolver())`
with no override, so production runs at 300 s; `run()`'s `asyncio.wait_for` then kills the
process and the container and raises `ScannerExecutionFailed`. That fires **as a tool failure,
not as a bounded completion** — a scan that hits it is recorded the same way an unreachable
target is. The plan's own ceilings already sum past it before this job is added: `spider`
`maxDuration: 2` plus `passiveScan-wait` `maxDuration: 5` is 7 minutes against 300 s. **So M5.4
picks durations and a `timeout_seconds` satisfying two inequalities:**

- the plan's own durations must sum below the adapter's `timeout_seconds`, or the caps do not
  bind;
- `checkout + max(semgrep, trivy, zap)` must stay below `WorkerSettings.job_timeout` — `max`
  rather than a sum, because ADR-016 decision 1 runs the enabled scanners concurrently.

**The block above does not satisfy the first one, and saying so is the point rather than an
admission:** 2 + 5 + 3 is 10 minutes against 300 s. The violation is not this job's — the
committed plan already breaches it at 7 minutes — but this job widens it, so M5.4 either lowers
the plan's durations or raises the adapter's timeout, bounded above by the second inequality.
This ADR fixes the shape of the constraint and leaves the arithmetic to the issue that can
measure a real active run against it.

**`job_timeout` is not raised to make room**, and the reason is not the test that guards it:
`platform/settings.py`'s comment on `normalization_sweep_stale_after_seconds` records that
raising `job_timeout` past that threshold makes the reconciliation sweep *"start continuously
re-enqueuing live work"*. The caps in the block are inner ceilings under both inequalities, and
their job is to stop one rule or one scan consuming the whole budget, not to terminate the
container. The probe's 62 s is far under every bound, which is why nothing has met this yet.

- **Scope is the context, and the context is a subtree rather than one URL.** `verion-target`'s
  `urls` is `[target]`, which ZAP reads as a top-level URL — everything beneath it is in context —
  and the committed plan sets no `includePaths` or `excludePaths`. So the bound is one host's
  subtree, and the probe's 86 distinct paths are what that looks like rather than a breach of it.
  Narrowing it with path restrictions is available and deliberately not taken: no measurement
  exists of what an active scan finds under one.
- **`maxScanDurationInMins: 3`** caps the job. **`maxRuleDurationInMins: 1`** caps any single rule,
  so one pathological rule cannot consume the whole budget. **`threadPerHost: 2`** bounds
  concurrent load on a target that may be somebody's staging environment.
- **`policy` is left at ZAP's default, and that is a decision rather than an omission.** The
  default policy is what the probe measured, so it is the only configuration this project has any
  evidence about; naming a narrower policy would substitute an unmeasured configuration for a
  measured one inside the ADR whose subject is what consent authorises. The cost is that the
  default includes rules which execute real commands on the target — see the table below.
- **What an active scan is permitted to do: send attack traffic inside the consented target's
  context**, under the caps above and the adapter timeout. There is no allow-list of rule classes;
  the bound is the context and the clock. **Whether ZAP leaves that context by following a
  redirect is not established here** — nothing in this repository has measured it, and the probe
  cannot settle it, since its figures come from the target's own log and that log by construction
  records only requests which reached that host.

**Neither the parameter spellings above nor the containment properties this section claims are
verified against the pinned image from this repository**, because no probe artifact is committed:
the names are taken from ZAP's Automation Framework, and the context bound is read off the plan's
structure rather than off an observed active run. Verifying both is part of M5.9, and it is
registered with the rest of that irreproducibility as **G42**.

### 6. Consent does not become a second path around ADR-013

ADR-013's 2026-08-27 `## Amendments` restates the property in the wording to cite: *"both gates run
before the target is contacted and before any subprocess is spawned, in that order"*. Both run
against a consented target exactly as against any other, `allow_private_targets` stays test-only,
and a consented target that resolves to a private address is still refused.

The two govern different things: **ADR-013 decides which targets may be reached; consent decides
what may be done to a target it has already admitted.** Consent is read strictly downstream of both
gates (decision 4), so it cannot widen what they admit — it can only narrow what happens after
them. `ROADMAP.md`'s M5.4 bullet already states this as acceptance criteria, including the test
whose subject is the ordering; it is cited here rather than re-argued.

## What consent authorises

~~**These figures are not re-derivable from this repository.** No probe artifact is committed and
none is tracked: the access log, the ZAP report and the probe's working tree do not exist here.
They are one operator's hand-run, recorded because a decision about what consent authorises has to
say what it authorises — not because anything in the tree can check them.~~ — **STRUCK 2026-09-08
(M5.9): FALSIFIED.** M5.9 commits a ZAP report and the target's own Werkzeug access log under
`tests/integration/fixtures/active_scan/`, so the predicate column below can be run. **The table
that follows is the probe's and is superseded — read the restated one in `## Amendments`.** Struck
here rather than only amended because this paragraph is ninety lines above that section, and a
reader of the body who never reaches it would take the opposite of what holds. Registered as
**G42**, whose first half this discharges and whose second half no capture can.

Each figure is stated as the predicate that produced it, per G40's rule that *"a figure a reader
cannot re-run has the defect this entry exists to record"*. One run, one small Flask app; the
source is that app's own Werkzeug access log in every row but the first.

| Figure | Predicate |
|---|---|
| 62 s | Wall-clock of one `docker run` of the ZAP image with an `activeScan` job added to the committed plan shape — not with decision 5's parameters, which no run in this repository has executed. Timed by the operator on one developer machine; 47 s of it is attributed to the `activeScan` job. |
| 391 requests | Log lines carrying a well-formed request line, between the run's first and last request, excluding the 7 lines Werkzeug rejected. |
| 86 paths | Distinct values of the request-line path, truncated at the first `?`, over those 391. |
| 200×252, 404×132, 405×7 | Status-code counts over those same 391, inside the scan window. The whole-file 200 count is 257; the extra five are two pre-scan smoke requests and three hand replays, outside the window. |
| 7 malformed | Log lines Werkzeug rejected with a bad request version — TLS ClientHellos arriving at a plaintext port. Counted separately; they are the 400s and not an additional failure class. |
| 0 | Log lines with a 5xx status. A property of this target, not a guarantee about any target. |

Among those 86 paths, by family:

- **Cloud-metadata SSRF probes, six providers** — `/latest/meta-data/` (AWS),
  `/computeMetadata/v1/` (GCP), `/metadata/instance` (Azure), `/opc/v1/instance/` and
  `/opc/v2/instance/` (Oracle), `/metadata/v1` (DigitalOcean), `/openstack/latest/meta_data.json`
  (OpenStack).
- **Secret-file probes** — `/.ssh/id_rsa`, `/.ssh/id_dsa`, `/.env`, `/.git/config`, `/key.pem`,
  `/privatekey.key`, `/server.key`, `/sftp-config.json`, `/WS_FTP.INI`.
- **Real shell command execution on the target host.** The default policy's injection rules
  executed `sleep` on the target twice. This is the row that makes consent necessary rather than
  advisable, and it is why `PRODUCT_SPEC.md` §11.1's threat-model-first principle applies to the
  act of granting consent and not only to the code that acts on it.

Nothing was persisted on the target. That is a property of this target.

## Consequences

**A consent grant leaves no history and no log, and `PRODUCT_SPEC.md` §11.5 does not reach it.**
That principle requires an actor and a timestamp for *"every risk state change (opened, dismissed,
resolved)"*; consenting to attack a host is not a risk state change, so the strongest auditability
principle this project has says nothing about the strongest authorisation act it performs.
Decision 1 records the current grant's actor and timestamp, which is the cheap half. What is
missing is the history — `updated_at` is one timestamp for the whole row, so a consent grant and a
scanner toggle are indistinguishable in it, a withdrawal overwrites the grant it replaces, and
`src/` contains zero `logging.getLogger` calls, so nothing is written anywhere else either.
Registered as **G43**.

**M5.4 ships a scan plan whose output nothing in this repository has seen**, until M5.9 captures
one. G31 and G39 both fire at M5.4 for unrelated reasons and are cited in that issue's bullets.

**The passive path is unchanged.** A project without consent gets exactly the plan
`_build_plan_yaml` builds today, so the committed corpus, ADR-0026's derived profile and every
existing ZAP test describe the same configuration after this change as before it.

## Amendments

The first two entries **qualify an incomplete decision**; neither strikes a falsified one. Decision
2 is accurate about everything it says and silent about two things the implementation had to
settle. **The third is a strike**, and it is marked as one because the two above it declare the
opposite treatment.

- **2026-08-27 (M5.4, commit 1): decision 2 is incomplete as to the request's shape. The consent
  field is tri-state — grant, withdraw, or omitted — and the omitted state is what makes decision
  3 live.** A two-state flag would make that decision unreachable: if every write restates
  consent, `active_scan_consent_target` always equals the `zap_target_url` written beside it and
  the comparison can never be false. Omitting it is what lets an owner repoint the target without
  restating consent, which is the case decision 3 exists for.
- **2026-08-27 (M5.4, commit 1): decision 2 calls the implicit effect of a target change a
  *withdrawal*, and the shipped behaviour is a *suspension*. Measured, not predicted** — editing
  the target to a trailing slash and back restores the grant, with the original `granted_at` and
  `granted_by`. The behaviour is not changed and the word is: `active_scan_consent_in_force`
  still requires equality with a target the owner did grant against, so no path reaches consent
  against an unconsented target. What "withdrawal" overstated is permanence. One consequence
  follows, and it is **an instance of G43 rather than a new gap**: `granted_at` now spans an
  interval in which consent was not in force, and nothing records that interval — which is the
  missing grant history that entry already carries.
- **2026-08-27 (M5.4, commit 2): `## Consequences`' paragraph beginning *"The passive path is
  unchanged."* is STRUCK. It is false in both halves.** Implementing decision 5's first
  inequality forced `passiveScan-wait`'s ceiling from 5 minutes to 2, unconditionally — so a
  project without consent does **not** get *"exactly the plan `_build_plan_yaml` builds today"*,
  and the committed corpus, ADR-0026's derived profile and the existing ZAP tests do **not**
  *"describe the same configuration after this change as before it"*: they were captured under
  the 5-minute ceiling and production now runs 2 on both branches. Struck rather than qualified,
  because no scoping rescues either clause — the paragraph asserted an invariance the
  implementation had to break to satisfy this ADR's own arithmetic. **This is the second way G39
  fired at this commit**, the first being the `activeScan` job itself; that entry's Note records
  both, and no new entry is opened, since a profile that has stopped describing production is
  exactly what G39 already is.

- **2026-09-08 (M5.9): `## What consent authorises` is RE-DERIVED against a committed capture,
  and every row is RESTATED rather than confirmed. It also carries a STRIKE, and the two are
  separate acts.** That section opened *"These figures are not re-derivable from this repository"*;
  **that sentence is FALSIFIED and is struck at its own site**, because a falsified claim ninety
  lines above the amendment that falsifies it is read by everyone who does not scroll. **That makes
  two strikes in this section**, so the introduction above — *"The first two entries qualify an
  incomplete decision … The third is a strike"* — enumerates the first three entries and is no
  longer a description of the whole. Left as written: it is accurate about what it enumerates, and
  editing it would restate an amendment history rather than record one. The figures now are
  re-derivable —
  `tests/integration/fixtures/active_scan/app_access.log` is the target's own Werkzeug log, which
  is the source the predicate column names for every row but the first. The figures below come
  from **this ADR's own plan**, run through the shipped `ZapAdapter` at its pinned digest, which
  the 2026-08-25 probe was not: it ran the committed plan shape with an `activeScan` job added and
  **not** decision 5's parameters, which is why restatement was the expected outcome.

  | Figure | Probe (2026-08-25) | This ADR's plan (2026-09-08) |
  |---|---|---|
  | wall clock | 62 s, of which 47 s the `activeScan` job | **65.5 s**, timed around `ZapAdapter.run()`; the log spans 60.0 s first request to last. The job is **not** separately attributed — the report carries no per-job timing, so the probe's 47 s has no counterpart here and is not restated. |
  | requests | 391 | **390** |
  | distinct paths | 86 | **86** |
  | status codes | 200×252, 404×132, 405×7 | **200×253, 404×130, 405×7** |
  | malformed | 7 | **7** |
  | 5xx | 0 | **0** |

  **The shape holds and the details moved, which is the honest reading of a second run rather than
  a vindication of the first.** Path count is identical; request count differs by one and the
  200/404 split by one either way — this run's own `/.zap<nonce>` probe path differs per run, and
  the counts are a single sample, not a range. **Every family in the list below reproduced**,
  including all six cloud-metadata providers, every named secret-file probe, and real shell
  execution on the target: `90036` fired at confidence 3 with an `attack` of
  `{{__import__("subprocess").check_output("sleep 15", shell=True)}}`. **Nothing persisted and
  nothing returned 5xx** — still a property of this target, not a guarantee.

  **What this does NOT verify, and it is the half G42 was opened for:** that ZAP *honoured*
  `maxScanDurationInMins`, `maxRuleDurationInMins` or `threadPerHost`. A completed run proves the
  plan was accepted, not that an unrecognised parameter would have been rejected — and
  `ZapAdapter.run` binds `_, stderr = await process.communicate()` and surfaces stderr only on a
  non-zero exit, so ZAP's console output is discarded on every successful run. **No capture taken
  through the shipped adapter as it stands can close that**, which is recorded in G42 and in
  ADR-0027's `## Amendments`.

## Alternatives considered

**Consent as a boolean on `ScannerConfig`, with no stored target.** Rejected — decision 3. It is
the shape that produces the staging-to-production carry-over, and nothing about it looks wrong on
the page.

**Consent as its own entity with an append-only grant history.** Rejected for M5.4, and it is the
alternative that would have closed G43 outright. It needs a repository, a port, a read surface and
a retention answer, for a project that has never granted consent once. Recorded rather than
dismissed: it is the shape G43 takes if G43 is taken.

**Binding consent to the resolved IP rather than to the target string.** Rejected on ADR-013's own
ground: the resolved IP is exactly the value that can change between configuring and scanning, so
storing one would create the pre-approval `validate_zap_target_url` refuses to create, in the field
whose whole purpose is to be compared at scan time.

**A consent check in `RunScanUseCase`.** Rejected — decision 4. Legal, workable, and it dissolves
the one structural property this design has.

**Naming a narrower active-scan policy.** Rejected — decision 5. It would replace the only
configuration this project has measured with one it has not.
