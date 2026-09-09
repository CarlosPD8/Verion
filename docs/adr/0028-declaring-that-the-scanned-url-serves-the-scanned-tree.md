# ADR-0028 — Declaring that the scanned URL serves the scanned tree

## Status

Accepted — M5.5. Written before any implementation code, so that the field list, the voiding
rule and the port shape are chosen by somebody who is not also writing the tests that would
make them pass. That ordering is ADR-0023's amendment section 3 applied a second time.

**Size:** a ceiling of **22,000 bytes** was declared before writing, on ADR-0027's precedent.
The decision text measured 20,979 bytes at acceptance, inside it.

*(Updated 2026-09-09, M5.5 commit 2: **the file is now past that ceiling, and the overrun is
disclosed rather than trimmed away** — which is the whole of what ADR-0027's precedent consists
of, and invoking that precedent while omitting its disclosure would have been the emptier half
of it. The `## Amendments` section is the entire difference; the decision text is unchanged at
its accepted size. The ceiling governed the decision text at acceptance, and amendments accrue
afterwards by design, so trimming a decision to make room for its own amendments would be the
wrong direction.*

*The current byte count is deliberately **not** written here, and two attempts at writing it in
this commit are why. Each measurement was falsified by the paragraph that recorded it — 26,282,
then 29,020, then 29,218 — because a figure describing the size of the file it sits in changes
the file. The second attempt tried to converge by keeping the replacement digits the same
length, and failed on the sentence explaining the trick. So the figure goes in the commit
message, which is what this ADR's own Status said before the disclosure was added, and the
disclosure keeps the part that is stable: that the ceiling was passed, and by what.)*

## Context

ADR-016 decision 1 makes cross-tool correlation well-founded by construction: one job, one
checkout, every repo-based scanner against the same tree. **G27** records that this covers two
tools of three. ZAP is dispatched by `ScannerPort.target_kind` to a URL and never reads the
checkout, so nothing in the system asserts that the URL it crawled serves the tree Semgrep and
Trivy read. ADR-0023 Decision C defers the SAST↔DAST derivation behind two triggers, and G27 is
the one it calls "the less visible of the two", because a group produced from two different
systems looks exactly like a group produced from one.

G24, the other trigger, was resolved at M5.9. So the pair now exists and correlating it would
still be unfounded, which is the situation G27's own assignment note predicted in as many words.

## Decision

### 0. The scope change, recorded as a decision rather than inherited

M5.5's roadmap block stated its acceptance criterion as *"a derived SAST↔DAST group is not
produced when the declaration is absent"*, until this commit struck it. **That criterion is not
satisfiable inside M5.5, and the ground is structural rather than a property of the fixtures.**
`correlation/domain/match_key.py` declares `SIGNAL_FIELDS = ("package", "url")`. `mappers/trivy.py`
populates `package` and never `url`; `mappers/zap.py` populates `url` and never `package`;
`mappers/semgrep.py` populates neither, constructing `Location(file_path=…, start_line=…,
end_line=…)`. Two findings group only on equality of every key field, so **no pair of tools can
co-group by any route that exists today** — Semgrep against either other tool by the third clause,
and Trivy against ZAP by the first two, which is the half a compressed version of this argument
drops.

Measured through the real mappers and the shipped matcher over **the three files
`semgrep_scan.json`, `trivy_scan.json` and `zap_scan.json`** — named rather than cited as their
directory, which also holds three `*_synthetic_edges.json` files and yields 47 findings in 20
groups if a reader re-derives over the folder, the staleness class ADR-0027 decision 1 and
**G39** both name: **34 findings in 8 groups, zero of them spanning two tools.**
`tests/integration/fixtures/active_scan/`'s `zap_active_scan.json` gives 16 findings in 5 groups.
**That second corpus contributes its counts and NOT a second cross-tool zero**, because it holds
one tool's output and could not produce a cross-tool group whatever the mappers did; reading it as
a confirming measurement would over-count the evidence by one. A conditioning gate written now
would be green whether it is wired in or not.

**A dating fact, which explains the criterion without blaming it.** G27's assignment — the note
that set that criterion — is dated **2026-08-25**. ADR-0023's amendment freezing the key's three
fields is dated **2026-08-26**, and M5.8 implemented the matcher the same day. The criterion was
written the day before the code it constrains, against an imagined correlation path rather than
the one that exists. This is the ordinary way a forward-looking criterion goes stale, and the
repair is to move it to the issue that can satisfy it.

**Decided: M5.5 ships the declaration and `projects`' own read surface. The conditioning becomes
an acceptance criterion of M5.6. G27 does not close here** — it is split across the two issues,
not reassigned; see the register.

### 1. Where the declaration lives — a new entity, because the claim is about a pair

A new `ServingDeclaration` entity in `projects/domain/`, its own table, one row per project on
`ScannerConfigModel`'s `UniqueConstraint(project_id, …)` precedent, holding both sides **by
value**:

`id`, `project_id`, `declared_target_url`, `declared_repo_url`, `declared_default_branch`,
`declared_at`, `declared_by`.

**Not a column on `ScannerConfig`, and not one on `ConnectedRepo`, for the same reason stated
once.** The URL side lives on `ScannerConfig.zap_target_url` and the tree side on
`ConnectedRepo.url` / `ConnectedRepo.default_branch`. A column on either is a claim about the
other, so the row that holds the claim is not the row somebody edits when the claim stops being
true. Put it on `ScannerConfig` and repointing the project at a different repository leaves a
declaration standing that names a tree no longer connected; put it on `ConnectedRepo` and editing
the target URL does the same in the other direction. **Both sides have to be stored by value
anyway** for decision 2's rule to have anything to compare — the same reason M5.4 stores
`active_scan_consent_target` rather than a boolean, ADR-0024 decision 1 — and a by-value copy of
another entity's field is not naturally a column on this one.

**This does not take `zap_target_url`'s named exit, and it does not add to that debt either.**
`ScannerConfig`'s docstring calls that field *"honest debt: tool-specific configuration in a
generic entity"* with a concrete exit: *"migrate to a normalized (project_id, tool) table when a
SECOND tool needs tool-specific settings."* This declaration does not fire that trigger, because
it is **not tool-specific at all** — it is a claim about a project's deployment topology that
would read identically if ZAP were replaced by another DAST scanner tomorrow. Filing it on
`ScannerConfig` would both enlarge the debt and mis-describe it: the exit condition would stop
matching what the table holds, so the one thing keeping that debt honest — a trigger somebody can
check — would quietly stop applying. **The exit stays unfired**, and that reading is ADR-0024's
rather than re-derived here: its G2 ruling settled that the trigger counts **tools**, saying *"ZAP
remains the only tool with tool-specific settings; consent is a second setting for that same first
tool"*. So `zap_target_url` is **not** the only tool-specific field on that entity — the three
consent columns are three more — and the trigger is unfired because all four serve one tool.

**The in-force rule is a pure function in `projects/domain/`, not a property on the entity.**
`ScannerConfig.active_scan_consent_in_force` can be a property because both values it compares
live on the same entity. Here they do not: the rule compares one entity against two others, so it
takes them as arguments. `projects/domain/authorization.py`'s `may_read` is the precedent —
`ProjectAccessPort`'s docstring names it as the place `projects` keeps a rule whose verdict
crosses a boundary — and this is the second instance of that shape rather than a new one.

### 2. The voiding rule, and the asymmetry it cannot close

**The rule.** A declaration is in force iff a row exists for the project and all three stored
values equal their live counterparts: `declared_target_url` against `ScannerConfig.zap_target_url`,
`declared_repo_url` against `ConnectedRepo.url`, `declared_default_branch` against
`ConnectedRepo.default_branch`. Equality is **verbatim on the stored strings, deliberately not
normalized**, copying ADR-0024 decision 3 with its ground: a normalizer is a second place for the
two sides to disagree. The residue is copied too — a cosmetic edit voids the declaration and the
owner re-declares — and it is accepted for the same reason.

**The asymmetry.** `ConnectedRepo` carries a URL and a branch **name** and no commit. **G25** is
open: nothing on `Scan` or anywhere else records which tree a scan observed. So the declaration
can be voided by a reconfiguration and **cannot detect that either side's content changed**.

**Decided: the declaration binds only to what is observable, and this ADR says so rather than
leaving it to be discovered. It does not wait on G25.** Two grounds, and the second is the one
that decides it:

- **Waiting puts M5.5 behind M9.1.** G25's own `Deferral rationale:` says nothing should read a
  scan's commit until M9.1 decides its diffing semantics, and names four changes across two
  modules as the fix — `Scan` gains a field, the migration, `RepoCheckoutPort.checkout` returning
  or accepting a revision, and `TriggerScanUseCase` deciding whether a caller may pin.
- **G25 would not close the asymmetry.** A commit on `Scan` records which tree the **scanner**
  read. It records nothing about which revision the **deployment** is running, and nothing in this
  system observes that today: no port fetches a deployed revision. **The `Server` banner is not a
  counter-example, and the scope of its refusal has to be stated precisely or this argument
  overreaches.** ADR-0023 Decision A refused lifting it into `Location.package` /
  `Location.installed_version` as a **correlation signal**, and its closing paragraph deliberately
  leaves the other use open — *"If it ever needs structure, its home is **Security Context** —
  FR-3 asks for 'deployment signals', and a live server's self-reported stack is a fact about the
  deployment rather than the location of a finding."* So a deployment-identity read is **available
  and unbuilt**, not refused. What is refused is the shortcut of comparing it field-to-field
  against a manifest, and Decision A's perverse property still bounds what any such read could be
  worth: the banner exists only while the target still carries the vulnerability the signal is
  derived from. So with G25 closed the pair is still half
  observed: the tree side versioned at scan time, the URL side unversioned entirely. **A
  declaration that waited for G25 would be waiting for something that does not remove the
  asymmetry it is waiting on.**

**What a present declaration therefore does NOT assert.** Stated as a list because each line is a
separate thing a reader might otherwise assume:

- Not that the URL serves the tree **now**. It records that a person asserted it at `declared_at`
  against three named values, and that those three values have not been edited since.
- Not that the deployment runs any particular revision of the repository.
- Not that the deployment is current with the branch tip, or with anything else.
- Not that the code Semgrep read is the code the URL executes.
- **It voids on RECONFIGURATION and never on DRIFT.** Editing the target URL, the repository URL
  or the branch name voids it. Deploying different code to the same URL does not, and nothing
  anywhere would notice. → **G47**.

### 3. Who may declare it — owner-gated, as a floor rather than as a match

**Decided: the project owner, the same gate M5.4's consent uses on ADR-016 decision 3's
precedent.** And this is chosen as the narrower of two available answers, not because the two
claims have the same author.

- `projects/domain/project.py` declares exactly `Role.OWNER` and `Role.MEMBER`. There is no
  vocabulary for *"whoever knows the deployment"*, and inventing a third role for one field would
  be a role-model change made in passing, inside an issue whose subject is a declaration.
- Of the two answers the model can express, **owner is the one that cannot authorize somebody who
  should not declare**. `MEMBER` could. Where the vocabulary is too coarse for the distinction,
  taking the narrower side is the direction ADR-0024 decision 1's defaulting argument already
  chose for consent.

**What this does not implement, said plainly.** M5.4's roadmap bullet asserts that these are *"two
different claims, made by two different people, about two different things"*. Today one person
makes both. **The separation of the claims is preserved in full** — two records, two voiding
rules, two acceptance criteria, and neither implies the other, which is what that bullet's
"one field would make each imply the other" was protecting. **The separation of the declarers is
not**, and the bullet's premise is therefore documentary rather than enforced. → **G49**.

### 4. How the verdict reaches `correlation` — a new port, shipped with its consumer

**Decided: a new `ServingDeclarationPort` in `projects/ports/`, one method,
`async def url_serves_scanned_tree(*, project_id: str) -> bool`.** A verdict crosses; `projects`
keeps the rule (rule 3). **Async by rule 7**, which is not decoration here: evaluating the verdict
reads the declaration row plus `ScannerConfig` and `ConnectedRepo`, so this is an I/O-bound port.
`ProjectAccessPort.may_read_project` is `async def` and so is every method on every existing
`projects/ports/*.py` file. *(This clause read "all seven" when the decision was accepted,
which was true then and is dated rather than wrong: commit 1 added
`serving_declaration_repository.py` as the eighth. Corrected to a form that does not carry a
count, since the property is what the sentence is for.)*

**Not a method on `ProjectAccessPort`.** That port's docstring argues at length for having exactly
one method, because a second gives a consumer a vocabulary for *which* reason a call failed and
rebuilds the project-existence leak on the consumer's side. Hanging an unrelated subject off it
would break the design it states, for a saving of one file.

**Not a method on `ScannerConfigRepositoryPort`.** That is a persistence port returning entities.
A verdict method on it would sit beside `get_by_project_id`, which hands the consumer the whole
entity anyway — so the copy of the rule that rule 3 forbids would be one call away, which is the
condition `ProjectAccessPort` exists to remove rather than to document.

**This is `ProjectAccessPort`'s shape and deliberately not M5.4's, and the difference is worth
stating because M5.4 is the more recent precedent and the wrong one here.**
`ScannerConfigRepositoryPort.get_by_project_id` hands `RunScanUseCase` the entire `ScannerConfig`,
all three consent columns included, and the use case evaluates `active_scan_consent_in_force`
itself; the verdict-only crossing happens **one boundary later**, at `ScanOptions`, whose docstring
is where the "carries verdicts, never the state a verdict was computed from" rule is written. That
is defensible there, because `RunScanUseCase` needs `enabled_tools` and `zap_target_url` from the
same read and would hold the entity regardless. It is the wrong precedent here: `correlation`
needs the verdict and nothing else, and giving it the entity would put a copy of this module's
rule one attribute access away in a module that must not hold one.

**Reachability, from the contracts rather than from memory.** `cross-module-correlation` forbids
`verion.modules.projects.domain` and `verion.modules.projects.adapters` and does **not** forbid
`verion.modules.projects.ports`. `layers-correlation` orders `adapters → application → ports →
domain`, so this port is read from `correlation/application/` and **never** from
`correlation/domain/`, where `group_by_match_key` and `matches` live. Both constraints point at
the same site: the use case, beside the `ProjectAccessPort` call already there.

**The port ships at M5.6, with its consumer, not in M5.5.** A port with no caller has no `di.py`
factory that anything depends on and no site where an adapter meets a port-annotated return type —
which is precisely the bound ADR-015 states on what `mypy --strict` verifies. It would be a file
the strict gate reports green on without having checked the thing the file exists for. **M5.5's
read surface is `projects`' own**: the repository port, and the module's API, which returns a
dedicated response schema and never the entity (rule 10). → **G48**.

### 5. What a green M5.5 does not prove

Following ADR-0027 decision 5's pattern, so this arrives as a decision rather than as a discovery.

- **It ships a declaration that no correlation path reads, and it could not ship one that does.**
  Decision 0's measurement is the ground: zero cross-tool groups in either committed corpus, by
  mapper construction rather than by fixture.
- **It does not close G27.** That entry's validity condition is discharged when a derived group is
  *withheld* because the declaration is absent, and the derivation belongs to M5.6.
- **What would make it live:** M5.6's route extractor producing a group whose members come from two
  tools, plus this ADR's port and the gate that reads it. **That obligation now lives at M5.6's
  issue block as an acceptance criterion**, and at G27, whose `Status:` names both issues — not
  only in this ADR's prose, because **G28** is the record of what happens to a requirement
  reachable only by somebody re-reading a register.
- **What it does prove:** that a person can record the claim, that the record voids on
  reconfiguration, that the rule has exactly one evaluation site, and that the rule stays inside
  `projects` when its verdict later crosses.

## Consequences

**M5.6 grows, and the growth is named here rather than found there.** It inherits the port, its
`di.py` factory, the gate, and the acceptance criterion moved off M5.5 — on top of the route
extractor and the module-placement decision its own block already owns. If that makes M5.6 too
large, the split to make is the port and the gate against the extractor, not the criterion again.

**One new table and one migration in `projects`**, plus a route pair on that module's API. Rule 8
applies as normal; there is no second declarative base and nothing here changes that.

**G27 is split, not reassigned.** Its declaration half is M5.5's and its conditioning half is
M5.6's, and the entry stays open until both land. A reader who sees only the M5.5 commit must not
read the entry as discharged, which is why the split is written into `Status:` rather than into a
note under it.

**Three register entries are seeded by this ADR, in the same commit**, per `CLAUDE.md`'s rule that
an ADR deferring something with a trigger condition seeds the entry that carries the escalation
check: **G47** (the declaration voids on reconfiguration and never on drift, and nothing observes
the deployed revision), **G48** (the port is decided here and ships at M5.6, so between the two
issues the declaration has no cross-module reader), **G49** (owner-gating does not implement
M5.4's two-declarers premise).

**The `Server` banner stays refused as a `Location` signal, and stays available as a Security
Context one.** Nothing here reopens ADR-0023 Decision A, whose grounds — identity ambiguity across
two systems — this ADR's subject makes sharper rather than weaker. But the two uses are not the
same refusal, and decision 2 is careful about which it invokes: Decision A's own closing paragraph
names Security Context as the banner's home if it ever needs structure, so a deployment-identity
read is unbuilt rather than forbidden, and G47's trigger list says so.

## Amendments

- **2026-09-09 (M5.5, commit 2): whether a declaration may be created whose three values
  do not match the live ones. A decision this ADR did not take, not a correction of one it
  did.** Decision 2 defines when a declaration is *in force* and says nothing about what the
  write path accepts, so "void from birth" was expressible and undecided. **Decided: the
  write path refuses a mismatch, as a compare-and-set precondition rather than as
  validation** — the owner sends three values they were shown, and the check asserts nothing
  moved between their read and their write. That framing is what makes the route answer
  **409** rather than 400: the request is well-formed and the resource is not in the state it
  presumes.

  Two grounds, each at the width it actually holds:

  1. **The narrow half of M5.4's precedent.** `UpdateScannerConfigUseCase.execute` refuses a
     void-making combination *present in the request* — *"Granting against nothing is
     rejected rather than accepted and silently inert … the right answer arrived at by a
     route that tells the owner nothing."* A declare-with-mismatch is the same kind. **Not
     stated as "this module rejects void grants"**, which is false: `_resolve_consent` in
     that same file silently stores a void grant when a *later* act invalidates a *prior*
     row. Two rules, not one inconsistency.
  2. **The one that decides it.** A void-from-birth row is an attestation carrying a real
     name and a real timestamp on a claim the system can show was false at the instant it
     was made. A stale row is honest about its staleness; a born-false row is not, in a
     module where authorship is load-bearing (`declared_by`,
     `active_scan_consent_granted_by`, **G43**).

  **A third ground was considered and dropped, and it is recorded because it is the one that
  looks strongest.** It ran: a non-matching row can *activate itself* later, when somebody
  configures the target to a value a dormant declaration already names. It is dropped on two
  independent counts. It **proves too much** — the identical property ships in ADR-0024's
  consent, where ADR-0024's own 2026-08-27 amendment measured it (*"editing the target to a
  trailing slash and back restores the grant"*) and accepted it as a qualification, and the
  revived claim there authorizes real attack traffic rather than a wrong correlation group.
  And **the match requirement does not close it**: after a matching declaration is written,
  changing the target away and back revives it with nobody re-asserting. → **G50**.

  **Rejected alternative, named because it makes the question disappear and somebody will
  propose it:** a body-less route that copies the live values in, making a mismatch
  inexpressible rather than checked — the structural analogue of `_resolve_consent`'s "the
  target in THIS request, never `existing`'s". Rejected on **blind attestation**: it records
  a claim about values the declarer may never have seen, which empties `declared_by` of the
  meaning ground 2 rests on.

  **Decision 2's "single place it is evaluated" survives unqualified.** The use case *calls*
  `declaration_in_force` rather than re-comparing three strings; it only separates the two
  absences that function folds into `False` by design, because "you have not connected a
  repository" and "your values are stale" are different answers.

- **2026-09-09 (M5.5, commit 2): the URL check on the declare path, and the exception
  vocabulary. Also a decision this ADR did not take.** `declared_target_url` is persisted from
  user input, so it takes `validate_zap_target_url` — well-formedness plus rule 12's refusal
  of `user:pass@host`, and **not** an SSRF check, which this commit does not turn it into.
  Two consequences worth recording:

  - **`InvalidScannerConfig` is reused rather than translated.** A dedicated
    `InvalidServingDeclaration` could only ever carry that validator's output, and the rewrap
    would reopen the rule-12 message question for no behavioural gain, since both map to 400.
    `GitHubApiError` already serves two use cases in this router. So this commit adds **two**
    exceptions, `ServingDeclarationNotFound` (404) and `ServingDeclarationMismatch` (409), and
    not three.
  - **Validation runs before the compare-and-set, and that ordering is one of two independent
    protections rather than the only one.** The second is structural: **no message raised on
    the declare path interpolates a declared value.** It has to be, because
    `ConnectedRepo.url` is stored completely unvalidated — `ConnectRepositoryUseCase` takes a
    `str` and constructs the entity with no parse — so a repo URL carrying userinfo is
    storable today and quoting `declared_repo_url` would leak it on a field no ordering
    argument protects.
  - **The two validators stand in different relations to their live counterparts, and this
    commit adopts set equality for one pair while knowingly departing from it for the
    other.** For `declared_target_url` against `zap_target_url`, the same validator runs on
    both write paths, so the accepted sets are equal by construction and a declarable target
    is exactly a configurable one. For `declared_repo_url` against `ConnectedRepo.url` they
    are not: the live side is stored with **no validation at all**, so the declaration's
    accepted set is **strictly narrower**. The consequence is concrete and is not a corner
    case — a repository connected with userinfo in its url can never be declared, a
    permanent 400 rather than a mismatch, and per **G51** there is no update route and a
    second connect breaks the read, so a project in that state has no way out of it.
    **The narrowing is deliberate and is the right side to err on**: the alternative is
    copying a credential into a second table and serving it to every member. But it is a
    containment rather than a fix, and **the real fix is validating `ConnectedRepo.url` at
    its own write path**, which would restore equality by raising the live side rather than
    by lowering this one. That work is not opened as its own entry, because **G51's trigger
    already fires on it** — *"the first issue that changes `ConnectedRepoRepositoryPort`, or
    any issue that makes a project's repository re-connectable"* — and a fourth entry would
    be a second record of one obligation.

  **What a green M5.5 still does not prove, extending decision 5 rather than restating it:**
  the end-to-end sequence over the API can falsify exactly **one** of the rule's three pairs.
  `ConnectedRepo` has no update route, so the repo URL and branch pairs cannot be made to
  differ from live through HTTP at all and are covered by unit tests only. Recorded at the
  test module too, since that is where somebody reads four green steps and infers more.

## Alternatives considered

**A column on `ScannerConfig`, beside the consent triple.** The cheapest option and the one the
shape of M5.4 invites. Rejected in decision 1: it files a topology claim under tool-specific
configuration, mis-describes the debt exit that keeps `zap_target_url` honest, and leaves the
claim in a row that a `ConnectedRepo` edit can falsify without touching.

**A column on `ConnectedRepo`.** Symmetric and rejected symmetrically. It also sits worse: that
entity is the VCS connection, and a serving URL is a deployment fact rather than a repository one.

**Folding it into M5.4's consent — one flag, one column, or one screen.** Already forbidden by
M5.4's own bullet and not re-litigated here: *"Either can be true while the other is false … One
field would make each imply the other."* Recorded as considered because the two records now sit
one table apart and the folding will look tempting to somebody who sees them side by side.

**Waiting on G25 and binding the declaration to a commit.** Rejected in decision 2, on the ground
that G25 would leave the URL side unversioned regardless, so the wait buys a better-observed half
of a pair that stays half-observed.

**Verifying the coupling automatically instead of declaring it.** Rejected by ADR-0023 Decision A
before this issue existed, on two independent arguments plus the anti-correlation property — and
**what it refused is the banner as a `Location` correlation signal, which is narrower than "the
banner is refused"**; decision 2 above establishes that scope and names the use Decision A leaves
open. Cited rather than re-argued, which is what M5.5's roadmap block already instructs.

**Shipping the conditioning gate in M5.5 anyway, over the empty relation.** Rejected as decision 0.
A gate whose guarded event cannot occur is green whether or not it is wired in, so shipping it
would convert an unmet criterion into a passing test — the failure mode `CLAUDE.md`'s
type-suppression baseline exists to detect one level down, arriving here as a test rather than as
a suppression.
