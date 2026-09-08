# ADR-0027 — How M5.9 stands the demo target up, where the active capture lives, and what a green active-scan run proves

## Status

Accepted — 2026-09-08 (M5.9).

Written and reviewed **before any of M5.9's code existed**, the ordering ADR-0023's 2026-08-26
amendment adopted and ADR-0024 and ADR-0025 followed.

**Length ceiling: 20 KB (20,480 bytes), declared for this ADR as ADR-0024 declared its own scope
bounds.** Measured at **19163 bytes**, 94% of it. The ceiling
exists because a second decision hiding inside a long ADR is indistinguishable from a thorough
one — if it does not fit, the second decision is deferred with a trigger and a register entry.

## Context

`ROADMAP.md`'s M5.9 bullet names four deliverables — stand `verion-demo-target` up under Python
3.11, assert it is serving, run the active scan over the `eval()` sink and commit the capture,
report the measured `Tests (pytest — unit + integration)` step — and decides none of the questions
underneath them. **G24** and **G29** are assigned here. **G42**'s re-entry trigger is *"M5.9's
committed active capture"*. **G39** already fired at M5.4 on its scan-plan clause and is not
discharged by anything this issue does.

**The target is no longer prose, and every fact below was re-derived from it rather than from the
register.** At `c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850`, which `git rev-list --count HEAD`
reports as the repository's **only** commit and which is `main`:

- `app.py`'s `__main__` block is `app.run(host="0.0.0.0", port=8080, debug=False)`. **The port is
  fixed in the target's own code**, and its README states *"The port is part of what captured
  scanner output records"*. The committed `zap_scan.json` records `@port 8080`.
- `templates/index.html` carries an author comment stating that its `<a href="/calculate?expr=2*3">`
  is *"the ONLY path from `/` to /calculate"*, that removing it means *"the crawler never visits
  /calculate, never learns that the `expr` parameter exists"*, and that *"the crawler takes the
  parameter name to fuzz from this example query string"*.
- The comment above the `eval` call is a **contract from the target to this project**: *"This call
  must stay visible to that rule: do not fix it, wrap it, rename it, reach it through an alias or
  getattr, or add a `# nosec` / `# noqa` comment."* Nothing in Verion enforces it.
- The index page renders `urllib3.__version__` from the serving process, so a healthy response
  body carries `1.24.1` — the one string that cannot be produced under 3.12, since `urllib3
  1.24.1` fails to import there (**G29**).

Three prior decisions are cited, not re-argued: **ADR-013** (both gates, in order, before any
subprocess; `allow_private_targets` test-only), **ADR-0024 decision 5** (the plan's bounds, and
that its parameter spellings are unverified against any executed plan), and **ADR-0026 decisions 1
and 5** (a profile derived from *"the three committed real fixtures in `tests/fixtures/scanners/`"*,
scoped by explicit reference rather than by sweeping a directory).

## Decision

### 1. The active capture does **not** live in `tests/fixtures/scanners/`

It lives beside M5.9's test, under `tests/integration/fixtures/active_scan/`, carrying its own
provenance README modelled on the corpus one.

Both properties this would break are stated in that directory's own README, not in the register:
its third paragraph, *"All three come from one `Scan`, one checkout, one artifact"* — the coherence
**G23** was opened for and closed by — and its opening, *"Real output from the three scanner
adapters"*. An active ZAP capture is a **fourth real document from a second `Scan` under a
different plan**. Putting it there falsifies both sentences, and no label rescues it: the
`*_synthetic_edges.json` files coexist there because they are *not captures*, so the opening
sentence never claimed them. It would also falsify **ADR-0026 decision 1**'s *"the three committed
real fixtures in `tests/fixtures/scanners/`"* — which describes the **directory** while
`corpus_profile` names three literal filenames, so the ADR sentence breaks while the code and every
assertion stay green. That is exactly the class of silent staleness **G39** exists to name,
arriving through the ADR rather than through the profile.

**What this costs, stated rather than discovered: G39 is not dischargeable by M5.9.** Only a
capture that *replaces* `zap_scan.json` moves the derived row (`corpus_profile` reads three
filenames), and this decision does not replace it. G39 therefore stays open with its Note
(2026-08-27, M5.4) standing unchanged, and the event that discharges it is a full re-capture of the
passive corpus — which is not this issue's work and would invalidate every measurement **G20**
guards. **G42 is unaffected and is dischargeable**, because its trigger names *"M5.9's committed
active capture"* without naming a directory.

**Replacing `zap_scan.json` is rejected** rather than merely not chosen: the three files come from
one `Scan`, so an active ZAP capture from a second run breaks G23's coherence property directly,
and re-taking all three under an active plan invalidates the byte counts, both coverage tables,
every mapper assertion and ADR-0026's pinned literals — a milestone of work to discharge one
register entry.

### 2. The target reaches CI by a **live clone at the pinned SHA, with a hard SHA assertion**

M5.9 clones `github.com/CarlosPD8/verion-demo-target` through the real `GitRepoCheckout`, reads
`git rev-parse HEAD` back out of the checkout, and **aborts before serving anything if it is not
`c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850`**.

**Which half of G25 this relies on, stated because the two are easy to conflate: current state, not
capability.** `GitRepoCheckout` runs `git clone --depth 1` with no `--branch` and no `--revision`,
so the pinned SHA cannot be *requested*. It is reached today only because the target has exactly one
commit and it is the `main` tip — re-derived above, not assumed. The assertion is what makes that
safe: if the target ever gains a commit, the test **fails loudly** instead of scanning a different
tree. It is also the procedure `tests/fixtures/scanners/README.md`'s *How to re-capture* step 1
already prescribes (*"verify `git rev-parse HEAD` matches it before going further. If it does not,
stop"*), and G25's own probe note records that verification step working. The remedy if it ever
fires is a full clone plus `git checkout <sha>`, or `git clone --revision` on git ≥ 2.49.

**The port stays 8080 and the target is not modified.** The fixed port is orthogonal to this
decision — a vendored copy and an image face it identically — and it is not worked around, because
the target's README makes the port part of what a capture records and `zap_scan.json` records
`@port 8080`. A capture served on another port does not describe the same run. The existing
`_local_target_server` fixtures bind port `0`; **M5.9 does not reuse them and does not inherit that
convention.** A port collision surfaces as a bind failure, so the target never serves and decision
6's liveness gate fails — loud, not silent, which is the property G29 asks for.

**The target is served as a subprocess under `uv run --no-project --python 3.11
--with-requirements <checkout>/requirements.txt python app.py`**, the command the fixtures README
already records, with a **minimal environment** — the subprocess reaches a working `eval()` sink,
so anything in its environment is reachable by a scanner payload, and the CI job's environment
carries `DATABASE_URL` and `REDIS_URL`. In-process import is unavailable: the test process is 3.12
and the closure requires 3.11.

### 3. The CI test and the committed capture are **two artifacts**, and the capture is produced outside CI

The CI test runs the active scan live, asserts against its own live report, and **writes nothing**.
The committed capture is taken by a deliberate hand-run and committed in its own commit, **driven
through the shipped `ZapAdapter` at `ZapAdapter.docker_image`'s pinned digest, on the plan
`_build_plan_yaml` and `_active_scan_jobs` build — never an ad-hoc plan.** That clause is
load-bearing rather than tidy: **G42**'s trigger has two halves, and the second — *"when decision
5's parameter spellings become verifiable against a plan this repository has run"* — is satisfied
only by a run of the shipped plan. A hand-run reproducing the 2026-08-25 probe's shape would not
satisfy it, which is why G42's own `Deferral rationale:` rules out committing that probe's logs —
*"they were produced by a plan the shipped adapter does not have."*

Their procedures are incompatible and the incompatibility is not incidental. A capture owes
redaction, a key-set diff against the previous document, a leak scan whose pattern list is extended
*before* the run, and re-derivation of every number in its README. A CI test owes reproducibility on
every push. A test that writes its own fixture makes the fixture a function of the last run — the
arrangement `tests/fixtures/scanners/README.md` refuses in its second paragraph, *"These files are
not regenerated by any test."*

**The capture is the ZAP report *and* the target's Werkzeug access log**, both redacted. One is not
enough: **G42**'s trigger is when *"every row of ADR-0024's table becomes re-derivable"*, and that
table's own predicate column sources every row but the first from *"that app's own Werkzeug access
log"*. A report-only capture would arrive at G42's trigger unable to discharge it. Expect the rows
to be **restated rather than confirmed** — the probe ran a plan that was not decision 5's — which
is the outcome G42's *"either restates it or records why the hand-run figure still stands"*
anticipates.

### 4. M5.9's module is `platform`, and the header stays as written

M5.9 writes no file under `src/`. Its deliverables are a test, a fixture directory and possibly a
`ci.yml` step, and `platform` is this roadmap's label for CI-and-test-infrastructure work — M5.7,
its sibling, already carries it.

**This is deliberately not left OPEN the way M5.6's is, and the difference is what makes M5.6's
open question real.** M5.6's placement question is a *hexagonal boundary* question: it decides
which module owns production code, so rule 3 and `ARCHITECTURE.md` §3 bind the answer and getting
it wrong is architectural debt. M5.9 has no production code, so no boundary is in play and the
header is a label. Leaving a label open would imply a decision exists where none does.

### 5. What a green run proves, and what it may not assert

**Must prove, in this order, each failing on its own:**

1. **The target booted under 3.11 and is serving the app** — decision 6.
2. **The scan reached the vulnerable endpoint** — decision 6.
3. **The active scan produced a finding the passive plan does not produce, attributed to the
   `expr` parameter on `/calculate`.** Expressed against a committed artifact rather than against
   prose: at least one alert whose `alertRef` is **absent from the five in `zap_scan.json`**
   (`10038-1`, `10020-1`, `10036-2`, `10021`, `10027`), carrying an instance on the `/calculate`
   path attributed to `expr`. Which report field carries that attribution is read off the first
   live run and recorded in the test, not predicted here.

**Must not assert:** the alert id `90036` or `6-5`; any `riskcode`, `confidence`, `cweid` or alert
name; the alert count; the request, path or status-code counts; any timing. Every one of those is
**prose from one hand-run under a plan the shipped adapter does not have** — ADR-0024's table says
so in its own predicate column, *"not with decision 5's parameters, which no run in this repository
has executed"* — and pinning them would transcribe an unreproducible run into an assertion, which
is the defect **G42** exists to record rather than a fix for it. They belong in the capture's
provenance README, where they are evidence; a test is not the place to freeze them.

**What is already pinned by an artifact and therefore needs no assertion here:** the ZAP binary
(digest `sha256:781a2bda…`, in `ZapAdapter.docker_image` and `ci.yml`'s `Pull ZAP Docker image`
step), the SAST half (`semgrep_scan.json`'s `dangerous-eval` at `app.py` line 28 — a line number
safe to cite only because it is qualified by a frozen SHA), the plan (`_build_plan_yaml` and
`_active_scan_jobs`, pinned by `tests/unit/test_zap_scan_plan.py`), and the target tree (decision
2's assertion).

### 6. Two independent gates: liveness before the scan, crawl-reach after it

**They are separate assertions and neither substitutes for the other.**

**Liveness, before the scan.** An HTTP `GET /` whose response body must contain the string
`1.24.1`, rendered by the running process from `urllib3.__version__`. This is stronger than the
request-must-succeed that G29's sub-bullet asks for, and deliberately: a port that accepts a
connection proves nothing, a 200 proves something is serving, and the rendered dependency version
proves *this* app booted on *this* closure under an interpreter that can import `urllib3 1.24.1` —
which is the exact failure G29 describes.

**Crawl-reach, after the scan.** The report's URI set must contain a `/calculate` path carrying the
`expr` parameter. **This is a second door onto G29's false negative and the liveness gate does not
cover it**: `index.html`'s comment states its link is the only path from `/` to `/calculate`, so a
healthy app whose link was never followed yields passive header alerts only — byte-identical to a
correct scan of a target with no vulnerability. Both gates must fail loudly and separately, or a
crawl failure is read as an absence of vulnerability.

**It is checkable rather than aspirational, and the mechanism is worth stating because the report
has no spider log.** The URI set is the union of `site[].alerts[].instances[].uri`. That works
because the response-level passive alerts fire on every crawled page: in the committed corpus
`/robots.txt` and `/sitemap.xml` appear carrying only `10036-2` and `10038-1`, so a page ZAP
fetched is a page that appears. Four distinct URIs appear there, `/calculate?expr=2*3` among them.

**This is not added to G29 and that entry is not amended.** G29's subject is the interpreter
constraint and the liveness assertion that catches it; the crawl-reach gate is a decision about
what this test asserts, which is an ADR act. Recording it in the register instead would put an
assertion requirement in the one place a test author is least likely to read.

## Consequences

**CI executes real remote code execution on the runner, by design, on every push.** The active
scan's injection rules reach `eval()`; ADR-0024 records the probe's default-policy run executing
`sleep` on the target host twice. The blast radius is the runner: an ephemeral VM, with the target
subprocess started under a minimal environment (decision 2). It is bounded by ADR-0024 decision 5's
context and clock, and by `allow_private_targets=True` being confined to the test — ADR-013's
documented escape hatch, unchanged. What is new relative to ADR-0024 is only *where* the traffic
lands, and it lands on a machine this project already treats as disposable.

**The suite's runtime is expected to cross 120s and M5.9 must report the measured step.** The
tracked step reads **72s** at `ccc73f4` (CI run `34151970614`, re-derived from the jobs API, not
carried from `CLAUDE.md`'s 71s baseline at `7cca54b`), leaving **48s**. The only estimate of the
new test's cost is the probe's 62s, which is a hand-run under a different plan and omits standing
the target up. Above 300s the M5.7 dependency inverts; M5.9 says which happened.

**The target's `eval`-visibility contract is recorded here and enforced nowhere.** Decision 2's SHA
assertion is what stands in for it: at a pinned SHA the contract holds by construction, and a moved
SHA fails the test rather than silently scanning a tree whose sink was fixed. That is a
containment, not an enforcement, and it is the honest description.

**Two captures of one target now exist under two plans, in two directories, with one procedure
between them. → G44.**

## Alternatives considered

**A vendored copy of the target under `tests/integration/fixtures/`** — the shape
`tests/fixtures/scanners/README.md` itself names as *"the honest shape"*. **Rejected on a
measurement taken for this decision:** with this project's own lint configuration, `ruff check`
reports **`I001` on the target's `app.py`, and it is autofixable**; `.pre-commit-config.yaml` runs
`ruff check --force-exclude --fix`, so the hook would **rewrite the vendored file and break the
byte-identity that is the entire point of vendoring it**, failing the commit while leaving the
original staged. Protecting it needs a `pyproject.toml` `exclude` that permanently narrows
`ruff check .` over a directory, and `trailing-whitespace`/`end-of-file-fixer` sit outside any ruff
exclusion (dormant today — all four files are clean — but not absent). Two further costs: identity
to `c68caa7` becomes a claim inside this repository with nothing checking it, which is the
unverifiable-prose class **G42** exists for; and the target's README, where the freeze contract
lives, is not part of the app and would not be vendored. **The objection that motivated vendoring
does not transfer**: the README's argument is about repointing `test_multi_scanner_dispatch.py` at a
default branch with no SHA check — its word is *silently* — and that same file already clones
`github.com/octocat/Hello-World` on every push, so an external clone in CI is not a new class of
dependency here.

**A container image of the target.** Rejected: a Dockerfile, a registry and a digest pin for a
six-file app, against a target whose README states *"No CI, no tests, no linter config, no Docker
… by design"*. The image becomes a second frozen artifact to keep in step with `c68caa7` — the
vendoring drift problem with a build step on top — and it answers the fixed port no better than
either alternative.

**Serving the target on an ephemeral port**, as both `_local_target_server` fixtures do. Rejected:
the target's README makes 8080 part of what a capture records, editing `app.py` is forbidden by its
own contract, and a wrapper importing `app` to rebind the port would be a serving path that differs
from the documented one and from the run every committed fixture describes.

**One artifact: the CI test writes the capture.** Rejected — decision 3. It makes a committed
fixture a function of the last CI run and puts redaction on a path nobody reviews.

**Adding the crawl-reach requirement to G29 instead of deciding it here.** Rejected — decision 6.
The register is where a *gap* lives; this is an assertion the test must carry, and it would be
invisible to the person writing that test.

**Asserting the probe's alert ids and risk codes**, which would make the test read as a much
stronger demonstration. Rejected — decision 5. It freezes an unreproducible hand-run into a green
check, which is what **G42** is a record of, not a remedy for.
