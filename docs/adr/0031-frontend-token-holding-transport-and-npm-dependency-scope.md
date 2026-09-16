# ADR-0031 — The frontend's token holding, its transport to the API, and what ADR-0009 covers in an npm tree

## Status

**Accepted — 2026-09-16 (M8.3 started early). Decision 2 CONFIRMED by precondition P1 on 2026-09-16, before any screen code, with one measured limitation.**

- **P1 passed on every check it defines.**
  - Under `next dev` and, separately, under `next build` followed by `next start`, the `Authorization` value arrived at a header-echo server **byte-identical**: the same sha256 and 73 bytes on both sides.
  - Through the rewrite against the real API: no token → 401; a malformed token → 401; a valid token for a non-member → **404**; a valid token for the owner → 200.
  - The captured output is under *Consequences*.
- **One route is not reachable through the rewrite: `POST /projects/`.** It is the only one of the API's 19 routes whose path ends in a slash. This screen does not call it. M8.4's scope, "Connect repo → confirm Security Context → trigger first scan", does not name creating a project, but connecting a repository needs a project to exist, so an onboarding flow that starts from nothing would need it. That is an inference, not something M8.4 states. The measurement, the setting tested against it, and the bound M8.4 inherits are under *Consequences*.
- **Decision 1 stands**, because the transport it depends on is confirmed.
- **Decision 3 was never provisional.** Its dependency record is under *Consequences*.

*Until this confirmation this section read "Accepted — 2026-09-16 (M8.3 started early), with decision 2 PROVISIONAL", with decision 2 resting on the unverified assumption that a rewrite forwards `Authorization` unchanged, and P1 failing meaning decisions 1 and 2 would be re-decided before any screen code.*

## Context

`PRODUCT_SPEC.md` §13 names Next.js as the frontend, and a Next.js screen was chosen over a throwaway static page. That makes one screen **M8.3 started early**, a departure recorded under M8.3 in `docs/ROADMAP.md`. The screen is a login form, plus one project's ranked list from `GET /projects/{project_id}/scored-risks`.

Four facts about what already exists constrain every option. Each was read from the code rather than the documentation:

- **The token.** `POST /auth/login` (`identity`'s `login`) returns `LoginResponse`: `access_token`, `token_type = "bearer"`, `expires_in` and `user`. `JwtAccessTokenIssuer.issue` signs `{sub, iat, exp}` with the configured `Settings.jwt_algorithm` (HS256 by default), and `Settings.jwt_expires_minutes` defaults to 30. `identity`'s router has no refresh, logout or revocation route, so a token is valid until its `exp`, whatever happens.
- **How the API reads it.** Only from the `Authorization: Bearer` header: `platform/di.py`'s `_bearer_scheme = HTTPBearer()` feeds `get_current_user_id`, and every authenticated route depends on it. Nothing reads a cookie.
- **Cross-origin.** `create_app` in `platform/app.py` installs no CORS middleware. A page served on `:3000` that sends a Bearer header to `:8000` needs a preflight the API does not answer.
- **The GitHub connect flow.** `GET /auth/github/login` (`github_login`) requires `CurrentUserIdDep` and returns a redirect. `Settings.oauth_success_redirect_url` already assumes a frontend at `http://localhost:3000/dashboard`.

Rule 16 applies because where a credential is held, and how it reaches the API, is a credential-handling control. It is expensive to reverse because M8.4, M9.2 and M11.3 all build on the arrangement.

## Decision

### 1. The access token is held in memory only

The token lives in a module-level variable or React state. It is never written to `localStorage`, `sessionStorage` or a cookie.

- **What it exposes.** Script running on the frontend's origin (an XSS) can read the token and use or send it anywhere until its `exp` — up to 30 minutes — and nothing on the API side can revoke it.
- **What it does not expose.** Nothing is stored in the browser once the tab closes, and there is no CSRF exposure, because a Bearer header is never attached by the browser on its own.
- **What it costs.** A reload or a new tab requires logging in again.

With a 30-minute lifetime and no refresh route, **the persistent options buy mostly survival of a reload inside half an hour**. That is weaker than it looks, and weaker than their exposure: `localStorage` and `sessionStorage` keep the token readable by any XSS for its whole lifetime.

**An httpOnly cookie set by the API is rejected**. It changes `get_current_user_id`, which every authenticated route depends on, and it needs CSRF protection and credentialed CORS. That is a backend security change made for one screen.

**An httpOnly cookie held by a Next server layer, which attaches the Bearer header itself, is the better long-term shape, and is rejected here.** It adds a server session layer and CSRF handling on the Next side, and it pre-empts M8.4, which is where token holding gets decided (see *Consequences*). It also narrows XSS rather than closing it: injected script cannot read the token, but it can still call the proxy while the session lives.

### 2. The browser calls the frontend's own origin, and a Next rewrite forwards to the API — confirmed by P1, 2026-09-16

The browser sends API requests to `/api/*` on the frontend's origin, and a rewrite in the Next configuration forwards them to the API. The API's base URL comes from server-side configuration and never from user input. **`create_app` is not changed and no CORS middleware is added.**

**CORS in `create_app` is rejected for this screen.** It is a security-relevant change to the one factory every route shares, made to serve a page a same-origin proxy can serve without touching the backend.

**Precondition P1 — verified before any screen code, with captured output:**

1. Install into `frontend/`. `.gitignore` excludes `node_modules/`, `.next/` and `.env*.local` from the commit that lands this ADR, so nothing is staged.
2. Write a rewrite from `/api/:path*` to a header-echo server. The echo server is a standard-library Python script **outside this repository** that prints the request headers it receives.
3. Send a request with `Authorization: Bearer <a known exact string>` through the frontend origin, **separately under `next dev` and under `next build` followed by `next start`**.
4. Record three things:
   - (a) whether `Authorization` arrives **byte-identical**;
   - (b) whether `X-Forwarded-For` or `X-Forwarded-Host` is added;
   - (c) whether the rewrite works under `next start` at all.
5. Against the real API, through the proxy, a request with no token must be refused, while a valid token for a user who is not a member of the project must return **404**. The 404 is what shows the header reached `get_current_user_id`.
6. **If (a) or step 5 fails: stop.** Write no screen code, take no workaround, and re-decide decisions 1 and 2 by amending this ADR.

### 3. ADR-0009 on an npm dependency tree: direct dependencies only

ADR-0009's Decision is triggered by a claim, and has no clause about transitive dependencies. Where `pyproject.toml` records the protocol being applied, it was applied to individual direct dependencies: 5 of the 19 declared there (11 runtime, 8 dev) carry a "Verified per ADR-009" comment — `arq`, `pyyaml`, `semgrep`, `mypy`, `types-PyYAML`. It has never been applied over a whole tree. An npm tree for a Next.js app is, by the nature of the ecosystem, far larger than any direct list. It is not measured here, because measuring it means resolving a lockfile. So the protocol's scope for `frontend/` is stated rather than implied:

- **Covered:** each direct dependency, verified against primary sources (registry metadata, upstream repository) **before it is installed**.
- **The direct dependency set is:** `next`, `react`, `react-dom`, `typescript`, `@types/node`, `@types/react`, `@types/react-dom`, `eslint`, `eslint-config-next`. A direct dependency outside this list requires an amendment to this ADR first, and ends the M8.3 departure (see `docs/ROADMAP.md`).
- **Pinned** to exact versions, with no range operators, and installed with `npm ci` from a **committed lockfile**.
- **Where the record lives.** The verification evidence goes in this ADR's *Consequences*, as a dated entry. `package.json` cannot hold comments, so `pyproject.toml`'s per-dependency comments do not transfer.
- **Not covered: the transitive tree.** It is stated as unverified and registered as **G69**.
- **Install scripts.** Whether the tree installs with install scripts disabled is checked when the dependencies are installed, and recorded in the same entry. That is not verified at acceptance.

`ADR-0009` carries a dated amendment pointing here, so a reader of that document learns this scope.

## Consequences

- **M8.4 re-opens token holding.**
  - `github_login` requires a Bearer token and answers with a redirect. A browser top-level navigation cannot attach an `Authorization` header, so under decision 1 the connect flow cannot start as that route is written. The route half of this is read from the code; **the browser half is not verified here.**
  - The fix — returning the authorize URL as JSON, or a cookie-based session — belongs to M8.4, which carries an "Inherits ADR-0031" bullet.
- **M10.2's rate limiting would see the frontend server as the client** for proxied requests, unless forwarded headers are set and trusted. What a rewrite adds is recorded by P1 (b). M10.2 carries an "Inherits ADR-0031" bullet.
- **M11.3's deployment gains a Next server process**, because rewrites need one. P1 (c) records whether `next start` serves them.
- **Where the Node-toolchain premise is qualified.** Four places reject a Node toolchain, on two different grounds, and each carries a dated qualification landing with this ADR.
  - **As a supply-chain surface:** `pyproject.toml`'s mypy comment and ADR-0015's pyright alternative. Two reasons answer these:
    - **The alternatives were not equivalent.** pyright's Node surface bought nothing mypy did not already give at no Node cost, while `frontend/` is the frontend `PRODUCT_SPEC.md` §13 names, and its only Node-free alternative would have been discarded at M8.3.
    - **The surfaces sit in different places.** `frontend/` is **confined to its own directory, which no CI job installs**. That half of the argument ends when **G69** adds one.
  - **As a JS toolchain in a pure-Python project:** ADR-0007's dependency-cruiser alternative and `scripts/check_claims.py`'s `RETIRED_TOOLS` comment. That premise stops being true when `frontend/` is created. The rejection stands on its other ground, no benefit over a native Python tool.
- **Ungated.** Nothing in CI builds, lints or type-checks `frontend/`, and the suppression count cannot see it. Registered as **G69**, with the reasons adding a CI job is not a one-line change.

### Decision 3's dependency record (2026-09-16, before install)

Each direct dependency was checked against the npm registry (`npm view`: version, publish time, repository, maintainers, `dist.attestations`, `engines`, peer and optional dependencies, install scripts) and its upstream repository through the GitHub API.

| Package | Pinned | Published | Upstream (GitHub API) | Registry evidence |
|---|---|---|---|---|
| `next` | 16.3.5 | 2026-09-11 | `vercel/next.js`, not archived | SLSA provenance attestation; `engines.node >=20.9.0` |
| `react` | 19.3.0 | 2026-09-09 | `react/react` | SLSA provenance attestation |
| `react-dom` | 19.3.0 | 2026-09-09 | `react/react` | SLSA provenance attestation; peer `react ^19.3.0` |
| `typescript` | 6.0.3 | 2026-04-16 | `microsoft/TypeScript`, not archived | `main: ./lib/typescript.js` |
| `@types/node` | 22.20.3 | 2026-09-15 | `DefinitelyTyped/DefinitelyTyped` | registry signature |
| `@types/react` | 19.3.0 | 2026-09-09 | `DefinitelyTyped/DefinitelyTyped` | registry signature |
| `@types/react-dom` | 19.3.0 | 2026-09-09 | `DefinitelyTyped/DefinitelyTyped` | registry signature; peer `@types/react ^19.3.0` |

- **`react`'s repository URL is `github.com/react/react`, not `facebook/react`, and it was verified rather than assumed.** `GET /repos/facebook/react` answers **301** to `/repositories/10270250`. `GET /repos/react/react` returns `"id": 10270250`, `created_at` 2013-05-24 and owner organisation `react`. It is the same repository after a transfer, not a lookalike.
- **`typescript` is pinned to 6.0.3, not `latest` (7.0.2).** 7.0.2's root export is `./lib/version.cjs`, with its compiler API only under `./unstable/*`. 6.0.3's `main` is `./lib/typescript.js`. `next build` reported `Running TypeScript … Finished TypeScript` against 6.0.3.
- **`eslint` and `eslint-config-next`, both on decision 3's list, are NOT in the committed tree.** That is a subset of the list, so no amendment is owed. **They were installed once and then removed**, so their before-install record is also owed here:

  | Package | Tried | Published | Upstream (GitHub API) | Registry evidence, before install |
  |---|---|---|---|---|
  | `eslint` | 10.10.0, then 9.39.5 | 10.10.0: 2026-09-04. 9.39.5: 2026-07-10, **retrieved after removal**; the before-install query for it failed on its field syntax | `eslint/eslint`, not archived | 10.10.0: `engines.node ^20.19.0 \|\| ^22.13.0 \|\| >=24`. 9.39.5: `engines.node ^18.18.0 \|\| ^20.9.0 \|\| >=21.1.0`, `maintenance` dist-tag |
  | `eslint-config-next` | 16.3.5 | 2026-09-11 | `vercel/next.js`, not archived | SLSA provenance attestation; peer `eslint >=9.0.0` |

  Why neither is in the tree:
  - `eslint@10.10.0` (`latest`) declares `engines.node ^20.19.0 || ^22.13.0 || >=24`, which excludes this machine's Node **v22.12.0**.
  - `eslint@9.39.5` (the `maintenance` tag) installed with the registry warning `This version is no longer supported`.
  - Installed, that pair brought the tree's **only** engine mismatch (`@typescript-eslint/visitor-keys`' nested `eslint-visitor-keys`) and its **only** install script (`unrs-resolver@1.12.2`, via `eslint-config-next → eslint-import-resolver-typescript`).
  - Lint is ungated either way (**G69**), and `next build` still runs the type check.
- **Install scripts.** With the seven packages above, `npm install --ignore-scripts` produced a lockfile of **60 package entries, 39 of them optional platform binaries, and 0 with `hasInstallScript`**. `npm ci` from that lockfile needs no install script. It installed 29 packages with no engine or deprecation warning.
- **Not verified:** the transitive tree beyond the counts above (**G69**).

### P1, captured 2026-09-16

**The probe.** A header-echo server recorded each request head as raw socket bytes: a standard-library Python script outside this repository, listening on `127.0.0.1:8765`. The frontend was served on `:3100`, with `VERION_API_BASE_URL` pointing the rewrite at the echo server. A fixed Bearer value was sent with `curl`, and the received `authorization` value was compared byte for byte with what was sent.

```
[dev] request line: GET /projects/p1-probe/scored-risks?limit=1 HTTP/1.1
[dev] authorization headers received: 1
[dev] sent     sha256=af85e6d9b6165368075e46e5a56c6563e231ee338c6bd3b049ee20b7d01bc0fb len=73
[dev] received sha256=af85e6d9b6165368075e46e5a56c6563e231ee338c6bd3b049ee20b7d01bc0fb len=73
[dev] BYTE-IDENTICAL: True
[dev] x-forwarded-* added: ['x-forwarded-host']

[start] request line: GET /projects/p1-probe/scored-risks?limit=1 HTTP/1.1
[start] authorization headers received: 1
[start] sent     sha256=af85e6d9b6165368075e46e5a56c6563e231ee338c6bd3b049ee20b7d01bc0fb len=73
[start] received sha256=af85e6d9b6165368075e46e5a56c6563e231ee338c6bd3b049ee20b7d01bc0fb len=73
[start] BYTE-IDENTICAL: True
[start] x-forwarded-* added: ['x-forwarded-host']
```

- **(a)** Byte-identical under both modes.
- **(b)** The rewrite adds `x-forwarded-host` and **no `x-forwarded-for`**, so the API receives no client address from the proxy at all. That sharpens M10.2's inheritance.
- **(c)** The rewrite is compiled into `.next/routes-manifest.json` at build time and served by `next start`.
- **Header names** arrive lower-cased, which HTTP permits. The comparison is of the value.

**End to end, every check through the rewrite.** Against the real API, run under uvicorn on `:8000` with the database at `alembic` head `f3c9a1d27b58`, under `next build` then `next start`. The project was created **directly** against the API, because that setup is the route in the limitation below; every check went through the proxy.

```
register owner: 201
login owner: 200 token_len=188 token_type=bearer
register outsider: 201
login outsider: 200 token_len=188 token_type=bearer
create project as owner (SETUP, direct to API, not via proxy): 201
scored-risks, no token: 401 {'detail': 'Not authenticated'}
scored-risks, malformed token: 401 {'detail': 'Invalid or expired token'}
scored-risks, valid token, NON-member: 404 {'detail': "No readable project with id 'f7c761f6-9092-47e0-a199-ca2b069e65fd'"}
scored-risks, valid token, member: 200 keys=['items', 'limit', 'normalization', 'offset', 'thresholds', 'total']
```

The API's access log shows those four `GET …/scored-risks` requests arriving with 401, 401, 404 and 200. The 404 and the 200 are what show the header reached `get_current_user_id`.

**A side-effect found while running P1, and closed.** `next dev` wrote `AGENTS.md` and a `CLAUDE.md` into `frontend/`, and a second `CLAUDE.md` would be loaded as project instructions beside this repository's. `next.config.mjs` sets `agentRules: false`, the option `next/dist/server/config-shared.d.ts` documents for exactly this. The files were deleted, and no later run regenerated them.

### The trailing-slash limitation, measured and bounded (2026-09-16)

`POST /api/projects/` does not reach `create_project` through the rewrite. Without the setting below, Next answers **308** to `/api/projects`. The API then receives `POST /projects` and answers **307** to `http://127.0.0.1:8000/projects/`, an absolute URL on the API's own origin that a browser would follow off the proxy:

```
=== POST /api/projects/ (no follow)
HTTP/1.1 308 Permanent Redirect
location: /api/projects

=== POST /api/projects (no follow)
HTTP/1.1 307 Temporary Redirect
server: uvicorn
location: http://127.0.0.1:8000/projects/
```

**`skipTrailingSlashRedirect: true` was tested with the P1 harness still standing, and it does not fix this.** It removes Next's 308. The compiled rewrite still consumes the slash: its regex is `^/api(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))?(?:/)?$`, and `:path*` rebuilds the destination without it. The API logged `POST /projects` → **307** under `next start` and again under `next dev`:

```
=== [start, setting ON] POST /api/projects/ (no redirect following)
HTTP/1.1 307 Temporary Redirect
server: uvicorn
location: http://127.0.0.1:8000/projects/

INFO:     127.0.0.1:61200 - "POST /projects HTTP/1.1" 307 Temporary Redirect
INFO:     127.0.0.1:61213 - "POST /projects HTTP/1.1" 307 Temporary Redirect
```

The setting is therefore **not** in `next.config.mjs`: it is not load-bearing, and an unexplained configuration line is worse than none.

**The mechanism, in one sentence:** a redirect Starlette builds from the request URL points at the API's own origin — the rewrite sets `host` to the destination — and so leaves the proxy.

**Its instances today, measured on 2026-09-16 rather than asserted:**
- **Slash-terminated routes:** exactly **one** of the API's **19** routes (18 declared in the six inbound routers, plus `/health`) has a path ending in a slash: `create_project`, `@router.post("/")` in `projects/adapters/inbound/api/router.py`. No route is declared with an empty path.
- **Other redirects:** `RedirectResponse` is constructed **three** times, all in `identity`'s router. The URLs come from `oauth_client.build_authorize_url(state)` and from `settings.oauth_success_redirect_url` (twice, once with `?error=github_oauth_denied`). None is derived from the request, so the proxy does not change where they point.

**So the exposure is one route, measured, not a class.** M8.4 inherits that bound. Its onboarding flow is the first plausible caller of `POST /projects/`, by the inference under *Status*. A second slash-terminated route would reactivate the mechanism.

### What the screen's commit established about the build (2026-09-16)

- **`next build` is a real type check, and the only local one (G69).**
  - With `tsconfig.json` set to `"strict": true`, it ran clean.
  - Appending `export const typeCheckMutation: number = "not a number";` to `lib/session.ts` failed it with `error TS2322: Type 'string' is not assignable to type 'number'.` and `Failed to type check.`, exit 1.
  - The mutation was reverted.
- **Rule 12's non-leakage test ships with the module that handles the token**, in `frontend/tests/token-non-leakage.test.mjs`, run by `npm test`. It uses Node's built-in `node --test` with `--experimental-strip-types`, so it adds **no** dependency outside decision 3's list. Its six cases:
  - no source under `app/` or `lib/` *uses* Web Storage, `document.cookie`, IndexedDB or `console`;
  - a failed read (401, 404, 500, network failure) and a failed login return results that carry no token;
  - the token travels only in the `Authorization` header, to `/api/*`, and never in the URL.

  **Mutation-checked, not only green.** Writing the token to `localStorage` in `session.ts` failed case 1; appending it to the request URL in `api.ts` failed the four read cases. Both files were restored byte-identical by sha256. **Not run in CI (G69).**
- **`next-env.d.ts` is in `.gitignore`.** Every `next dev` and `next build` regenerates it with different imports (`.next/dev/types/*` against `.next/types/*`), so a tracked copy would flip with whichever command ran last.
- **`uv build`'s sdist includes `frontend/`'s 10 tracked files (the 9 of the screen and its build configuration, plus the rule-12 test) and nothing from `node_modules/`, `.next/` or `next-env.d.ts`**, since hatchling honours `.gitignore`. That matches what the sdist already ships under hatchling's defaults, with no `[tool.hatch]` configuration: `docs/`, `tests/`, `infra/` and `.claude/` among them. No exclusion was added. The wheel, built separately, holds 0 `frontend/` entries out of 218.

## Alternatives considered

- **`localStorage` or `sessionStorage`.** Rejected in decision 1: the token is readable by any XSS for its whole lifetime, in exchange for surviving a reload within 30 minutes.
- **An httpOnly cookie issued by the API.** Rejected in decision 1: it changes the shared `get_current_user_id` and needs CSRF protection and credentialed CORS.
- **An httpOnly cookie held by a Next server layer.** Rejected in decision 1 for this screen, as the better long-term shape arriving before the issue that decides it.
- **`CORSMiddleware` in `create_app`.** Rejected in decision 2: a security change to the shared factory that a same-origin proxy avoids.
- **Verifying the whole transitive npm tree by ADR-0009's checks.** Rejected in decision 3 as not performable by hand at that scale; recorded as unverified instead of implied as checked.
