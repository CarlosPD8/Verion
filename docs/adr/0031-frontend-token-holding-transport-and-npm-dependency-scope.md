# ADR-0031 — The frontend's token holding, its transport to the API, and what ADR-0009 covers in an npm tree

## Status

**Accepted — 2026-09-16 (M8.3 started early), with decision 2 PROVISIONAL.**

- **Decision 2** (a Next rewrites proxy in place of CORS) rests on an unverified assumption: that a Next rewrite forwards the `Authorization` request header to the API unchanged.
- **Precondition P1** verifies that assumption. It runs at the start of the commit that builds the screen, before any screen code is written, and is specified under decision 2.
- **Decision 1 is coupled to decision 2.** If P1 fails, both are re-decided by an amendment to this ADR before any screen code exists. No workaround is taken inside the screen.
- **Decision 3 is not provisional.**

*This Status paragraph is replaced by a dated confirmation when P1 passes, and `docs/adr/README.md`'s row changes with it.*

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

### 2. The browser calls the frontend's own origin, and a Next rewrite forwards to the API — PROVISIONAL on P1

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

## Alternatives considered

- **`localStorage` or `sessionStorage`.** Rejected in decision 1: the token is readable by any XSS for its whole lifetime, in exchange for surviving a reload within 30 minutes.
- **An httpOnly cookie issued by the API.** Rejected in decision 1: it changes the shared `get_current_user_id` and needs CSRF protection and credentialed CORS.
- **An httpOnly cookie held by a Next server layer.** Rejected in decision 1 for this screen, as the better long-term shape arriving before the issue that decides it.
- **`CORSMiddleware` in `create_app`.** Rejected in decision 2: a security change to the shared factory that a same-origin proxy avoids.
- **Verifying the whole transitive npm tree by ADR-0009's checks.** Rejected in decision 3 as not performable by hand at that scale; recorded as unverified instead of implied as checked.
