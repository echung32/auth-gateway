# Centralized OAuth / Authentication Worker — Design

**Date:** 2026-06-25
**Status:** Approved design, ready for implementation planning
**Approach:** C — ship a lean JWT-issuing auth worker now, structured so the full
`workers-oauth-provider` OAuth server can be mounted later for third-party clients.

## Goal

A single central worker (`auth.yourdomain.com`) that authenticates users via GitHub
and provides authentication for a fleet of first-party workers — both browser web
apps and token-based APIs — with seamless single sign-on across them.

## Key decisions (settled during brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Identity source | GitHub OAuth (upstream) | No password storage; low maintenance. |
| Consumers | Mix of browser web apps + token APIs | Both served by one token primitive. |
| Token validation | **JWT verified offline** by resource workers | Central worker stays off the hot path; one primitive serves browser + API. |
| Refresh-token store | **Per-family Durable Object** (atomic rotate/revoke) | KV's non-atomic read-then-write can't guarantee single-use rotation/theft-detection on a 30-day credential; a per-family DO serializes the head check. (Revised from the original KV design after review.) |
| Browser refresh | **Credentialed CORS** on `/token` + `/logout` | Browser apps on allowlisted origins call `auth.<domain>/token` cross-origin with `credentials: include`; the Set-Cookie only applies with `Access-Control-Allow-Credentials` + a specific `Access-Control-Allow-Origin`. |
| Client types | First-party now, third-party likely later | Build lean; keep an OAuth-shaped seam for `workers-oauth-provider` later. |
| Domain | Custom domain, shared apex (`.yourdomain.com`) | Enables a shared cookie → true seamless browser SSO. |
| Revocation | No denylist on resource-worker hot path | Zero KV reads per request; revocation bites at refresh (≤15-min window). |
| Audience scoping | Fleet-wide audience by default | Seamless SSO; per-app audiences added only where isolation is needed. |
| Signing | Asymmetric EdDSA (Ed25519) | Resource workers verify with public key only; cannot mint tokens. |

## Tech stack

- **`hono`** — routing (already in the project).
- **`jose`** — all JWT signing/verification and JWKS. No hand-rolled crypto.
- **`arctic`** — GitHub upstream OAuth dance (authorize URL, `state`, code→token exchange).
- **KV (`AUTH_KV`)** — refresh-token storage + theft-detection bookkeeping.
- **Worker secrets** — Ed25519 private signing key, GitHub client secret.
- **`workers-oauth-provider`** — deferred to phase 2 (third-party / MCP clients).
- **Vitest + `@cloudflare/vitest-pool-workers`** — tests in the real workerd runtime.

## Architecture

Three parts:

### 1. Central auth worker (`auth.yourdomain.com`)

Internal modules kept separate so the phase-2 provider swap is clean:

- **Flow handler** — routes:
  - `GET /authorize` — begin GitHub login; validate `redirect_uri` against allowlist.
  - `GET /callback` — GitHub returns here; verify `state`, exchange code, upsert user, mint tokens, set cookies, redirect back.
  - `POST /token` — refresh: rotate refresh token, mint new access JWT.
  - `POST /logout` — delete refresh token from KV, clear cookies.
  - `GET /.well-known/jwks.json` — publish public key(s) with `kid`.
- **Identity adapter** — wraps `arctic`'s GitHub client; normalizes the GitHub
  profile into an internal user record. Isolated so more upstreams are additive.
- **Token service** — the seam. Clean interface: `issueTokens`, `verify`,
  `refresh`, `revoke`. Today backed by `jose` + KV; later can be backed by
  `workers-oauth-provider`.
- **JWKS endpoint** — serves the public key(s) resource workers verify against.

### 2. Shared verification package (`auth-verify`)

Resource workers live in **separate repos**, so the helper is its own standalone
GitHub repo, built to `dist/`, and installed as a **git dependency**:
`pnpm add github:<you>/auth-verify#v1`. No npm account, no registry auth; versions
pinned via git tags. `jose` is a peer dependency the consumer already has. This keeps
one canonical copy of the security-sensitive verify logic (no copy-paste drift).

A small helper imported by every resource worker:

- `requireUser(request, env)` → verified user claims, or throws `401`.
- Reads the access token from the `Authorization: Bearer` header (APIs) **or** the
  cookie (browser apps).
- Fetches and caches the JWKS; refetches on an unknown `kid` (supports key rotation).
- Verifies signature, `exp`, `iss`, and `aud` offline — no network call to the auth worker.

### 3. Resource workers (browser apps + APIs)

Unchanged except: import `auth-verify` and call `requireUser`. On `401`, browser
apps redirect to `auth.yourdomain.com/authorize?redirect_uri=...`.

### Storage & keys

- `AUTH_KV`: single-use OAuth `state` only. (Refresh tokens moved to a per-family Durable Object — `RefreshFamily` — for atomic rotation/theft-detection.)
- Secrets: Ed25519 private key (signing), GitHub client ID/secret. Optional `SIGNING_PUBLIC_JWKS` (JSON array of additional public JWKs) lets the JWKS publish previous keys during a rotation window for zero-downtime key rotation.
- Refresh: the `RefreshFamily` DO stores the full `UserClaims`, so a refreshed access token carries the same `email`/`name`/`scopes` as the original (no claim degradation across refresh).
- Access tokens are **not** stored — they are self-verifying JWTs.

## Data flow

### A) First-time browser login (seamless SSO)

1. User hits `app1.yourdomain.com`; no valid cookie → `requireUser` throws 401 →
   app1 redirects to `auth.yourdomain.com/authorize?redirect_uri=https://app1.yourdomain.com/...`.
2. Auth worker validates `redirect_uri` against the allowlist, then redirects to
   GitHub with a signed, single-use `state` (CSRF + carries return URL).
3. GitHub login → `auth.yourdomain.com/callback`. Verify `state`, exchange code for
   GitHub token, fetch profile, upsert internal user.
4. Token service mints an **access JWT** (~15 min; claims `sub`, `email`, `scopes`,
   `iss`, `aud`, `jti`) and an opaque **refresh token** (stored in `AUTH_KV`).
5. Set two cookies on `.yourdomain.com` — `HttpOnly`, `Secure`, `SameSite=Lax`:
   the access JWT and the refresh token. Redirect back to app1.
6. User visits `app2.yourdomain.com` → cookie already present → verified offline →
   instantly logged in. **This is the SSO.**

### B) API access (programmatic / SPA)

- Client sends `Authorization: Bearer <access JWT>`. Resource worker verifies
  signature + `exp` + `aud` offline against cached JWKS. No network call.

### C) Refresh (access token expired)

- A `401` triggers a call to `auth.yourdomain.com/token` with the refresh cookie.
- Auth worker checks the refresh token in KV (valid? not revoked?), mints a fresh
  access JWT, re-sets the cookie.
- Refresh tokens **rotate** on every use; reuse of a rotated token invalidates the
  whole chain (theft detection).

### D) Logout / revocation

- `POST /logout` deletes the refresh token from KV and clears cookies.
- No access-token denylist on the resource-worker hot path: a revoked user retains
  access only until the ≤15-min access token expires. Revocation is enforced at
  refresh time.

## Security model

| Threat | Mitigation |
|--------|------------|
| Token forgery | EdDSA signing; private key only in auth-worker secrets. Resource workers verify, never mint. |
| Open redirect / token exfiltration | `redirect_uri` checked against a strict allowlist (no wildcards) before any redirect. |
| CSRF on login | Unguessable single-use `state` (KV, short TTL), verified on callback. Note: KV get-then-delete is not atomic, so a concurrent-callback race could consume state twice; accepted as a documented residual risk because GitHub's single-use authorization code independently blocks the double-login replay. Atomic single-use would require a Durable Object (out of scope). |
| Cookie theft | `HttpOnly` + `Secure` + `SameSite=Lax`; short access-token lifetime caps damage. |
| Refresh-token leak | Opaque, server-side in KV, rotated on use; rotated-token reuse kills the chain. |
| Audience confusion | JWT `aud` claim; per-worker enforcement optional. Default = fleet-wide. |
| Key rotation | JWKS publishes `kid`; roll by publishing new key alongside old, switch signing, retire old after expiry. No downtime. |
| GitHub secrets | Client secret in Worker secrets; never in code or KV. |

## Testing strategy

Vitest + `@cloudflare/vitest-pool-workers` (real workerd runtime; authentic KV/bindings).
GitHub is stubbed at the HTTP boundary — no live calls in tests.

- **Token service (unit):** issue→verify round-trips; expired rejected; bad-signature
  rejected; `aud`/`iss` mismatch rejected; refresh rotation invalidates old token;
  rotated-token reuse kills the chain.
- **Verify package (unit):** reads bearer header and cookie; returns claims on valid;
  throws 401 on missing/expired/tampered; JWKS caching + refetch on unknown `kid`.
- **Login flow (integration):** `/authorize` rejects off-allowlist `redirect_uri`;
  `/callback` rejects bad/expired `state`; happy path sets both cookies with correct
  attributes (`HttpOnly`, `Secure`, `SameSite`, `Domain=.yourdomain.com`).
- **Refresh endpoint (integration):** valid refresh mints new access token;
  revoked/expired/rotated refresh rejected; logout clears cookies and deletes KV record.
- **End-to-end (happy path):** login → call a protected resource route with the issued
  token → 200; tampered token → 401.

## Phase 2 seam (future, not in this build)

When third-party / MCP clients arrive, mount `workers-oauth-provider` behind the
existing token-service interface and OAuth-shaped routes. Resource workers already
verify JWTs and need no change. Adds: dynamic client registration, consent screens,
PKCE for external clients.

## Out of scope (YAGNI for now)

- Multiple upstream identity providers (adapter is isolated to add later).
- Per-app audience isolation (added only where a specific app needs it).
- Access-token denylist / instant global revocation.
- Third-party client registration and consent UI (phase 2).
