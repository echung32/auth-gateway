# oauth-worker

A centralized OAuth / authentication Cloudflare Worker for a fleet of apps on a shared apex domain. It delegates identity to GitHub (via [arctic](https://arcticjs.dev/)), issues short-lived EdDSA JWT access tokens and rotating refresh tokens (held in a per-family Durable Object for atomic rotation/theft-detection), sets `HttpOnly` cookies for browser SSO, and publishes a JWKS endpoint so resource workers can verify tokens offline without phoning home on every request.

---

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/authorize` | Starts the GitHub OAuth flow. Accepts optional `redirect_uri` query param (must be in `REDIRECT_ALLOWLIST`). |
| `GET` | `/callback` | GitHub redirects here after the user authorizes. Validates CSRF state, exchanges code for tokens, sets cookies, and redirects to `redirect_uri`. |
| `POST` | `/token` | Refresh-token grant. Reads the refresh token from the `__Secure-fleet_rt` cookie (no JSON body); on success returns `200` with refreshed `Set-Cookie` headers (no token in response body). Rotation + theft-detection are atomic in the `RefreshFamily` Durable Object. Accepts credentialed CORS from allowlisted app origins. |
| `POST` | `/logout` | Revokes the refresh-token family (via the `RefreshFamily` Durable Object) and returns `204` with cleared cookies. Accepts credentialed CORS from allowlisted app origins. |
| `GET` | `/.well-known/jwks.json` | Publishes the public EdDSA key(s) as a JWKS. Resource workers fetch this to verify tokens offline. |

---

## Configuration

### `wrangler.jsonc` — `vars`

| Variable | Example | Description |
|----------|---------|-------------|
| `ISSUER` | `https://auth.yourdomain.com` | JWT `iss` claim and JWKS base URL. |
| `AUDIENCE` | `fleet` | JWT `aud` claim; must match resource worker config. |
| `COOKIE_DOMAIN` | `.yourdomain.com` | Domain for the `__Secure-fleet_at` / `__Secure-fleet_rt` cookies (leading dot enables all subdomains). |
| `ACCESS_TTL_SEC` | `900` | Access token lifetime in seconds (default: 15 minutes). |
| `REFRESH_TTL_SEC` | `2592000` | Refresh token lifetime in seconds (default: 30 days). |
| `REDIRECT_ALLOWLIST` | `["https://app1.yourdomain.com"]` | JSON array of allowed `redirect_uri` values. |
| `GITHUB_REDIRECT_URI` | `https://auth.yourdomain.com/callback` | Must match the callback URL registered in your GitHub OAuth App. |

### `AUTH_KV` — KV namespace

Single-use OAuth CSRF `state` is stored here (short TTL). Refresh tokens are **not** in KV — they live in the `RefreshFamily` Durable Object. Create the namespace and paste the ID into `wrangler.jsonc`:

```bash
pnpm wrangler kv namespace create AUTH_KV
# copy the printed id into wrangler.jsonc → kv_namespaces[0].id
```

### `RefreshFamily` — Durable Object

Refresh-token families are stored in a SQLite-backed Durable Object (`durable_objects.bindings` → `REFRESH_FAMILY`, with a `new_sqlite_classes` migration in `wrangler.jsonc`). A DO instance is single-threaded, so rotation and theft-detection are atomic. No setup beyond the binding + migration (already in `wrangler.jsonc`); `wrangler deploy` provisions it.

### Secrets

Typed in `src/env.d.ts` (they aren't in `wrangler.jsonc`, since secrets must never be committed there). Set them via `wrangler secret put` before deploying (see Deploy below); in tests they're supplied by `vitest.config.ts`:

| Secret | Description |
|--------|-------------|
| `SIGNING_PRIVATE_JWK` | EdDSA (Ed25519) private key in JWK JSON format. Generate with `node scripts/generate-keys.mjs`. |
| `GITHUB_CLIENT_ID` | Client ID from your GitHub OAuth App. |
| `GITHUB_CLIENT_SECRET` | Client Secret from your GitHub OAuth App. |

---

## Deploy prerequisites

Run these once before `wrangler deploy`. You do **not** need to run them in development.

### 1. Create the KV namespace

```bash
pnpm wrangler kv namespace create AUTH_KV
```

Paste the printed `id` into `wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  { "binding": "AUTH_KV", "id": "<paste id here>" }
]
```

### 2. Generate the signing key and upload secrets

```bash
node scripts/generate-keys.mjs          # prints SIGNING_PRIVATE_JWK and the public JWKS

pnpm wrangler secret put SIGNING_PRIVATE_JWK   # paste the printed JWK JSON when prompted
pnpm wrangler secret put GITHUB_CLIENT_ID
pnpm wrangler secret put GITHUB_CLIENT_SECRET
```

### 3. Create a GitHub OAuth App

In your GitHub account or organization, go to **Settings → Developer settings → OAuth Apps → New OAuth App** and set:

- **Homepage URL**: `https://auth.yourdomain.com`
- **Authorization callback URL**: `https://auth.yourdomain.com/callback`

Copy the **Client ID** and generate a **Client Secret** for the `wrangler secret put` commands above.

### 4. Deploy

```bash
pnpm wrangler deploy
```

---

## Resource workers

`packages/auth-verify` is developed in this repo and published to its own GitHub repository (tagged `v1`) so downstream resource workers can consume it without an npm account.

Install the verifier via git dependency:

```bash
pnpm add github:<you>/auth-verify#v1
```

Then guard a route:

```ts
import { requireUser } from "auth-verify";

const OPTS = {
  jwksUrl: "https://auth.yourdomain.com/.well-known/jwks.json",
  issuer: "https://auth.yourdomain.com",
  audience: "fleet",
};

const user = await requireUser(request, OPTS); // throws a 401 Response if invalid
```

`requireUser` reads the token from the `Authorization: Bearer <token>` header or the `__Secure-fleet_at` cookie. It verifies the signature offline using `createRemoteJWKSet` (jose), caches the JWKS in module scope, and re-fetches automatically when it encounters an unknown `kid` (key rotation).

`user` is typed as `VerifiedUser`:

```ts
interface VerifiedUser {
  sub: string;
  email: string | null;
  name: string | null;
  scopes: string[];
}
```

On a 401, a browser app should redirect the user to:

```
https://auth.yourdomain.com/authorize?redirect_uri=<self>
```

---

## Development

### Worker test suite

```bash
pnpm test
```

Runs the Vitest worker pool suite (GitHub OAuth is stubbed — no real credentials needed). The `auth-verify` package has its own separate suite (below). Run `pnpm typecheck` for `tsc --noEmit`.

### auth-verify package tests

```bash
pnpm --filter auth-verify test
```

### Regenerate Cloudflare types

After changing bindings in `wrangler.jsonc`, regenerate `worker-configuration.d.ts`:

```bash
pnpm wrangler types
```

### Local dev server

```bash
pnpm dev
```

Starts `wrangler dev` on `http://localhost:8787`. Secrets can be stored in a `.dev.vars` file:

```
SIGNING_PRIVATE_JWK={"kty":"OKP",...}
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
```

---

## Architecture overview

```
Browser / API client
       │
       ▼
  oauth-worker  (this repo)
  ┌──────────────────────────────────────────────┐
  │  /authorize  → GitHub OAuth redirect         │
  │  /callback   → exchange code, issue tokens   │
  │  /token      → rotate refresh token          │
  │  /logout     → revoke + clear cookies        │
  │  /.well-known/jwks.json  → public JWKS       │
  │                                              │
  │  AUTH_KV: single-use CSRF state              │
  │  RefreshFamily DO: rotating refresh tokens   │
  │  SIGNING_PRIVATE_JWK: EdDSA private key      │
  └──────────────────────────────────────────────┘
       │ sets __Secure-fleet_at cookie (JWT)
       │ sets __Secure-fleet_rt cookie (opaque)
       ▼
  Resource worker  (separate repo, uses auth-verify)
  ┌────────────────────────────────────────────┐
  │  requireUser(request, opts)                │
  │    reads Bearer header or cookie           │
  │    verifies JWT offline via JWKS           │
  │    returns VerifiedUser                    │
  └────────────────────────────────────────────┘
```
