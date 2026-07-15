# auth-gateway

A centralized OAuth / authentication Cloudflare Worker for a fleet of apps on a shared apex domain. It delegates identity to GitHub (via [arctic](https://arcticjs.dev/)), issues short-lived EdDSA JWT access tokens and rotating refresh tokens (held in a per-family Durable Object for atomic rotation/theft-detection), sets `HttpOnly` cookies for browser SSO, and publishes a JWKS endpoint so resource workers can verify tokens offline without phoning home on every request.

---

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/authorize` | Starts the GitHub OAuth flow. Accepts optional `redirect_uri` query param (must be in `REDIRECT_ALLOWLIST`). |
| `GET` | `/callback` | GitHub redirects here after the user authorizes. Validates CSRF state, exchanges code for tokens, sets cookies, and redirects to `redirect_uri`. |
| `POST` | `/token` | Two grants, dispatched by `grant_type`. **Refresh (default, no `grant_type`):** reads the refresh token from the `__Secure-fleet_rt` cookie (no JSON body); on success returns `200` with refreshed `Set-Cookie` headers (no token in response body). Rotation + theft-detection are atomic in the `RefreshFamily` Durable Object. Accepts credentialed CORS from allowlisted app origins. **`client_credentials` (form body with `client_id` + `client_secret`):** returns `200 { access_token, token_type, expires_in }` for a programmatic caller — see [Programmatic access](#programmatic-access-service-credentials). |
| `POST` | `/logout` | Revokes the refresh-token family (via the `RefreshFamily` Durable Object) and returns `204` with cleared cookies. Accepts credentialed CORS from allowlisted app origins. |
| `GET` | `/.well-known/jwks.json` | Publishes the public EdDSA key(s) as a JWKS. Resource workers fetch this to verify tokens offline. |
| `POST` | `/clients` | Create a service client (fleet PAT) owned by the caller. Requires the caller's own access token (Bearer or `__Secure-fleet_at` cookie). Returns `client_id` + a one-time `client_secret`. |
| `GET` | `/clients` | List the caller's own service clients (metadata only, never the secret). |
| `DELETE` | `/clients/:id` | Revoke one of the caller's own service clients. |

---

## Configuration

### `wrangler.jsonc` — `vars`

| Variable | Example | Description |
|----------|---------|-------------|
| `ISSUER` | `https://auth.yourdomain.com` | JWT `iss` claim and JWKS base URL. |
| `AUDIENCE` | `fleet` | JWT `aud` claim; must match resource worker config. |
| `COOKIE_DOMAIN` | `.yourdomain.com` | Domain for the access cookie `__Secure-fleet_at` (leading dot enables all subdomains). The refresh cookie `__Secure-fleet_rt` is host-only (no `Domain` attribute). |
| `ACCESS_TTL_SEC` | `900` | Access token lifetime in seconds (default: 15 minutes). |
| `REFRESH_TTL_SEC` | `2592000` | Refresh token lifetime in seconds (default: 30 days). |
| `REDIRECT_ALLOWLIST` | `["https://app1.yourdomain.com"]` | JSON array of exact origins (scheme + host + optional port) allowed as `redirect_uri` targets. Also used as the credentialed-CORS origin allowlist for `/token` and `/logout`. |
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

### 1b. Create the service-client KV namespace

```bash
pnpm wrangler kv namespace create CLIENTS_KV
```

Paste the printed `id` into `wrangler.jsonc` → the `CLIENTS_KV` entry in
`kv_namespaces`, replacing the placeholder id.

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

The verifier lives in its own GitHub repository, [`echung32/auth-verify`](https://github.com/echung32/auth-verify) (tagged `v1`), so downstream resource workers — and this gateway's e2e test — can consume it via git dependency without an npm account.

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

## Programmatic access (service credentials)

Machine callers that can't run the browser OAuth flow — a service hitting an
internal API guarded by `auth-verify`, a cron job, a CLI — use **service
clients**: self-service "personal access tokens" for the fleet.

1. A logged-in user creates a client (a browser app sends the `__Secure-fleet_at`
   cookie automatically; a CLI passes `Authorization: Bearer <access_token>`):

   ```bash
   curl -X POST https://auth.yourdomain.com/clients \
     -H "authorization: Bearer $ACCESS_TOKEN" \
     -H "content-type: application/json" \
     -d '{"label":"ollama-caller"}'
   # => { "client_id": "svc_…", "client_secret": "…", "label": "ollama-caller", "created_at": "…" }
   ```

   The `client_secret` is shown **only once** — store it in the calling service.

2. The service exchanges its credentials for a short-lived JWT:

   ```bash
   curl -X POST https://auth.yourdomain.com/token \
     -d grant_type=client_credentials \
     -d client_id=svc_… \
     -d client_secret=…
   # => { "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 3600 }
   ```

3. The service calls resource workers with `Authorization: Bearer <access_token>`.
   `requireUser` verifies it unchanged. The token **acts as the owning user**
   (same `sub`/`email`/scopes) and additionally carries `token_use: "service"` +
   `client_id`, so a resource worker can distinguish automated calls if it wants
   to. Re-exchange when the token expires.

Revoking a client (`DELETE /clients/:id`) stops new tokens immediately; any
already-issued token ages out within `ACCESS_TTL_SEC`. Service tokens carry no
refresh token and set no cookies.

---

## Development

### Worker test suite

```bash
pnpm test
```

Runs the Vitest worker pool suite (GitHub OAuth is stubbed — no real credentials needed), including an end-to-end test that verifies issued tokens through the published `auth-verify` package. The verifier's own unit suite lives in the [`echung32/auth-verify`](https://github.com/echung32/auth-verify) repo. Run `pnpm typecheck` for `tsc --noEmit`.

### Updating the verifier

The `auth-verify` devDependency is pinned to the `v1` tag and resolved to a specific commit in `pnpm-lock.yaml`, so installs stay reproducible. To pull a verifier change into this gateway:

1. Make the change in the [`echung32/auth-verify`](https://github.com/echung32/auth-verify) repo, rebuild and commit `dist/`, then move/push the `v1` tag.
2. Here, run `pnpm update auth-verify` to re-resolve the lockfile to the new commit, then `pnpm test` to confirm the e2e contract test still passes.

Because `v1` is a moving tag, CI must install with `--frozen-lockfile` so the committed commit hash — not whatever `v1` currently points at — is authoritative.

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
  auth-gateway  (this repo)
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
