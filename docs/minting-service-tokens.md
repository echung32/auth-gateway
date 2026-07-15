# Minting service tokens (programmatic access)

This guide is for **machine callers** that can't run the interactive GitHub
browser flow — a service hitting another service's API, a cron job, a CLI, a
CI step. Instead of a user login, a caller uses a **service client**: a
`client_id` + `client_secret` that a user mints once and hands to the service.
The service exchanges those credentials for short-lived access tokens.

A service token **acts as the user who created it** (same `sub`, `email`,
scopes), so any resource worker guarded by `auth-verify` accepts it with no
changes — see [integrating-auth-gateway.md](./integrating-auth-gateway.md).

- Gateway: `https://auth.ethanchung.dev`
- Access-token lifetime: **3600s** (1 hour), per `ACCESS_TTL_SEC`

## Overview

```
 user (browser/CLI)            service (machine)             resource worker
        │                             │                             │
        │ 1. POST /clients            │                             │
        │    (with your access token) │                             │
        │ ◀── client_id + secret      │                             │
        │─────── hand off ──────────▶ │                             │
        │                             │ 2. POST /token              │
        │                             │    grant_type=client_       │
        │                             │    credentials              │
        │                             │ ◀── access_token (1h)       │
        │                             │ 3. Authorization: Bearer ──▶│
        │                             │                             │ requireUser() ✓
```

## Step 1 — a user mints a client

Minting requires **your own** gateway access token. Two ways to present it:

- **Browser app** on `*.ethanchung.dev`: the `__Secure-fleet_at` cookie is sent
  automatically — just `fetch("/clients", { method: "POST", credentials: "include" })`.
- **CLI / script**: pass `Authorization: Bearer <your-access-token>`. To get one
  today, complete the browser login once and copy the `__Secure-fleet_at` cookie
  value.

```bash
curl -X POST https://auth.ethanchung.dev/clients \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H "content-type: application/json" \
  -d '{"label":"ollama-caller"}'
```

Response (`201`):

```json
{
  "client_id": "svc_9Fk2…",
  "client_secret": "u7Qw…",
  "label": "ollama-caller",
  "created_at": "2026-07-15T22:40:00.000Z"
}
```

> ⚠️ The `client_secret` is shown **only here, once**. It is stored hashed
> (SHA-256) and can never be retrieved again. If you lose it, revoke the client
> and mint a new one. `label` is optional — a human-readable tag for `GET /clients`.

Store `client_id` + `client_secret` wherever the service keeps its secrets
(a Worker secret via `wrangler secret put`, an env var, a vault, etc.).

## Step 2 — the service exchanges credentials for a token

The service (no user, no cookies) calls the token endpoint with an
`application/x-www-form-urlencoded` body:

```bash
curl -X POST https://auth.ethanchung.dev/token \
  -d grant_type=client_credentials \
  -d client_id=svc_9Fk2… \
  -d client_secret=u7Qw…
```

Response (`200`):

```json
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 3600 }
```

Bad or unknown credentials return `401 { "error": "invalid_client" }`.

The `access_token` is a normal EdDSA JWT. Besides the usual user claims it
carries two markers so a resource worker can spot automated calls if it wants:

```jsonc
{
  "sub": "gh|123", "email": "you@example.com", "name": "You",
  "scopes": ["read:user", "user:email"],
  "token_use": "service",   // marks a service-minted token
  "client_id": "svc_9Fk2…", // which client minted it
  "iss": "https://auth.ethanchung.dev", "aud": "fleet",
  "iat": …, "exp": …, "jti": "…"
}
```

## Step 3 — call resource workers

Send the token as a bearer header, exactly like a user token:

```bash
curl https://some-service.ethanchung.dev/data \
  -H "authorization: Bearer <access_token>"
```

The resource worker's `requireUser(request, AUTH)` verifies it offline and
returns the owning user's `{ sub, email, name, scopes }`.

## Handling expiry

There is **no refresh token** for this grant — when the token expires (1 hour),
the service simply re-runs Step 2. Cache the token and re-mint on demand:

```ts
// Minimal token cache for a service (TypeScript, works in a Worker or Node).
let cached: { token: string; expiresAt: number } | null = null;

async function getServiceToken(): Promise<string> {
  const now = Date.now();
  // Refresh 60s early to avoid using a token that expires mid-request.
  if (cached && now < cached.expiresAt - 60_000) return cached.token;

  const res = await fetch("https://auth.ethanchung.dev/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);

  const { access_token, expires_in } = await res.json();
  cached = { token: access_token, expiresAt: now + expires_in * 1000 };
  return access_token;
}
```

Then attach `Authorization: Bearer ${await getServiceToken()}` to each outbound
request.

## Listing and revoking clients

Both require your own access token (Bearer or cookie), same as minting.

```bash
# List your clients (metadata only — never the secret)
curl https://auth.ethanchung.dev/clients \
  -H "authorization: Bearer $ACCESS_TOKEN"
# => { "clients": [ { "client_id": "svc_9Fk2…", "label": "ollama-caller", "created_at": "…" } ] }

# Revoke a client
curl -X DELETE https://auth.ethanchung.dev/clients/svc_9Fk2… \
  -H "authorization: Bearer $ACCESS_TOKEN"
# => 204
```

You can only see and delete **your own** clients; another user's `client_id`
returns `404`.

**Revocation is eventually consistent.** Deleting a client immediately stops it
from minting *new* tokens, but any token already issued stays valid until it
expires (≤ 1 hour) — resource workers verify offline and never phone home. If
you need an immediate cutoff, that window is the tradeoff to be aware of.

## Security notes

- Treat `client_secret` like a password: a leaked secret lets the holder mint
  tokens that act as you, with your full scopes, until you revoke the client.
- Secrets are high-entropy random and stored only as SHA-256; the gateway
  compares them in constant time.
- Prefer a **distinct client per service** so you can revoke one blast radius
  without disrupting the others, and so `GET /clients` stays legible.
