# Service Credentials (fleet personal access tokens) — design

## Problem

The gateway can only mint tokens through the interactive GitHub browser flow
(`/authorize` → `/callback`). Programmatic callers — e.g. a service that needs
to hit an Ollama API server guarded by `auth-verify` — have no browser, no
GitHub session, and no cookie jar, so they cannot obtain a token.

The verifier side is already header-ready: `requireUser` accepts
`Authorization: Bearer <jwt>` and verifies offline via JWKS. The gap is purely
on **issuance**: there is no non-interactive way to hand a machine a valid
token.

## Goal

Add a **self-service** OAuth2 `client_credentials` grant so any authenticated
user can mint machine credentials for their own services and manage them —
essentially "personal access tokens" for the fleet.

- A user (authenticated via the existing browser flow) creates a *service
  client* and receives a `client_id` + `client_secret` (secret shown once).
- The user hands the credentials to their service. The service exchanges them
  for short-lived EdDSA JWTs via the token endpoint.
- The issued JWT **acts as the owning user** (PAT-style), so resource workers
  that already authorize on user identity work with **zero changes**.
- Users can list and revoke their own clients.

### Non-goals (v1)

- No per-client scope narrowing — the token inherits the owner's full scopes.
  (The `scopes` claim is currently cosmetic anyway; least-privilege can be added
  later without breaking this design.)
- No admin/registration console, no rate limiting, no client-secret rotation
  endpoint (revoke + re-create instead).
- No refresh tokens on this grant (per RFC 6749 §4.4.3).

## Key decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Credential storage | New KV namespace `CLIENTS_KV` | Client records are long-lived; CSRF `state` in `AUTH_KV` is ephemeral/TTL'd. Separate lifecycle → separate namespace. |
| Registration model | Self-service, authenticated by the user's own gateway JWT | Multi-user; users manage their own credentials. |
| Token identity | PAT-style — acts as the owning user | Downstream `requireUser` unchanged; matches "my token" mental model. |
| Scopes | Inherit full user scopes | YAGNI; `scopes` claim not yet enforced anywhere. |
| Keep secret→JWT exchange | Yes (do **not** hand out long-lived tokens) | Offline JWKS verification means a long-lived token is effectively un-revocable. Short JWT + re-exchange makes revocation eventual-consistent within the access TTL. |
| Client auth transport | Credentials in the token-request **body** (form-encoded) | Simplest for machine clients; `Authorization: Basic` not supported in v1. |
| Marker claims | Add `token_use: "service"` + `client_id` to issued JWT | Lets a resource worker distinguish automated calls if it ever wants to; ignored by current verifier. |

## Endpoints

### Management (authenticated by the user's own gateway access token)

Auth: read the caller's access JWT from `Authorization: Bearer <jwt>` **or** the
`__Secure-fleet_at` cookie, verified **locally** against the gateway's own
public key (issuer/audience checked). A browser UI (cookie auto-sent) and a CLI
(Bearer) both work.

| Method | Path | Behaviour |
|--------|------|-----------|
| `POST` | `/clients` | Create a service client owned by the caller. Optional JSON body `{ "label": "<string>" }`. Returns `201 { client_id, client_secret, label, created_at }` — `client_secret` is plaintext and shown **only** here. |
| `GET` | `/clients` | List the caller's own clients. Returns `200 { clients: [{ client_id, label, created_at }] }` — never the secret or its hash. |
| `DELETE` | `/clients/:id` | Revoke one of the caller's own clients. `204` on success; `404` if the id is not found **or** not owned by the caller (no ownership oracle). |

### Token exchange (no session; the service presents its credentials)

Extend the existing `POST /token` to dispatch on `grant_type`:

- `grant_type=client_credentials` with form fields `client_id` + `client_secret`
  → **new path**. On success returns
  `200 { access_token, token_type: "Bearer", expires_in }` (JSON body; no
  cookies). On bad/unknown credentials returns `401` with an OAuth-style
  `{ error: "invalid_client" }`.
- absent / any other `grant_type` → **existing** cookie-refresh path,
  unchanged and still returning refreshed `Set-Cookie` headers. Fully backward
  compatible.

The browser flow (`/authorize`, `/callback`, `/logout`) is untouched.

## Data model — `CLIENTS_KV`

Dual-keyed so we can both look up by `client_id` at exchange time and list by
owner:

- `client:<client_id>` →
  ```json
  {
    "client_id": "<opaque>",
    "secret_hash": "<sha-256 hex of client_secret>",
    "owner": { "sub": "gh|123", "email": "…", "name": "…", "scopes": ["read:user","user:email"] },
    "label": "<string|null>",
    "created_at": "<ISO-8601>"
  }
  ```
- `owner:<owner_sub>:<client_id>` → `""` (listing index; deleted on revoke)

The owner's `UserClaims` are **snapshotted at creation** and re-stamped into
every issued token, so the exchange never needs the user present.

### Identifiers & secret handling

- `client_id` = `svc_` + base64url(16 random bytes).
- `client_secret` = base64url(32 random bytes), high entropy.
- Stored only as **SHA-256** (`secret_hash`); a plain hash + constant-time
  compare is sufficient for high-entropy random secrets (no bcrypt/argon
  needed — those defend low-entropy passwords).
- `created_at` timestamps come from `new Date().toISOString()` in the handler.

## Issued token

The exchange calls the **existing `issueAccessToken`** with the owner's claims,
extended to include the marker claims:

```jsonc
{
  "iss": "<ISSUER>", "aud": "<AUDIENCE>",
  "sub": "gh|123", "email": "…", "name": "…",
  "scopes": ["read:user", "user:email"],
  "token_use": "service",          // marker — new
  "client_id": "svc_…",            // marker — new
  "iat": …, "exp": …, "jti": "…"
}
```

Signed EdDSA (`alg: EdDSA`, `kid`) exactly like user tokens. `expires_in`
mirrors `ACCESS_TTL_SEC`. No refresh token.

## Module structure

- `src/clients.ts` — `CLIENTS_KV` CRUD, `client_id`/`client_secret` generation,
  SHA-256 hashing + constant-time compare, ownership-scoped list/delete.
- `src/verifyAccess.ts` — verify the gateway's **own** access JWT locally
  (jose `jwtVerify` against the public key derived from `SIGNING_PRIVATE_JWK`,
  checking issuer + audience), reading it from Bearer header or `__Secure-fleet_at`
  cookie. Returns the caller's `UserClaims` or throws a `401` `Response`.
- `src/tokens.ts` — extend `issueAccessToken` to accept optional marker claims
  (`token_use`, `client_id`) without changing the user-flow call site's output.
- `src/handlers.ts` — thin handlers: `createClient`, `listClients`,
  `deleteClient`, and a `clientCredentialsGrant` branch inside `token`.
- `src/index.ts` — wire `POST /clients`, `GET /clients`, `DELETE /clients/:id`.
- `wrangler.jsonc` / `src/env.d.ts` — add the `CLIENTS_KV` binding.

## Error handling

- Management routes: missing/invalid/expired caller JWT → `401`. `DELETE` of a
  non-owned or missing id → `404` (uniform, no ownership oracle).
- Token exchange: unknown `client_id`, hash mismatch, or malformed body →
  `401 { error: "invalid_client" }`. Constant-time secret compare.
- Unknown `grant_type` values fall through to the existing refresh path (its own
  `401 no refresh token` if no cookie), preserving current behaviour.

## Testing

- `test/clients.test.ts` — id/secret generation shape, hashing + constant-time
  compare, create/get/list/delete against a KV stub, ownership scoping (user A
  cannot see or delete user B's client).
- `test/verifyAccess.test.ts` — accepts a valid self-issued token (Bearer and
  cookie), rejects wrong issuer/audience, expired, tampered, and missing.
- `test/handlers.test.ts` — extend: `client_credentials` success/failure,
  management routes' auth gate, backward-compat of the cookie-refresh branch.
- `test/e2e.test.ts` — extend: create a client → exchange credentials →
  `requireUser` accepts the issued token through the published `auth-verify`
  package, and the verified user equals the owner.

## Deploy delta

- `pnpm wrangler kv namespace create CLIENTS_KV`, paste id into `wrangler.jsonc`.
- `pnpm wrangler types` to regenerate `worker-configuration.d.ts`.
- README: document the three management routes, the `client_credentials`
  exchange (curl example), and a note that service tokens carry
  `token_use:"service"`.
