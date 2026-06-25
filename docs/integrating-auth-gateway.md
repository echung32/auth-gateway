# Integrating with auth-gateway

This guide explains how a resource app (e.g. `ccusage.ethanchung.dev`) authenticates
users against **auth-gateway** (`auth.ethanchung.dev`). Drop this file into the
consuming repo's docs.

## How it works

- **auth-gateway** logs users in via GitHub and issues a short-lived **EdDSA JWT**
  access token (~15 min) plus a rotating refresh token.
- Your app **verifies the access token offline** against auth-gateway's published
  JWKS — no network call to auth-gateway on each request. You never see the signing
  key, only the public keys.
- Two cookies are set on `.ethanchung.dev` after login: `__Secure-fleet_at` (the
  access JWT, shared across all your apps for SSO) and `__Secure-fleet_rt` (the
  refresh token, host-only to `auth.ethanchung.dev`).

**Prerequisite:** your app's origin must be in auth-gateway's `REDIRECT_ALLOWLIST`
(and CORS origin allowlist). `https://ccusage.ethanchung.dev` is already added; for a
new app, add its origin to `REDIRECT_ALLOWLIST` in auth-gateway's `wrangler.jsonc`
and redeploy.

## Install the verifier

```bash
pnpm add github:echung32/auth-verify#v1
```

`auth-verify` is a tiny helper (peer-dependency: `jose`) that verifies tokens offline.

## Verify config (use these exact values)

```ts
const AUTH = {
  jwksUrl: "https://auth.ethanchung.dev/.well-known/jwks.json",
  issuer: "https://auth.ethanchung.dev",
  audience: "fleet",
};
```

## Protecting a route (any Worker)

```ts
import { requireUser } from "auth-verify";

export default {
  async fetch(request: Request): Promise<Response> {
    let user;
    try {
      user = await requireUser(request, AUTH); // reads Bearer header OR the __Secure-fleet_at cookie
    } catch (res) {
      return res as Response; // a 401 Response when the token is missing/invalid/expired
    }

    // user is verified — { sub, email, name, scopes }
    return Response.json({ hello: user.sub });
  },
};
```

`requireUser` verifies the signature, `iss`, `aud`, and `exp`, caches the JWKS in
module scope, and re-fetches automatically on an unknown `kid` (so key rotation is
transparent). On any failure it **throws a `Response` with status 401** — catch it
and return it.

`VerifiedUser`:

```ts
interface VerifiedUser {
  sub: string;          // "gh|<github-id>"
  email: string | null;
  name: string | null;
  scopes: string[];
}
```

## Browser app flow (cookie SSO)

1. User visits `ccusage.ethanchung.dev`. Your worker calls `requireUser`. If there's
   no valid cookie it returns 401.
2. On 401, redirect the browser to auth-gateway, passing where to return:

   ```
   https://auth.ethanchung.dev/authorize?redirect_uri=https://ccusage.ethanchung.dev/<return-path>
   ```

3. The user logs in with GitHub (once — the session is shared, so other
   `*.ethanchung.dev` apps are already logged in). auth-gateway redirects back to
   your `redirect_uri` with the cookies set. `requireUser` now succeeds.
4. **Refresh** (when the ~15-min access token expires): on a 401, call

   ```ts
   await fetch("https://auth.ethanchung.dev/token", {
     method: "POST",
     credentials: "include", // sends the refresh cookie
   });
   ```

   On success it sets a fresh access cookie; retry your request. (auth-gateway sends
   credentialed CORS for allowlisted origins, so the browser applies the new cookie.)
   If `/token` returns 401, the refresh token is gone — restart at step 2.

## API / programmatic flow (bearer token)

Send the access JWT in the `Authorization` header:

```
Authorization: Bearer <access-token>
```

`requireUser` reads it the same way. (How a script obtains a token: complete the
browser login once and copy the `__Secure-fleet_at` cookie value, or build a
machine-to-machine grant later — out of scope here.)

## Logout

```ts
await fetch("https://auth.ethanchung.dev/logout", { method: "POST", credentials: "include" });
```

Revokes the refresh-token family (so existing refresh tokens stop working) and clears
the cookies. The current access token remains valid until it expires (≤15 min).

## Notes

- **Audience scoping:** every app currently shares `audience: "fleet"` — a token is
  valid at any fleet app. If one app needs hard isolation, give it a dedicated
  audience in auth-gateway and set `audience` accordingly here.
- **Local dev:** point `jwksUrl`/`issuer` at your local auth-gateway
  (`wrangler dev`) if you run it locally, or keep them at production.
