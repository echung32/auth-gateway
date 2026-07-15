# Service Credentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-service OAuth2 `client_credentials` grant so users can mint and manage machine credentials ("fleet PATs") for programmatic callers.

**Architecture:** Users create *service clients* (owned by them, stored in a new `CLIENTS_KV` namespace) via management routes authenticated by their own gateway JWT. A service exchanges its `client_id`/`client_secret` at the existing `POST /token` endpoint (new `grant_type` branch) for a short-lived EdDSA JWT that acts as the owning user (PAT-style), reusing `issueAccessToken`. Resource workers verify it via `auth-verify` unchanged.

**Tech Stack:** Cloudflare Workers, Hono, jose (EdDSA), Workers KV, Vitest (`@cloudflare/vitest-pool-workers`).

## Global Constraints

- Access token TTL is `ACCESS_TTL_SEC` = **3600** (from `wrangler.jsonc` vars; tests read this value).
- JWTs are EdDSA (`alg: "EdDSA"`, `kid`), verified offline via JWKS — never phone home.
- No refresh token on the `client_credentials` grant (RFC 6749 §4.4.3). No cookies on that path.
- Service token identity = **owning user** (PAT-style); scopes = owner's full scopes.
- Secrets stored only as SHA-256 hex; compared in constant time.
- Follow existing style: tab indentation, thin handlers in `handlers.ts`, one responsibility per `src/*.ts` module.
- Test env supplies secrets via `vitest.config.ts` Miniflare bindings; KV namespaces are provisioned by binding name (the `id` is ignored in tests).

---

### Task 1: Restore green baseline

Two assertions still expect the old 900s TTL after the bump to 3600. Fix them so the suite is green before adding features.

**Files:**
- Modify: `test/config.test.ts:8`
- Modify: `test/tokens.test.ts:26`

- [ ] **Step 1: Confirm the failures**

Run: `pnpm test`
Expected: FAIL — `test/config.test.ts` and `test/tokens.test.ts` each assert `900` but receive `3600`.

- [ ] **Step 2: Fix `test/config.test.ts`**

Change line 8 from:
```ts
		expect(cfg.accessTtlSec).toBe(900);
```
to:
```ts
		expect(cfg.accessTtlSec).toBe(3600);
```

- [ ] **Step 3: Fix `test/tokens.test.ts`**

Change line 26 from:
```ts
		expect((payload.exp as number) - (payload.iat as number)).toBe(900);
```
to:
```ts
		expect((payload.exp as number) - (payload.iat as number)).toBe(3600);
```

- [ ] **Step 4: Verify green**

Run: `pnpm test`
Expected: PASS — all suites green.

- [ ] **Step 5: Commit**

```bash
git add test/config.test.ts test/tokens.test.ts
git commit -m "test: align TTL assertions with ACCESS_TTL_SEC=3600"
```

---

### Task 2: `clients.ts` — KV CRUD, secret generation & hashing

**Files:**
- Create: `src/clients.ts`
- Test: `test/clients.test.ts`
- Modify: `wrangler.jsonc` (add `CLIENTS_KV` binding)

**Interfaces:**
- Consumes: `UserClaims` from `src/types.ts` (`{ sub: string; email: string | null; name: string | null; scopes: string[] }`), `Env.CLIENTS_KV: KVNamespace`.
- Produces:
  - `interface ServiceClient { client_id: string; secret_hash: string; owner: UserClaims; label: string | null; created_at: string }`
  - `interface ClientSummary { client_id: string; label: string | null; created_at: string }`
  - `generateClientId(): string`, `generateClientSecret(): string`
  - `hashSecret(secret: string): Promise<string>`, `constantTimeEqual(a: string, b: string): boolean`
  - `createClient(env, owner: UserClaims, label: string | null): Promise<{ client: ServiceClient; secret: string }>`
  - `getClient(env, clientId: string): Promise<ServiceClient | null>`
  - `listClients(env, ownerSub: string): Promise<ClientSummary[]>`
  - `deleteClient(env, ownerSub: string, clientId: string): Promise<boolean>`
  - `verifyClientSecret(env, clientId: string, secret: string): Promise<ServiceClient | null>`

- [ ] **Step 1: Add the `CLIENTS_KV` binding to `wrangler.jsonc`**

Change the `kv_namespaces` array (lines 17-19) to:
```jsonc
	"kv_namespaces": [
		{ "binding": "AUTH_KV", "id": "fd3b5ba4e71640ea841fb1d0cd89f643" },
		{ "binding": "CLIENTS_KV", "id": "0000000000000000000000000000cccc" }
	],
```
The `id` is a placeholder — the real namespace is created at deploy time (Task 8 docs). Tests provision by binding name and ignore it.

- [ ] **Step 2: Regenerate Worker types**

Run: `pnpm wrangler types`
Expected: `worker-configuration.d.ts` now includes `CLIENTS_KV: KVNamespace` on `Env`.
Fallback if offline: add `CLIENTS_KV: KVNamespace;` to the `Env` interface in `src/env.d.ts`.

- [ ] **Step 3: Write the failing test**

Create `test/clients.test.ts`:
```ts
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
	constantTimeEqual,
	createClient,
	deleteClient,
	generateClientId,
	generateClientSecret,
	getClient,
	hashSecret,
	listClients,
	verifyClientSecret,
} from "../src/clients";

const owner = { sub: "gh|1", email: "a@b.com", name: "A", scopes: ["read:user"] };

describe("clients", () => {
	it("generates svc_ ids and distinct secrets", () => {
		expect(generateClientId()).toMatch(/^svc_[A-Za-z0-9_-]+$/);
		expect(generateClientSecret()).not.toBe(generateClientSecret());
	});

	it("hashes deterministically and compares in constant time", async () => {
		expect(await hashSecret("x")).toBe(await hashSecret("x"));
		expect(constantTimeEqual("abc", "abc")).toBe(true);
		expect(constantTimeEqual("abc", "abd")).toBe(false);
		expect(constantTimeEqual("abc", "ab")).toBe(false);
	});

	it("creates, fetches, and verifies a client", async () => {
		const { client, secret } = await createClient(env, owner, "ci");
		const fetched = await getClient(env, client.client_id);
		expect(fetched?.owner.sub).toBe("gh|1");
		expect(fetched?.label).toBe("ci");
		expect(fetched?.secret_hash).not.toBe(secret); // stored hashed, not plaintext
		expect(await verifyClientSecret(env, client.client_id, secret)).not.toBeNull();
		expect(await verifyClientSecret(env, client.client_id, "wrong")).toBeNull();
		expect(await verifyClientSecret(env, "svc_missing", secret)).toBeNull();
	});

	it("lists only the owner's clients and scopes deletion by owner", async () => {
		const a = await createClient(env, { ...owner, sub: "gh|A" }, null);
		const b = await createClient(env, { ...owner, sub: "gh|B" }, null);
		const listA = await listClients(env, "gh|A");
		expect(listA.some((c) => c.client_id === a.client.client_id)).toBe(true);
		expect(listA.some((c) => c.client_id === b.client.client_id)).toBe(false);
		expect(await deleteClient(env, "gh|B", a.client.client_id)).toBe(false); // not owner
		expect(await deleteClient(env, "gh|A", a.client.client_id)).toBe(true);
		expect(await getClient(env, a.client.client_id)).toBeNull();
	});
});
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pnpm test test/clients.test.ts`
Expected: FAIL — cannot import from `../src/clients` (module missing).

- [ ] **Step 5: Implement `src/clients.ts`**

```ts
import type { UserClaims } from "./types";

export interface ServiceClient {
	client_id: string;
	secret_hash: string;
	owner: UserClaims;
	label: string | null;
	created_at: string;
}

export interface ClientSummary {
	client_id: string;
	label: string | null;
	created_at: string;
}

function b64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateClientId(): string {
	return `svc_${b64url(crypto.getRandomValues(new Uint8Array(16)))}`;
}

export function generateClientSecret(): string {
	return b64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function hashSecret(secret: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let out = 0;
	for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return out === 0;
}

const clientKey = (id: string) => `client:${id}`;
const ownerKey = (sub: string, id: string) => `owner:${sub}:${id}`;

export async function createClient(env: Env, owner: UserClaims, label: string | null): Promise<{ client: ServiceClient; secret: string }> {
	const client_id = generateClientId();
	const secret = generateClientSecret();
	const client: ServiceClient = {
		client_id,
		secret_hash: await hashSecret(secret),
		owner,
		label,
		created_at: new Date().toISOString(),
	};
	await env.CLIENTS_KV.put(clientKey(client_id), JSON.stringify(client));
	await env.CLIENTS_KV.put(ownerKey(owner.sub, client_id), "");
	return { client, secret };
}

export async function getClient(env: Env, clientId: string): Promise<ServiceClient | null> {
	const raw = await env.CLIENTS_KV.get(clientKey(clientId));
	return raw ? (JSON.parse(raw) as ServiceClient) : null;
}

export async function listClients(env: Env, ownerSub: string): Promise<ClientSummary[]> {
	const prefix = ownerKey(ownerSub, "");
	const { keys } = await env.CLIENTS_KV.list({ prefix });
	const clients = await Promise.all(keys.map((k) => getClient(env, k.name.slice(prefix.length))));
	return clients
		.filter((c): c is ServiceClient => c !== null)
		.map((c) => ({ client_id: c.client_id, label: c.label, created_at: c.created_at }));
}

export async function deleteClient(env: Env, ownerSub: string, clientId: string): Promise<boolean> {
	const client = await getClient(env, clientId);
	if (!client || client.owner.sub !== ownerSub) return false;
	await env.CLIENTS_KV.delete(clientKey(clientId));
	await env.CLIENTS_KV.delete(ownerKey(ownerSub, clientId));
	return true;
}

export async function verifyClientSecret(env: Env, clientId: string, secret: string): Promise<ServiceClient | null> {
	const client = await getClient(env, clientId);
	if (!client) return null;
	return constantTimeEqual(await hashSecret(secret), client.secret_hash) ? client : null;
}
```

Note: `listClients` reads the first KV `list` page (1000 keys). Per-user client counts are far below that; pagination is intentionally omitted (YAGNI).

- [ ] **Step 6: Run test to verify it passes**

Run: `pnpm test test/clients.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/clients.ts test/clients.test.ts wrangler.jsonc worker-configuration.d.ts src/env.d.ts
git commit -m "feat: service-client KV store with hashed secrets"
```

---

### Task 3: `verifyAccess.ts` — verify the gateway's own JWT

Authenticates the management routes by verifying a gateway-issued access token (Bearer or `__Secure-fleet_at` cookie) locally against the public JWKS.

**Files:**
- Create: `src/verifyAccess.ts`
- Test: `test/verifyAccess.test.ts`

**Interfaces:**
- Consumes: `readAccessToken(request): string | null` from `src/cookies.ts`, `getConfig(env)` from `src/config.ts`, `getPublicJwks(env)` from `src/keys.ts`, `UserClaims` from `src/types.ts`.
- Produces: `verifyAccessToken(env: Env, request: Request): Promise<UserClaims>` — resolves to the caller's claims, or throws a `Response` with `status: 401`.

- [ ] **Step 1: Write the failing test**

Create `test/verifyAccess.test.ts`:
```ts
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { issueAccessToken } from "../src/tokens";
import { verifyAccessToken } from "../src/verifyAccess";

const user = { sub: "gh|9", email: "u@x.com", name: "U", scopes: ["read:user"] };

function req(headers: Record<string, string>) {
	return new Request("https://auth.ethanchung.dev/clients", { headers });
}

describe("verifyAccessToken", () => {
	it("accepts a valid self-issued token via Bearer", async () => {
		const token = await issueAccessToken(env, user);
		const claims = await verifyAccessToken(env, req({ authorization: `Bearer ${token}` }));
		expect(claims.sub).toBe("gh|9");
		expect(claims.scopes).toEqual(["read:user"]);
	});

	it("accepts a valid token via the access cookie", async () => {
		const token = await issueAccessToken(env, user);
		const claims = await verifyAccessToken(env, req({ cookie: `__Secure-fleet_at=${token}` }));
		expect(claims.email).toBe("u@x.com");
	});

	it("rejects a missing token", async () => {
		await expect(verifyAccessToken(env, req({}))).rejects.toMatchObject({ status: 401 });
	});

	it("rejects a tampered token", async () => {
		const token = await issueAccessToken(env, user);
		await expect(verifyAccessToken(env, req({ authorization: `Bearer ${token}x` }))).rejects.toMatchObject({ status: 401 });
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test test/verifyAccess.test.ts`
Expected: FAIL — cannot import `../src/verifyAccess`.

- [ ] **Step 3: Implement `src/verifyAccess.ts`**

```ts
import { createLocalJWKSet, jwtVerify } from "jose";
import { getConfig } from "./config";
import { readAccessToken } from "./cookies";
import { getPublicJwks } from "./keys";
import type { UserClaims } from "./types";

function unauthorized(): Response {
	return new Response("unauthorized", { status: 401 });
}

export async function verifyAccessToken(env: Env, request: Request): Promise<UserClaims> {
	const token = readAccessToken(request);
	if (!token) throw unauthorized();
	const cfg = getConfig(env);
	// biome-ignore lint/suspicious/noExplicitAny: getPublicJwks returns a JWKS-shaped object jose accepts.
	const jwks = createLocalJWKSet((await getPublicJwks(env)) as any);
	try {
		const { payload } = await jwtVerify(token, jwks, { issuer: cfg.issuer, audience: cfg.audience });
		return {
			sub: payload.sub as string,
			email: (payload.email as string | undefined) ?? null,
			name: (payload.name as string | undefined) ?? null,
			scopes: (payload.scopes as string[] | undefined) ?? [],
		};
	} catch {
		throw unauthorized();
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test test/verifyAccess.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/verifyAccess.ts test/verifyAccess.test.ts
git commit -m "feat: verify gateway-issued access tokens locally"
```

---

### Task 4: Marker claims on `issueAccessToken`

Let the token issuer optionally stamp `token_use`/`client_id` without changing user-flow output.

**Files:**
- Modify: `src/tokens.ts`
- Test: `test/tokens.test.ts` (extend)

**Interfaces:**
- Produces: `issueAccessToken(env: Env, user: UserClaims, extra?: Record<string, unknown>): Promise<string>` — `extra` claims are merged into the JWT payload; defaults to `{}` so existing callers are unaffected.

- [ ] **Step 1: Write the failing tests**

Append to `test/tokens.test.ts` inside the `describe("issueAccessToken", …)` block:
```ts
	it("stamps marker claims when provided", async () => {
		const token = await issueAccessToken(
			env,
			{ sub: "gh|1", email: null, name: null, scopes: [] },
			{ token_use: "service", client_id: "svc_x" },
		);
		const jwks = createLocalJWKSet((await getPublicJwks(env)) as any);
		const { payload } = await jwtVerify(token, jwks, { issuer: env.ISSUER, audience: env.AUDIENCE });
		expect(payload.token_use).toBe("service");
		expect(payload.client_id).toBe("svc_x");
	});

	it("omits marker claims for user tokens", async () => {
		const token = await issueAccessToken(env, { sub: "gh|1", email: null, name: null, scopes: [] });
		const jwks = createLocalJWKSet((await getPublicJwks(env)) as any);
		const { payload } = await jwtVerify(token, jwks, { issuer: env.ISSUER, audience: env.AUDIENCE });
		expect(payload.token_use).toBeUndefined();
		expect(payload.client_id).toBeUndefined();
	});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test test/tokens.test.ts`
Expected: FAIL — `payload.token_use` is `undefined` in the first new test (extra arg ignored).

- [ ] **Step 3: Implement the change in `src/tokens.ts`**

Change the signature and the `SignJWT` payload. Replace lines 6-18:
```ts
export async function issueAccessToken(env: Env, user: UserClaims, extra: Record<string, unknown> = {}): Promise<string> {
	const cfg = getConfig(env);
	const { key, kid } = await loadSigningKey(env);
	const jti = crypto.randomUUID();
	return new SignJWT({ email: user.email, name: user.name, scopes: user.scopes, ...extra })
		.setProtectedHeader({ alg: "EdDSA", kid })
		.setIssuer(cfg.issuer)
		.setAudience(cfg.audience)
		.setSubject(user.sub)
		.setJti(jti)
		.setIssuedAt()
		.setExpirationTime(`${cfg.accessTtlSec}s`)
		.sign(key);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test test/tokens.test.ts`
Expected: PASS (all tests in the file).

- [ ] **Step 5: Commit**

```bash
git add src/tokens.ts test/tokens.test.ts
git commit -m "feat: optional marker claims on issueAccessToken"
```

---

### Task 5: Management handlers & routes (`/clients`)

Create, list, and revoke clients, authenticated by the caller's own access token.

**Files:**
- Modify: `src/handlers.ts` (add three handlers)
- Modify: `src/index.ts` (wire routes)
- Test: `test/handlers.test.ts` (extend)

**Interfaces:**
- Consumes: `verifyAccessToken` (Task 3), `createClient` / `listClients` / `deleteClient` (Task 2), `UserClaims`.
- Produces: `createClientHandler(c)`, `listClientsHandler(c)`, `deleteClientHandler(c)` — Hono handlers returning `Response`.

- [ ] **Step 1: Write the failing tests**

Append to `test/handlers.test.ts` (after the existing `describe`), and add the `issueAccessToken` import at the top (`import { issueAccessToken } from "../src/tokens";`):
```ts
describe("service-client management", () => {
	const userToken = (sub = "gh|100") =>
		issueAccessToken(env, { sub, email: "o@x.com", name: "O", scopes: ["read:user"] });

	it("rejects management routes without a token", async () => {
		expect((await app.request("/clients", { method: "POST" }, env, ctx())).status).toBe(401);
		expect((await app.request("/clients", {}, env, ctx())).status).toBe(401);
		expect((await app.request("/clients/svc_x", { method: "DELETE" }, env, ctx())).status).toBe(401);
	});

	it("creates, lists, and revokes a client scoped to the owner", async () => {
		const auth = { authorization: `Bearer ${await userToken("gh|201")}` };

		const createRes = await app.request(
			"/clients",
			{ method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ label: "ollama" }) },
			env,
			ctx(),
		);
		expect(createRes.status).toBe(201);
		const created = await createRes.json<{ client_id: string; client_secret: string; label: string }>();
		expect(created.client_id).toMatch(/^svc_/);
		expect(created.client_secret.length).toBeGreaterThan(20);
		expect(created.label).toBe("ollama");

		const listRes = await app.request("/clients", { headers: auth }, env, ctx());
		const { clients } = await listRes.json<{ clients: { client_id: string }[] }>();
		expect(clients.some((c) => c.client_id === created.client_id)).toBe(true);

		// A different user cannot delete it.
		const otherAuth = { authorization: `Bearer ${await userToken("gh|999")}` };
		const forbidden = await app.request(`/clients/${created.client_id}`, { method: "DELETE", headers: otherAuth }, env, ctx());
		expect(forbidden.status).toBe(404);

		const delRes = await app.request(`/clients/${created.client_id}`, { method: "DELETE", headers: auth }, env, ctx());
		expect(delRes.status).toBe(204);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test test/handlers.test.ts`
Expected: FAIL — `/clients` routes 404 (not wired) so status is not 401/201.

- [ ] **Step 3: Add handlers to `src/handlers.ts`**

Add imports near the top:
```ts
import { createClient, deleteClient, listClients } from "./clients";
import type { UserClaims } from "./types";
import { verifyAccessToken } from "./verifyAccess";
```

Add the three handlers at the end of the file:
```ts
async function requireCaller(c: Ctx): Promise<UserClaims | Response> {
	try {
		return await verifyAccessToken(c.env, c.req.raw);
	} catch (e) {
		return e as Response;
	}
}

export async function createClientHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	const body = await c.req.json<{ label?: string }>().catch(() => ({}) as { label?: string });
	const label = typeof body.label === "string" ? body.label : null;
	const { client, secret } = await createClient(c.env, caller, label);
	return c.json(
		{ client_id: client.client_id, client_secret: secret, label: client.label, created_at: client.created_at },
		201,
	);
}

export async function listClientsHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	return c.json({ clients: await listClients(c.env, caller.sub) });
}

export async function deleteClientHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	const ok = await deleteClient(c.env, caller.sub, c.req.param("id"));
	return ok ? c.body(null, 204) : c.text("not found", 404);
}
```

- [ ] **Step 4: Wire routes in `src/index.ts`**

Update the handler import to include the new handlers and add the routes:
```ts
import { corsPreflight } from "./cors";
import {
	authorize,
	callback,
	createClientHandler,
	deleteClientHandler,
	jwks,
	listClientsHandler,
	logout,
	token,
} from "./handlers";
```
Add after the existing route registrations (before `export default app;`):
```ts
app.post("/clients", createClientHandler);
app.get("/clients", listClientsHandler);
app.delete("/clients/:id", deleteClientHandler);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm test test/handlers.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/handlers.ts src/index.ts test/handlers.test.ts
git commit -m "feat: self-service client management routes"
```

---

### Task 6: `client_credentials` grant on `/token`

Exchange `client_id`/`client_secret` for a service JWT; leave the cookie-refresh path intact.

**Files:**
- Modify: `src/handlers.ts` (extend `token`, add `clientCredentialsGrant`)
- Test: `test/handlers.test.ts` (extend)

**Interfaces:**
- Consumes: `verifyClientSecret` (Task 2), `issueAccessToken` with marker claims (Task 4), `getConfig`.
- Produces: extended `token(c)` that dispatches `grant_type=client_credentials` (form body) to the new path; all other requests hit the unchanged refresh path.

- [ ] **Step 1: Write the failing tests**

Append to the `describe("service-client management", …)` block in `test/handlers.test.ts`:
```ts
	it("exchanges client_credentials for a service token and revocation stops it", async () => {
		const auth = { authorization: `Bearer ${await userToken("gh|300")}` };
		const created = await (
			await app.request("/clients", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: "{}" }, env, ctx())
		).json<{ client_id: string; client_secret: string }>();

		const form = new URLSearchParams({
			grant_type: "client_credentials",
			client_id: created.client_id,
			client_secret: created.client_secret,
		});
		const tokRes = await app.request(
			"/token",
			{ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() },
			env,
			ctx(),
		);
		expect(tokRes.status).toBe(200);
		const tok = await tokRes.json<{ access_token: string; token_type: string; expires_in: number }>();
		expect(tok.token_type).toBe("Bearer");
		expect(tok.expires_in).toBe(3600);
		expect(tok.access_token.split(".").length).toBe(3);

		await app.request(`/clients/${created.client_id}`, { method: "DELETE", headers: auth }, env, ctx());
		const after = await app.request(
			"/token",
			{ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() },
			env,
			ctx(),
		);
		expect(after.status).toBe(401);
	});

	it("rejects client_credentials with a bad secret", async () => {
		const auth = { authorization: `Bearer ${await userToken("gh|301")}` };
		const created = await (
			await app.request("/clients", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: "{}" }, env, ctx())
		).json<{ client_id: string }>();
		const form = new URLSearchParams({ grant_type: "client_credentials", client_id: created.client_id, client_secret: "nope" });
		const res = await app.request(
			"/token",
			{ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() },
			env,
			ctx(),
		);
		expect(res.status).toBe(401);
		expect((await res.json<{ error: string }>()).error).toBe("invalid_client");
	});

	it("leaves the cookie-refresh grant unchanged (no grant_type)", async () => {
		const res = await app.request("/token", { method: "POST" }, env, ctx());
		expect(res.status).toBe(401); // existing "no refresh token" path
	});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test test/handlers.test.ts`
Expected: FAIL — the `client_credentials` POST currently falls through to the refresh path and returns "no refresh token" (401 text, no `access_token`), so the 200/JSON assertions fail.

- [ ] **Step 3: Extend `token` in `src/handlers.ts`**

Add imports:
```ts
import { getConfig } from "./config";
import { createClient, deleteClient, listClients, verifyClientSecret } from "./clients";
```
(merge `verifyClientSecret` into the existing `./clients` import from Task 5; add `getConfig`).

Add the grant helper:
```ts
async function clientCredentialsGrant(c: Ctx, clientId: string, secret: string): Promise<Response> {
	if (!clientId || !secret) return c.json({ error: "invalid_client" }, 401);
	const client = await verifyClientSecret(c.env, clientId, secret);
	if (!client) return c.json({ error: "invalid_client" }, 401);
	const access = await issueAccessToken(c.env, client.owner, { token_use: "service", client_id: client.client_id });
	return c.json({ access_token: access, token_type: "Bearer", expires_in: getConfig(c.env).accessTtlSec }, 200);
}
```

Prepend the dispatch to the existing `token` handler (before the `const cors = …` line):
```ts
export async function token(c: Ctx): Promise<Response> {
	const contentType = c.req.header("content-type") ?? "";
	if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
		const form = await c.req.parseBody();
		if (form.grant_type === "client_credentials") {
			return clientCredentialsGrant(c, String(form.client_id ?? ""), String(form.client_secret ?? ""));
		}
	}
	// --- existing cookie-refresh path below, unchanged ---
	const cors = corsHeaders(c.env, c.req.raw);
	// … rest of the original function …
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test test/handlers.test.ts`
Expected: PASS (new and existing tests).

- [ ] **Step 5: Commit**

```bash
git add src/handlers.ts test/handlers.test.ts
git commit -m "feat: client_credentials grant on /token"
```

---

### Task 7: End-to-end — service token verified by `auth-verify`

Prove the full flow: user logs in → creates a client → exchanges credentials → `auth-verify` accepts the service token and resolves to the owner.

**Files:**
- Test: `test/e2e.test.ts` (extend)

**Interfaces:**
- Consumes: `app`, `requireUser` from `auth-verify`, `getPublicJwks`, `githubRoutes`/`json`/`stubFetch` helpers (all already imported in the file).

- [ ] **Step 1: Write the failing test**

Append inside the `describe("end-to-end", …)` block in `test/e2e.test.ts`:
```ts
	it("issues a service token via client_credentials that a resource worker accepts", async () => {
		const jwks = await getPublicJwks(env);
		stubFetch([
			...githubRoutes({ id: 55, login: "svc", name: "S" }, "s@x.com"),
			{ match: (u) => u.includes("/.well-known/jwks.json"), respond: () => json(jwks) },
		]);

		// User logs in via the browser flow.
		const authRes = await app.request("/authorize?redirect_uri=https://app1.yourdomain.com/cb", {}, env, ctx());
		const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;
		const cbRes = await app.request(`/callback?code=c&state=${state}`, {}, env, ctx());
		const at = cbRes.headers.getSetCookie().find((c) => c.startsWith("__Secure-fleet_at="))!.split(";")[0].split("=")[1];

		// User creates a service client.
		const created = await (
			await app.request(
				"/clients",
				{ method: "POST", headers: { authorization: `Bearer ${at}`, "content-type": "application/json" }, body: JSON.stringify({ label: "e2e" }) },
				env,
				ctx(),
			)
		).json<{ client_id: string; client_secret: string }>();

		// Service exchanges its credentials.
		const form = new URLSearchParams({ grant_type: "client_credentials", client_id: created.client_id, client_secret: created.client_secret });
		const tok = await (
			await app.request("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() }, env, ctx())
		).json<{ access_token: string }>();

		const user = await requireUser(
			new Request("https://app1.yourdomain.com/data", { headers: { authorization: `Bearer ${tok.access_token}` } }),
			OPTS,
		);
		expect(user.sub).toBe("gh|55");
	});
```

- [ ] **Step 2: Run test to verify it fails, then passes**

Run: `pnpm test test/e2e.test.ts`
Expected: PASS (the feature is already implemented by Tasks 2-6; this test locks the end-to-end contract). If it fails, fix the implicated task before continuing.

- [ ] **Step 3: Run the full suite + typecheck**

Run: `pnpm test && pnpm typecheck`
Expected: all suites PASS, `tsc --noEmit` clean.

- [ ] **Step 4: Commit**

```bash
git add test/e2e.test.ts
git commit -m "test: e2e service-token flow through auth-verify"
```

---

### Task 8: Documentation

**Files:**
- Modify: `README.md` (routes table, new section, deploy delta)

- [ ] **Step 1: Add the new routes to the routes table**

Under the `## Routes` table in `README.md`, add rows:
```markdown
| `POST` | `/clients` | Create a service client (fleet PAT) owned by the caller. Requires the caller's own access token (Bearer or `__Secure-fleet_at` cookie). Returns `client_id` + a one-time `client_secret`. |
| `GET` | `/clients` | List the caller's own service clients (metadata only, never the secret). |
| `DELETE` | `/clients/:id` | Revoke one of the caller's own service clients. |
```
And extend the `/token` row to note it also accepts `grant_type=client_credentials` (form body) returning a JSON `{ access_token, token_type, expires_in }`.

- [ ] **Step 2: Add a "Programmatic access (service credentials)" section**

Add after the `## Resource workers` section:
````markdown
## Programmatic access (service credentials)

Machine callers that can't run the browser OAuth flow use **service clients** —
self-service "personal access tokens" for the fleet.

1. A logged-in user creates a client (the access cookie is sent automatically by
   a browser app; a CLI passes `Authorization: Bearer <access_token>`):

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
   `requireUser` verifies it unchanged; the token **acts as the owning user**
   and carries `token_use: "service"` + `client_id` so a resource worker can
   distinguish automated calls if it wants to. Re-exchange when the token
   expires. Revoking the client (`DELETE /clients/:id`) stops new tokens;
   existing ones age out within `ACCESS_TTL_SEC`.
````

- [ ] **Step 3: Add the deploy delta**

Under `## Deploy prerequisites`, add a step to create the `CLIENTS_KV` namespace:
````markdown
### 1b. Create the service-client KV namespace

```bash
pnpm wrangler kv namespace create CLIENTS_KV
```

Paste the printed `id` into `wrangler.jsonc` → `kv_namespaces` (the `CLIENTS_KV`
entry, replacing the placeholder id).
````

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document service credentials flow and deploy step"
```

---

## Self-review notes

- **Spec coverage:** management routes (Task 5), `client_credentials` grant (Task 6), `CLIENTS_KV` dual-key model (Task 2), PAT-style marker claims (Task 4), local caller-JWT verification (Task 3), e2e (Task 7), docs + deploy delta (Task 8). Baseline fix (Task 1) is an incidental green-up.
- **Placeholders:** the KV `id` in `wrangler.jsonc` is an intentional placeholder replaced at deploy (Task 8, step 3) — flagged in Task 2.
- **Type consistency:** `UserClaims`, `ServiceClient`, `ClientSummary`, and all function signatures match across tasks; `issueAccessToken`'s optional `extra` param is backward compatible with existing call sites in `handlers.ts`.
