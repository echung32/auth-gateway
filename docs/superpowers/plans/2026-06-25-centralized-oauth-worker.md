# Centralized OAuth Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a central Cloudflare Worker that authenticates users via GitHub and issues short-lived EdDSA JWTs (plus rotating refresh tokens) so a fleet of first-party workers — browser apps and APIs — share seamless SSO, verifying tokens offline.

**Architecture:** A Hono worker on `auth.yourdomain.com` runs the GitHub OAuth dance (via `arctic`), mints access JWTs (via `jose`, EdDSA/Ed25519) and opaque rotating refresh tokens (stored in KV), sets cookies on the shared apex domain, and publishes a JWKS. Resource workers import a tiny shared `auth-verify` helper that verifies JWTs offline against the JWKS — the central worker is never in their request hot path. A clean `tokens`/`refresh` interface keeps `workers-oauth-provider` mountable later for third-party clients.

**Tech Stack:** TypeScript, Hono, `jose` (JWT/JWKS), `arctic` (GitHub OAuth), Cloudflare KV, Workers secrets, Vitest + `@cloudflare/vitest-pool-workers`.

## Global Constraints

- **Signing algorithm:** EdDSA (Ed25519) only. Private key lives in a Worker secret; resource workers see only the public key via JWKS.
- **Access token TTL:** 900 seconds (15 min). **Refresh token TTL:** 2592000 seconds (30 days).
- **No crypto by hand:** all JWT/JWKS operations go through `jose`; all GitHub OAuth goes through `arctic`.
- **No access-token denylist on the resource-worker hot path:** resource workers verify offline only. Revocation is enforced at refresh time.
- **Cookies:** `__Secure-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Access cookie `Domain=<COOKIE_DOMAIN>` (shared apex, e.g. `.yourdomain.com`). Refresh cookie is **host-only** to the auth worker (no `Domain`) so apps never receive it.
- **Refresh tokens rotate on every use;** reuse of a rotated token revokes the whole family (theft detection).
- **`redirect_uri` allowlist:** exact-origin match, no wildcards, checked before any redirect.
- Run `wrangler types` after any `wrangler.jsonc` binding change.
- Package manager is **pnpm**. Node test runtime is the real `workerd` via the vitest pool.

---

## File Structure

**Auth worker (`oauth-worker` repo):**
- `src/index.ts` — Hono app, route registration (replaces the starter tasks example).
- `src/config.ts` — non-secret config derived from `env` (issuer, audience, TTLs, cookie domain, allowlist).
- `src/types.ts` — shared types (`UserClaims`).
- `src/keys.ts` — load signing key from secret; build public JWKS.
- `src/tokens.ts` — issue access JWTs.
- `src/refresh.ts` — refresh-token KV storage, rotation, revocation.
- `src/state.ts` — single-use OAuth `state` storage in KV.
- `src/cookies.ts` — Set-Cookie builders + token readers.
- `src/github.ts` — `arctic` GitHub adapter; profile → `UserClaims`.
- `src/handlers.ts` — route handlers: `authorize`, `callback`, `refresh`, `logout`, `jwks`.
- `scripts/generate-keys.mjs` — one-time Ed25519 keypair generator.
- `vitest.config.ts`, `test/*.test.ts` — tests.

**Shared verify helper (`packages/auth-verify/`, published as its own GitHub repo):**
- `packages/auth-verify/src/index.ts` — `requireUser`.
- `packages/auth-verify/package.json`, `tsconfig.json`, `tsup.config.ts`.
- `packages/auth-verify/test/verify.test.ts`.

**Env shape (set in `wrangler.jsonc` `vars`, secrets, and KV):**
- Vars: `ISSUER`, `AUDIENCE`, `COOKIE_DOMAIN`, `ACCESS_TTL_SEC`, `REFRESH_TTL_SEC`, `REDIRECT_ALLOWLIST` (JSON array string), `GITHUB_REDIRECT_URI`.
- Secrets: `SIGNING_PRIVATE_JWK` (JSON string), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
- KV: `AUTH_KV`.

---

## Task 1: Project setup — dependencies, bindings, config, test harness

**Files:**
- Modify: `package.json`
- Modify: `wrangler.jsonc`
- Modify: `pnpm-workspace.yaml`
- Create: `vitest.config.ts`
- Create: `src/config.ts`
- Create: `src/types.ts`
- Delete: `src/endpoints/taskCreate.ts`, `src/endpoints/taskDelete.ts`, `src/endpoints/taskFetch.ts`, `src/endpoints/taskList.ts`
- Test: `test/config.test.ts`

**Interfaces:**
- Produces:
  - `UserClaims = { sub: string; email: string | null; name: string | null; scopes: string[] }`
  - `getConfig(env: Env): { issuer: string; audience: string; cookieDomain: string; accessTtlSec: number; refreshTtlSec: number; redirectAllowlist: string[] }`
  - `isAllowedRedirect(env: Env, redirectUri: string): boolean`

- [ ] **Step 1: Remove the starter tasks example and install dependencies**

```bash
git rm src/endpoints/taskCreate.ts src/endpoints/taskDelete.ts src/endpoints/taskFetch.ts src/endpoints/taskList.ts
pnpm remove chanfana zod
pnpm add hono jose arctic
pnpm add -D vitest @cloudflare/vitest-pool-workers
```

- [ ] **Step 2: Add the workspace packages glob**

Edit `pnpm-workspace.yaml` to add a `packages:` list (keep the existing `allowBuilds`):

```yaml
packages:
  - "packages/*"
allowBuilds:
  esbuild: true
  sharp: true
  workerd: true
```

- [ ] **Step 3: Add bindings to `wrangler.jsonc`**

Add these keys inside the top-level object (replace the all-commented bindings section):

```jsonc
	"kv_namespaces": [
		{ "binding": "AUTH_KV", "id": "REPLACE_WITH_KV_ID" }
	],
	"vars": {
		"ISSUER": "https://auth.yourdomain.com",
		"AUDIENCE": "fleet",
		"COOKIE_DOMAIN": ".yourdomain.com",
		"ACCESS_TTL_SEC": "900",
		"REFRESH_TTL_SEC": "2592000",
		"REDIRECT_ALLOWLIST": "[\"https://app1.yourdomain.com\",\"https://app2.yourdomain.com\"]",
		"GITHUB_REDIRECT_URI": "https://auth.yourdomain.com/callback"
	}
```

Create the KV namespace and paste its id over `REPLACE_WITH_KV_ID`:

```bash
pnpm wrangler kv namespace create AUTH_KV
```

- [ ] **Step 4: Regenerate env types**

Run: `pnpm wrangler types`
Expected: `worker-configuration.d.ts` now lists `AUTH_KV`, `ISSUER`, etc. on `interface Env`.

- [ ] **Step 5: Create `vitest.config.ts`**

```typescript
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// A real, valid Ed25519 private JWK used only in tests. Secrets are not in
// wrangler.jsonc, so the test harness supplies them via Miniflare bindings.
const TEST_SIGNING_JWK = JSON.stringify({
	crv: "Ed25519",
	d: "-bdIb7MCMNo7Xb8SPNI0dAgIoxMpyEdVBJLEN_uXaRk",
	x: "FxJI6vAKMXTSR84PL7fO4qK9J3zAyC_94XCdYasw4HU",
	kty: "OKP",
	alg: "EdDSA",
	use: "sig",
	kid: "test-kid",
});

export default defineWorkersConfig({
	test: {
		poolOptions: {
			workers: {
				wrangler: { configPath: "./wrangler.jsonc" },
				miniflare: {
					bindings: {
						SIGNING_PRIVATE_JWK: TEST_SIGNING_JWK,
						GITHUB_CLIENT_ID: "test-client-id",
						GITHUB_CLIENT_SECRET: "test-client-secret",
					},
				},
			},
		},
	},
});
```

- [ ] **Step 6: Add the test script to `package.json`**

Add to `"scripts"`: `"test": "vitest run"`.

- [ ] **Step 7: Write the failing config test**

Create `test/config.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { getConfig, isAllowedRedirect } from "../src/config";

describe("config", () => {
	it("parses TTLs as numbers and allowlist as array", () => {
		const cfg = getConfig(env);
		expect(cfg.accessTtlSec).toBe(900);
		expect(cfg.refreshTtlSec).toBe(2592000);
		expect(Array.isArray(cfg.redirectAllowlist)).toBe(true);
	});

	it("allows an exact-origin redirect and rejects others", () => {
		expect(isAllowedRedirect(env, "https://app1.yourdomain.com/dashboard")).toBe(true);
		expect(isAllowedRedirect(env, "https://evil.com/app1.yourdomain.com")).toBe(false);
		expect(isAllowedRedirect(env, "not a url")).toBe(false);
	});
});
```

- [ ] **Step 8: Run the test to verify it fails**

Run: `pnpm test test/config.test.ts`
Expected: FAIL — cannot find module `../src/config`.

- [ ] **Step 9: Create `src/types.ts` and `src/config.ts`**

`src/types.ts`:

```typescript
export interface UserClaims {
	sub: string;
	email: string | null;
	name: string | null;
	scopes: string[];
}
```

`src/config.ts`:

```typescript
export interface Config {
	issuer: string;
	audience: string;
	cookieDomain: string;
	accessTtlSec: number;
	refreshTtlSec: number;
	redirectAllowlist: string[];
}

export function getConfig(env: Env): Config {
	return {
		issuer: env.ISSUER,
		audience: env.AUDIENCE,
		cookieDomain: env.COOKIE_DOMAIN,
		accessTtlSec: Number(env.ACCESS_TTL_SEC),
		refreshTtlSec: Number(env.REFRESH_TTL_SEC),
		redirectAllowlist: JSON.parse(env.REDIRECT_ALLOWLIST) as string[],
	};
}

export function isAllowedRedirect(env: Env, redirectUri: string): boolean {
	let origin: string;
	try {
		origin = new URL(redirectUri).origin;
	} catch {
		return false;
	}
	return getConfig(env).redirectAllowlist.includes(origin);
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `pnpm test test/config.test.ts`
Expected: PASS (both tests).

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "chore: scaffold auth worker — deps, bindings, config, test harness"
```

---

## Task 2: Signing keys — load private key, derive public JWKS

**Files:**
- Create: `scripts/generate-keys.mjs`
- Create: `src/keys.ts`
- Test: `test/keys.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `loadSigningKey(env: Env): Promise<{ key: CryptoKey; kid: string }>`
  - `getPublicJwks(env: Env): Promise<{ keys: Array<Record<string, unknown>> }>`

- [ ] **Step 1: Write the key-generation script**

`scripts/generate-keys.mjs`:

```javascript
import { exportJWK, generateKeyPair } from "jose";
import { randomBytes } from "node:crypto";

const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
const jwk = await exportJWK(privateKey);
jwk.alg = "EdDSA";
jwk.use = "sig";
jwk.kid = randomBytes(8).toString("hex");

console.log("Set this as the SIGNING_PRIVATE_JWK secret:\n");
console.log(JSON.stringify(jwk));
```

Run it and capture the output for later (`wrangler secret put SIGNING_PRIVATE_JWK`):

```bash
node scripts/generate-keys.mjs
```

- [ ] **Step 2: Write the failing keys test**

`test/keys.test.ts` (reads the test signing key supplied by `vitest.config.ts`):

```typescript
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { getPublicJwks, loadSigningKey } from "../src/keys";

describe("keys", () => {
	it("loads the private key and exposes its kid", async () => {
		const { key, kid } = await loadSigningKey(env);
		expect(kid).toBe("test-kid");
		expect(key).toBeDefined();
	});

	it("publishes a public JWKS without the private 'd' field", async () => {
		const jwks = await getPublicJwks(env);
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0]).toMatchObject({ kid: "test-kid", alg: "EdDSA", use: "sig", crv: "Ed25519" });
		expect(jwks.keys[0]).not.toHaveProperty("d");
	});
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pnpm test test/keys.test.ts`
Expected: FAIL — cannot find module `../src/keys`.

- [ ] **Step 4: Implement `src/keys.ts`**

```typescript
import { type JWK, importJWK } from "jose";

interface SigningKey {
	key: CryptoKey;
	kid: string;
}

function parsePrivateJwk(env: Env): JWK & { kid: string } {
	return JSON.parse(env.SIGNING_PRIVATE_JWK) as JWK & { kid: string };
}

export async function loadSigningKey(env: Env): Promise<SigningKey> {
	const jwk = parsePrivateJwk(env);
	const key = (await importJWK(jwk, "EdDSA")) as CryptoKey;
	return { key, kid: jwk.kid };
}

export async function getPublicJwks(env: Env): Promise<{ keys: Array<Record<string, unknown>> }> {
	const { d, ...pub } = parsePrivateJwk(env) as Record<string, unknown>;
	return { keys: [pub] };
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pnpm test test/keys.test.ts`
Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: signing key loader, public JWKS, key-gen script"
```

---

## Task 3: Access token issuance

**Files:**
- Create: `src/tokens.ts`
- Test: `test/tokens.test.ts`

**Interfaces:**
- Consumes: `loadSigningKey` (Task 2), `getConfig` (Task 1), `UserClaims` (Task 1), `getPublicJwks` (Task 2).
- Produces: `issueAccessToken(env: Env, user: UserClaims): Promise<string>`

- [ ] **Step 1: Write the failing token test**

`test/tokens.test.ts` (verifies the issued JWT with `jose` against the public JWKS):

```typescript
import { env } from "cloudflare:workers";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { getPublicJwks } from "../src/keys";
import { issueAccessToken } from "../src/tokens";

describe("issueAccessToken", () => {
	it("mints a JWT that verifies against the public JWKS with correct claims", async () => {
		const token = await issueAccessToken(env, {
			sub: "gh|123", email: "a@b.com", name: "A B", scopes: ["read"],
		});
		const jwks = createLocalJWKSet(await getPublicJwks(env) as any);
		const { payload, protectedHeader } = await jwtVerify(token, jwks, {
			issuer: env.ISSUER,
			audience: env.AUDIENCE,
		});
		expect(protectedHeader.alg).toBe("EdDSA");
		expect(protectedHeader.kid).toBe("test-kid");
		expect(payload.sub).toBe("gh|123");
		expect(payload.email).toBe("a@b.com");
		expect(payload.scopes).toEqual(["read"]);
		expect(payload.jti).toBeDefined();
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/tokens.test.ts`
Expected: FAIL — cannot find module `../src/tokens`.

- [ ] **Step 3: Implement `src/tokens.ts`**

```typescript
import { SignJWT } from "jose";
import { getConfig } from "./config";
import { loadSigningKey } from "./keys";
import type { UserClaims } from "./types";

export async function issueAccessToken(env: Env, user: UserClaims): Promise<string> {
	const cfg = getConfig(env);
	const { key, kid } = await loadSigningKey(env);
	const jti = crypto.randomUUID();
	return new SignJWT({ email: user.email, name: user.name, scopes: user.scopes })
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

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test test/tokens.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: access token issuance with EdDSA JWTs"
```

---

## Task 4: Refresh tokens — KV storage, rotation, theft detection, revocation

**Files:**
- Create: `src/refresh.ts`
- Test: `test/refresh.test.ts`

**Interfaces:**
- Consumes: `getConfig` (Task 1).
- Produces:
  - `issueRefreshToken(env: Env, userId: string): Promise<string>` → returns `"<tokenId>.<secret>"`
  - `rotateRefreshToken(env: Env, presented: string): Promise<{ userId: string; refreshToken: string }>` (throws `Error` on invalid/expired/reuse)
  - `revokeRefreshToken(env: Env, presented: string): Promise<void>`

Storage model: `rt:<tokenId>` → `{ userId, secretHash, family }`; `fam:<family>` → current `tokenId`. Both written with `expirationTtl = refreshTtlSec`. Rotation deletes the old `rt:` key and points `fam:` at the new `tokenId`. A presented token whose `fam:` head no longer matches its `tokenId` is a reuse → the family is deleted (full revocation).

- [ ] **Step 1: Write the failing refresh test**

`test/refresh.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { issueRefreshToken, revokeRefreshToken, rotateRefreshToken } from "../src/refresh";

describe("refresh tokens", () => {
	it("issues a token that rotates and returns the same user", async () => {
		const t1 = await issueRefreshToken(env, "gh|1");
		const { userId, refreshToken: t2 } = await rotateRefreshToken(env, t1);
		expect(userId).toBe("gh|1");
		expect(t2).not.toBe(t1);
	});

	it("rejects a rotated (reused) token and revokes the whole family", async () => {
		const t1 = await issueRefreshToken(env, "gh|2");
		const { refreshToken: t2 } = await rotateRefreshToken(env, t1);
		// Reusing t1 is theft → must throw...
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow();
		// ...and must also invalidate the live token t2.
		await expect(rotateRefreshToken(env, t2)).rejects.toThrow();
	});

	it("rejects an unknown token", async () => {
		await expect(rotateRefreshToken(env, "nope.nope")).rejects.toThrow();
	});

	it("revokes on logout", async () => {
		const t1 = await issueRefreshToken(env, "gh|3");
		await revokeRefreshToken(env, t1);
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow();
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/refresh.test.ts`
Expected: FAIL — cannot find module `../src/refresh`.

- [ ] **Step 3: Implement `src/refresh.ts`**

```typescript
import { getConfig } from "./config";

interface RefreshRecord {
	userId: string;
	secretHash: string;
	family: string;
}

function randomToken(bytes: number): string {
	const buf = crypto.getRandomValues(new Uint8Array(bytes));
	return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(input: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function writeToken(env: Env, userId: string, family: string): Promise<string> {
	const ttl = getConfig(env).refreshTtlSec;
	const tokenId = randomToken(16);
	const secret = randomToken(32);
	const record: RefreshRecord = { userId, secretHash: await sha256(secret), family };
	await env.AUTH_KV.put(`rt:${tokenId}`, JSON.stringify(record), { expirationTtl: ttl });
	await env.AUTH_KV.put(`fam:${family}`, tokenId, { expirationTtl: ttl });
	return `${tokenId}.${secret}`;
}

export async function issueRefreshToken(env: Env, userId: string): Promise<string> {
	return writeToken(env, userId, randomToken(16));
}

export async function rotateRefreshToken(
	env: Env,
	presented: string,
): Promise<{ userId: string; refreshToken: string }> {
	const [tokenId, secret] = presented.split(".");
	if (!tokenId || !secret) throw new Error("malformed refresh token");

	const raw = await env.AUTH_KV.get(`rt:${tokenId}`);
	if (!raw) throw new Error("unknown refresh token");
	const record = JSON.parse(raw) as RefreshRecord;

	if ((await sha256(secret)) !== record.secretHash) throw new Error("bad refresh secret");

	const head = await env.AUTH_KV.get(`fam:${record.family}`);
	if (head !== tokenId) {
		// Reuse of a rotated token → revoke the entire family.
		await env.AUTH_KV.delete(`fam:${record.family}`);
		await env.AUTH_KV.delete(`rt:${tokenId}`);
		throw new Error("refresh token reuse detected");
	}

	await env.AUTH_KV.delete(`rt:${tokenId}`);
	const refreshToken = await writeToken(env, record.userId, record.family);
	return { userId: record.userId, refreshToken };
}

export async function revokeRefreshToken(env: Env, presented: string): Promise<void> {
	const [tokenId] = presented.split(".");
	if (!tokenId) return;
	const raw = await env.AUTH_KV.get(`rt:${tokenId}`);
	if (raw) {
		const record = JSON.parse(raw) as RefreshRecord;
		await env.AUTH_KV.delete(`fam:${record.family}`);
	}
	await env.AUTH_KV.delete(`rt:${tokenId}`);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test test/refresh.test.ts`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: rotating refresh tokens with theft detection in KV"
```

---

## Task 5: Single-use OAuth state store

**Files:**
- Create: `src/state.ts`
- Test: `test/state.test.ts`

**Interfaces:**
- Consumes: nothing (uses `AUTH_KV` directly).
- Produces:
  - `createState(env: Env, redirectUri: string): Promise<string>` (returns an opaque nonce)
  - `consumeState(env: Env, nonce: string): Promise<string>` (returns the stored `redirectUri`; throws on miss; deletes on read)

- [ ] **Step 1: Write the failing state test**

`test/state.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { consumeState, createState } from "../src/state";

describe("oauth state", () => {
	it("round-trips the redirect uri and is single-use", async () => {
		const nonce = await createState(env, "https://app1.yourdomain.com/cb");
		expect(await consumeState(env, nonce)).toBe("https://app1.yourdomain.com/cb");
		await expect(consumeState(env, nonce)).rejects.toThrow();
	});

	it("rejects an unknown state", async () => {
		await expect(consumeState(env, "bogus")).rejects.toThrow();
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/state.test.ts`
Expected: FAIL — cannot find module `../src/state`.

- [ ] **Step 3: Implement `src/state.ts`**

```typescript
const STATE_TTL_SEC = 600;

function randomNonce(): string {
	const buf = crypto.getRandomValues(new Uint8Array(24));
	return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function createState(env: Env, redirectUri: string): Promise<string> {
	const nonce = randomNonce();
	await env.AUTH_KV.put(`st:${nonce}`, redirectUri, { expirationTtl: STATE_TTL_SEC });
	return nonce;
}

export async function consumeState(env: Env, nonce: string): Promise<string> {
	const redirectUri = await env.AUTH_KV.get(`st:${nonce}`);
	if (!redirectUri) throw new Error("invalid or expired state");
	await env.AUTH_KV.delete(`st:${nonce}`);
	return redirectUri;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test test/state.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: single-use OAuth state store in KV"
```

---

## Task 6: Cookie builders and token readers

**Files:**
- Create: `src/cookies.ts`
- Test: `test/cookies.test.ts`

**Interfaces:**
- Consumes: `getConfig` (Task 1).
- Produces:
  - `accessCookie(env: Env, token: string): string`
  - `refreshCookie(env: Env, token: string): string`
  - `clearCookies(env: Env): string[]`
  - `readAccessToken(request: Request): string | null`
  - `readRefreshToken(request: Request): string | null`

Cookie names: access `__Secure-fleet_at`, refresh `__Secure-fleet_rt`. Access cookie carries `Domain=<cookieDomain>` (shared apex). Refresh cookie has **no Domain** (host-only to the auth worker). `readAccessToken` also accepts an `Authorization: Bearer` header (APIs).

- [ ] **Step 1: Write the failing cookie test**

`test/cookies.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { accessCookie, clearCookies, readAccessToken, readRefreshToken, refreshCookie } from "../src/cookies";

const env = { COOKIE_DOMAIN: ".yourdomain.com", ACCESS_TTL_SEC: "900", REFRESH_TTL_SEC: "2592000" } as unknown as Env;

describe("cookies", () => {
	it("builds a shared-apex access cookie with security attributes", () => {
		const c = accessCookie(env, "AT");
		expect(c).toContain("__Secure-fleet_at=AT");
		expect(c).toContain("Domain=.yourdomain.com");
		expect(c).toContain("HttpOnly");
		expect(c).toContain("Secure");
		expect(c).toContain("SameSite=Lax");
		expect(c).toContain("Max-Age=900");
	});

	it("builds a host-only refresh cookie (no Domain)", () => {
		const c = refreshCookie(env, "RT");
		expect(c).toContain("__Secure-fleet_rt=RT");
		expect(c).not.toContain("Domain=");
	});

	it("reads the access token from cookie or bearer header", () => {
		const fromCookie = new Request("https://x", { headers: { cookie: "__Secure-fleet_at=AAA" } });
		expect(readAccessToken(fromCookie)).toBe("AAA");
		const fromHeader = new Request("https://x", { headers: { authorization: "Bearer BBB" } });
		expect(readAccessToken(fromHeader)).toBe("BBB");
		expect(readAccessToken(new Request("https://x"))).toBeNull();
	});

	it("reads the refresh token from cookie", () => {
		const req = new Request("https://x", { headers: { cookie: "__Secure-fleet_rt=RRR" } });
		expect(readRefreshToken(req)).toBe("RRR");
	});

	it("clears both cookies", () => {
		const cleared = clearCookies(env);
		expect(cleared).toHaveLength(2);
		expect(cleared.every((c) => c.includes("Max-Age=0"))).toBe(true);
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/cookies.test.ts`
Expected: FAIL — cannot find module `../src/cookies`.

- [ ] **Step 3: Implement `src/cookies.ts`**

```typescript
import { getConfig } from "./config";

const ACCESS = "__Secure-fleet_at";
const REFRESH = "__Secure-fleet_rt";

function readCookie(request: Request, name: string): string | null {
	const header = request.headers.get("cookie");
	if (!header) return null;
	for (const part of header.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === name) return v.join("=");
	}
	return null;
}

export function accessCookie(env: Env, token: string): string {
	const cfg = getConfig(env);
	return `${ACCESS}=${token}; Domain=${cfg.cookieDomain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${cfg.accessTtlSec}`;
}

export function refreshCookie(env: Env, token: string): string {
	const cfg = getConfig(env);
	return `${REFRESH}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${cfg.refreshTtlSec}`;
}

export function clearCookies(env: Env): string[] {
	const cfg = getConfig(env);
	return [
		`${ACCESS}=; Domain=${cfg.cookieDomain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
		`${REFRESH}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
	];
}

export function readAccessToken(request: Request): string | null {
	const auth = request.headers.get("authorization");
	if (auth?.startsWith("Bearer ")) return auth.slice(7);
	return readCookie(request, ACCESS);
}

export function readRefreshToken(request: Request): string | null {
	return readCookie(request, REFRESH);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test test/cookies.test.ts`
Expected: PASS (all five tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: cookie builders and token readers"
```

---

## Task 7: GitHub identity adapter

**Files:**
- Create: `src/github.ts`
- Create: `test/helpers.ts` (shared fetch-stub helper, reused by Tasks 8 and 10)
- Test: `test/github.test.ts`

**Interfaces:**
- Consumes: `UserClaims` (Task 1).
- Produces:
  - `githubAuthUrl(env: Env, state: string): URL`
  - `exchangeGithubCode(env: Env, code: string): Promise<UserClaims>`

`exchangeGithubCode` uses `arctic` to swap the code for a GitHub access token, then fetches `https://api.github.com/user` and `https://api.github.com/user/emails` (a `User-Agent` header is required by GitHub), returning a normalized `UserClaims` with `sub = "gh|<id>"` and the primary verified email.

> **Note on outbound-fetch mocking:** this project uses `@cloudflare/vitest-pool-workers` v0.16 (Vitest 4), where the old `fetchMock` export from `cloudflare:test` **was removed**. The supported approach is to mock `globalThis.fetch` directly. Tasks 7, 8, and 10 share one small test helper for that.

- [ ] **Step 1a: Create the shared fetch-stub helper**

`test/helpers.ts`:

```typescript
import { vi } from "vitest";

export interface Route {
	match: (url: string, method: string) => boolean;
	respond: () => Response;
}

export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Replace globalThis.fetch with a router over the given routes. Call vi.unstubAllGlobals() in afterEach. */
export function stubFetch(routes: Route[]): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
			for (const r of routes) if (r.match(url, method)) return r.respond();
			throw new Error(`unexpected fetch: ${method} ${url}`);
		}),
	);
}

/** Routes that emulate the GitHub OAuth token exchange + profile + emails calls. */
export function githubRoutes(profile: { id: number; login: string; name: string | null }, email: string): Route[] {
	return [
		{
			match: (u, m) => u.includes("github.com/login/oauth/access_token") && m === "POST",
			respond: () => json({ access_token: "gho", token_type: "bearer", scope: "user:email" }),
		},
		// /user/emails MUST be matched before /user (both contain "api.github.com/user").
		{ match: (u) => u.includes("api.github.com/user/emails"), respond: () => json([{ email, primary: true, verified: true }]) },
		{ match: (u) => u.includes("api.github.com/user"), respond: () => json(profile) },
	];
}
```

- [ ] **Step 1b: Write the failing GitHub test**

`test/github.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exchangeGithubCode, githubAuthUrl } from "../src/github";
import { githubRoutes, stubFetch } from "./helpers";

afterEach(() => vi.unstubAllGlobals());

describe("github adapter", () => {
	it("builds an authorization url carrying the state", () => {
		const url = githubAuthUrl(env, "the-state");
		expect(url.hostname).toBe("github.com");
		expect(url.searchParams.get("state")).toBe("the-state");
	});

	it("exchanges a code into normalized user claims", async () => {
		stubFetch(githubRoutes({ id: 99, login: "octocat", name: "Octo Cat" }, "octo@github.com"));
		const user = await exchangeGithubCode(env, "code123");
		expect(user.sub).toBe("gh|99");
		expect(user.email).toBe("octo@github.com");
		expect(user.name).toBe("Octo Cat");
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/github.test.ts`
Expected: FAIL — cannot find module `../src/github`.

- [ ] **Step 3: Implement `src/github.ts`**

```typescript
import { GitHub } from "arctic";
import type { UserClaims } from "./types";

const SCOPES = ["read:user", "user:email"];
const UA = "oauth-worker";

function client(env: Env): GitHub {
	return new GitHub(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET, env.GITHUB_REDIRECT_URI);
}

export function githubAuthUrl(env: Env, state: string): URL {
	return client(env).createAuthorizationURL(state, SCOPES);
}

interface GithubUser { id: number; login: string; name: string | null }
interface GithubEmail { email: string; primary: boolean; verified: boolean }

export async function exchangeGithubCode(env: Env, code: string): Promise<UserClaims> {
	const tokens = await client(env).validateAuthorizationCode(code);
	const accessToken = tokens.accessToken();
	const headers = { authorization: `Bearer ${accessToken}`, "user-agent": UA, accept: "application/vnd.github+json" };

	const profile = (await (await fetch("https://api.github.com/user", { headers })).json()) as GithubUser;
	const emails = (await (await fetch("https://api.github.com/user/emails", { headers })).json()) as GithubEmail[];
	const primary = emails.find((e) => e.primary && e.verified) ?? null;

	return {
		sub: `gh|${profile.id}`,
		email: primary?.email ?? null,
		name: profile.name,
		scopes: SCOPES,
	};
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm test test/github.test.ts`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: GitHub identity adapter via arctic"
```

---

## Task 8: Route handlers and app wiring

**Files:**
- Create: `src/handlers.ts`
- Modify: `src/index.ts`
- Test: `test/handlers.test.ts`

**Interfaces:**
- Consumes: every module above (`config`, `state`, `github`, `tokens`, `refresh`, `cookies`, `keys`).
- Produces: a default-exported Hono app with routes:
  - `GET /authorize?redirect_uri=...` → 302 to GitHub (or 400 if `redirect_uri` not allowed)
  - `GET /callback?code=...&state=...` → 302 back to `redirect_uri`, sets both cookies (400 on bad state)
  - `POST /token` → 200 + new access cookie (401 on bad/expired/reused refresh)
  - `POST /logout` → 204, clears cookies
  - `GET /.well-known/jwks.json` → 200 public JWKS

- [ ] **Step 1: Write the failing handlers test**

`test/handlers.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { githubRoutes, stubFetch } from "./helpers";
import app from "../src/index";

afterEach(() => vi.unstubAllGlobals());

function ctx() {
	return { ...env, waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
}

describe("auth routes", () => {
	it("serves the public JWKS", async () => {
		const res = await app.request("/.well-known/jwks.json", {}, env, ctx());
		expect(res.status).toBe(200);
		const body = await res.json<{ keys: unknown[] }>();
		expect(body.keys.length).toBe(1);
	});

	it("rejects an off-allowlist redirect_uri on /authorize", async () => {
		const res = await app.request("/authorize?redirect_uri=https://evil.com", {}, env, ctx());
		expect(res.status).toBe(400);
	});

	it("redirects an allowed /authorize to GitHub", async () => {
		const res = await app.request("/authorize?redirect_uri=https://app1.yourdomain.com/cb", {}, env, ctx());
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toContain("github.com");
	});

	it("rejects /callback with an unknown state", async () => {
		const res = await app.request("/callback?code=c&state=bogus", {}, env, ctx());
		expect(res.status).toBe(400);
	});

	it("completes /callback: sets cookies and redirects back", async () => {
		stubFetch(githubRoutes({ id: 7, login: "u", name: "U" }, "u@x.com"));
		// Seed a valid state by calling /authorize first.
		const authRes = await app.request("/authorize?redirect_uri=https://app1.yourdomain.com/cb", {}, env, ctx());
		const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;

		const res = await app.request(`/callback?code=c&state=${state}`, {}, env, ctx());
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe("https://app1.yourdomain.com/cb");
		const cookies = res.headers.getSetCookie();
		expect(cookies.some((c) => c.startsWith("__Secure-fleet_at="))).toBe(true);
		expect(cookies.some((c) => c.startsWith("__Secure-fleet_rt="))).toBe(true);
	});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm test test/handlers.test.ts`
Expected: FAIL — cannot find module `../src/handlers` (and `src/index` has no routes yet).

- [ ] **Step 3: Implement `src/handlers.ts`**

```typescript
import type { Context } from "hono";
import { clearCookies, accessCookie, readRefreshToken, refreshCookie } from "./cookies";
import { isAllowedRedirect } from "./config";
import { exchangeGithubCode, githubAuthUrl } from "./github";
import { getPublicJwks } from "./keys";
import { issueRefreshToken, rotateRefreshToken, revokeRefreshToken } from "./refresh";
import { consumeState, createState } from "./state";
import { issueAccessToken } from "./tokens";

type Ctx = Context<{ Bindings: Env }>;

export async function authorize(c: Ctx): Promise<Response> {
	const redirectUri = c.req.query("redirect_uri") ?? "";
	if (!isAllowedRedirect(c.env, redirectUri)) return c.text("invalid redirect_uri", 400);
	const state = await createState(c.env, redirectUri);
	return c.redirect(githubAuthUrl(c.env, state).toString(), 302);
}

export async function callback(c: Ctx): Promise<Response> {
	const code = c.req.query("code");
	const state = c.req.query("state") ?? "";
	let redirectUri: string;
	try {
		redirectUri = await consumeState(c.env, state);
	} catch {
		return c.text("invalid state", 400);
	}
	if (!code) return c.text("missing code", 400);

	const user = await exchangeGithubCode(c.env, code);
	const access = await issueAccessToken(c.env, user);
	const refresh = await issueRefreshToken(c.env, user.sub);

	c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
	c.header("Set-Cookie", refreshCookie(c.env, refresh), { append: true });
	return c.redirect(redirectUri, 302);
}

export async function token(c: Ctx): Promise<Response> {
	const presented = readRefreshToken(c.req.raw);
	if (!presented) return c.text("no refresh token", 401);
	try {
		const { userId, refreshToken } = await rotateRefreshToken(c.env, presented);
		const access = await issueAccessToken(c.env, { sub: userId, email: null, name: null, scopes: [] });
		c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
		c.header("Set-Cookie", refreshCookie(c.env, refreshToken), { append: true });
		return c.body(null, 200);
	} catch {
		return c.text("invalid refresh token", 401);
	}
}

export async function logout(c: Ctx): Promise<Response> {
	const presented = readRefreshToken(c.req.raw);
	if (presented) await revokeRefreshToken(c.env, presented);
	for (const cookie of clearCookies(c.env)) c.header("Set-Cookie", cookie, { append: true });
	return c.body(null, 204);
}

export async function jwks(c: Ctx): Promise<Response> {
	return c.json(await getPublicJwks(c.env));
}
```

> Note: the `/token` refresh path issues an access token with minimal claims (`sub` only). A later enhancement can persist user profile alongside the refresh family if richer claims are needed on refresh; out of scope here.

- [ ] **Step 4: Wire routes in `src/index.ts`**

Replace the entire file with:

```typescript
import { Hono } from "hono";
import { authorize, callback, jwks, logout, token } from "./handlers";

const app = new Hono<{ Bindings: Env }>();

app.get("/authorize", authorize);
app.get("/callback", callback);
app.post("/token", token);
app.post("/logout", logout);
app.get("/.well-known/jwks.json", jwks);

export default app;
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pnpm test test/handlers.test.ts`
Expected: PASS (all five tests).

- [ ] **Step 6: Run the whole suite**

Run: `pnpm test`
Expected: PASS — every test file green.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: wire auth routes (authorize, callback, token, logout, jwks)"
```

---

## Task 9: Shared `auth-verify` package

**Files:**
- Create: `packages/auth-verify/package.json`
- Create: `packages/auth-verify/tsconfig.json`
- Create: `packages/auth-verify/tsup.config.ts`
- Create: `packages/auth-verify/src/index.ts`
- Create: `packages/auth-verify/test/verify.test.ts`
- Create: `packages/auth-verify/vitest.config.ts`

**Interfaces:**
- Consumes: nothing from the worker (standalone; `jose` is a peer dependency).
- Produces:
  - `requireUser(request: Request, opts: { jwksUrl: string; issuer: string; audience: string }): Promise<VerifiedUser>`
  - `VerifiedUser = { sub: string; email: string | null; name: string | null; scopes: string[] }`
  - On missing/invalid token, throws a `Response` with status `401`.

- [ ] **Step 1: Create the package manifest and build config**

`packages/auth-verify/package.json`:

```json
{
	"name": "auth-verify",
	"version": "1.0.0",
	"type": "module",
	"main": "./dist/index.js",
	"types": "./dist/index.d.ts",
	"exports": { ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" } },
	"files": ["dist"],
	"scripts": {
		"build": "tsup src/index.ts --format esm --dts",
		"test": "vitest run"
	},
	"peerDependencies": { "jose": "^5 || ^6" },
	"devDependencies": { "jose": "^6", "tsup": "^8", "vitest": "^3" }
}
```

`packages/auth-verify/tsconfig.json`:

```json
{
	"compilerOptions": {
		"target": "es2024",
		"module": "es2022",
		"moduleResolution": "Bundler",
		"strict": true,
		"declaration": true,
		"lib": ["es2024"],
		"types": []
	},
	"include": ["src"]
}
```

`packages/auth-verify/tsup.config.ts`:

```typescript
import { defineConfig } from "tsup";

export default defineConfig({ entry: ["src/index.ts"], format: ["esm"], dts: true, clean: true });
```

`packages/auth-verify/vitest.config.ts`:

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({ test: { environment: "node" } });
```

Install its dev deps from the repo root:

```bash
pnpm --filter auth-verify install
```

- [ ] **Step 2: Write the failing verify test**

`packages/auth-verify/test/verify.test.ts` (signs a token with a local key, serves a local JWKS, then verifies through `requireUser`):

```typescript
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { requireUser } from "../src/index";

const OPTS = { jwksUrl: "https://auth.test/jwks", issuer: "https://auth.test", audience: "fleet" };
let goodToken: string;

beforeAll(async () => {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
	const pub = await exportJWK(publicKey);
	pub.kid = "k1"; pub.alg = "EdDSA"; pub.use = "sig";

	globalThis.fetch = vi.fn(async () =>
		new Response(JSON.stringify({ keys: [pub] }), { headers: { "content-type": "application/json" } }),
	) as unknown as typeof fetch;

	goodToken = await new SignJWT({ email: "a@b.com", name: "A", scopes: ["read"] })
		.setProtectedHeader({ alg: "EdDSA", kid: "k1" })
		.setIssuer(OPTS.issuer).setAudience(OPTS.audience).setSubject("gh|1")
		.setIssuedAt().setExpirationTime("15m").sign(privateKey);
});

describe("requireUser", () => {
	it("returns claims for a valid bearer token", async () => {
		const req = new Request("https://app", { headers: { authorization: `Bearer ${goodToken}` } });
		const user = await requireUser(req, OPTS);
		expect(user.sub).toBe("gh|1");
		expect(user.email).toBe("a@b.com");
	});

	it("reads the token from the access cookie", async () => {
		const req = new Request("https://app", { headers: { cookie: `__Secure-fleet_at=${goodToken}` } });
		expect((await requireUser(req, OPTS)).sub).toBe("gh|1");
	});

	it("throws a 401 Response when no token is present", async () => {
		await expect(requireUser(new Request("https://app"), OPTS)).rejects.toMatchObject({ status: 401 });
	});

	it("throws a 401 Response for a tampered token", async () => {
		const req = new Request("https://app", { headers: { authorization: `Bearer ${goodToken}x` } });
		await expect(requireUser(req, OPTS)).rejects.toMatchObject({ status: 401 });
	});
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pnpm --filter auth-verify test`
Expected: FAIL — cannot find module `../src/index`.

- [ ] **Step 4: Implement `packages/auth-verify/src/index.ts`**

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

export interface VerifyOptions {
	jwksUrl: string;
	issuer: string;
	audience: string;
}

export interface VerifiedUser {
	sub: string;
	email: string | null;
	name: string | null;
	scopes: string[];
}

const ACCESS_COOKIE = "__Secure-fleet_at";
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: string) {
	let jwks = jwksCache.get(url);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(url));
		jwksCache.set(url, jwks);
	}
	return jwks;
}

function readToken(request: Request): string | null {
	const auth = request.headers.get("authorization");
	if (auth?.startsWith("Bearer ")) return auth.slice(7);
	const cookie = request.headers.get("cookie");
	if (!cookie) return null;
	for (const part of cookie.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === ACCESS_COOKIE) return v.join("=");
	}
	return null;
}

export async function requireUser(request: Request, opts: VerifyOptions): Promise<VerifiedUser> {
	const token = readToken(request);
	if (!token) throw new Response("Unauthorized", { status: 401 });
	try {
		const { payload } = await jwtVerify(token, getJwks(opts.jwksUrl), {
			issuer: opts.issuer,
			audience: opts.audience,
		});
		return {
			sub: String(payload.sub),
			email: (payload.email as string | null) ?? null,
			name: (payload.name as string | null) ?? null,
			scopes: (payload.scopes as string[]) ?? [],
		};
	} catch {
		throw new Response("Unauthorized", { status: 401 });
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pnpm --filter auth-verify test`
Expected: PASS (all four tests).

- [ ] **Step 6: Build the package**

Run: `pnpm --filter auth-verify build`
Expected: `packages/auth-verify/dist/index.js` and `index.d.ts` are produced.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: shared auth-verify package (requireUser, offline JWKS verify)"
```

---

## Task 10: End-to-end happy path

**Files:**
- Test: `test/e2e.test.ts`

**Interfaces:**
- Consumes: the worker app (`src/index`) and `auth-verify`'s `requireUser`.

This test drives a full login through the worker, extracts the issued access token from the Set-Cookie header, serves the worker's own JWKS to `requireUser` via a stubbed `fetch`, and asserts a protected resource accepts the real token and rejects a tampered one.

- [ ] **Step 1: Write the e2e test**

`test/e2e.test.ts`:

```typescript
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { requireUser } from "../packages/auth-verify/src/index";
import { getPublicJwks } from "../src/keys";
import app from "../src/index";
import { githubRoutes, json, stubFetch } from "./helpers";

afterEach(() => vi.unstubAllGlobals());

function ctx() {
	return { ...env, waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
}

const OPTS = { jwksUrl: "https://auth.yourdomain.com/.well-known/jwks.json", issuer: env.ISSUER, audience: env.AUDIENCE };

describe("end-to-end", () => {
	it("logs in, then a resource worker accepts the token and rejects tampering", async () => {
		// One stub serves both the GitHub OAuth calls and requireUser's JWKS fetch
		// (pointed at the worker's real public keys).
		const jwks = await getPublicJwks(env);
		stubFetch([
			...githubRoutes({ id: 42, login: "u", name: "U" }, "u@x.com"),
			{ match: (u) => u.includes("/.well-known/jwks.json"), respond: () => json(jwks) },
		]);

		const authRes = await app.request("/authorize?redirect_uri=https://app1.yourdomain.com/cb", {}, env, ctx());
		const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;

		const cbRes = await app.request(`/callback?code=c&state=${state}`, {}, env, ctx());
		const atCookie = cbRes.headers.getSetCookie().find((c) => c.startsWith("__Secure-fleet_at="))!;
		const token = atCookie.split(";")[0].split("=")[1];

		const ok = await requireUser(
			new Request("https://app1.yourdomain.com/data", { headers: { authorization: `Bearer ${token}` } }),
			OPTS,
		);
		expect(ok.sub).toBe("gh|42");

		await expect(
			requireUser(new Request("https://app1.yourdomain.com/data", { headers: { authorization: `Bearer ${token}x` } }), OPTS),
		).rejects.toMatchObject({ status: 401 });
	});
});
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `pnpm test test/e2e.test.ts`
Expected: PASS.

- [ ] **Step 3: Run the full suite**

Run: `pnpm test`
Expected: PASS — all worker tests green. Then `pnpm --filter auth-verify test` — green.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: end-to-end login + offline token verification"
```

---

## Task 11: Deploy prerequisites and docs

**Files:**
- Modify: `README.md`

**Interfaces:** none (operational).

- [ ] **Step 1: Set secrets**

```bash
node scripts/generate-keys.mjs            # copy the printed JWK
pnpm wrangler secret put SIGNING_PRIVATE_JWK   # paste the JWK
pnpm wrangler secret put GITHUB_CLIENT_ID
pnpm wrangler secret put GITHUB_CLIENT_SECRET
```

- [ ] **Step 2: Document setup in `README.md`**

Replace the starter README body with sections covering: (a) what the worker does, (b) required `vars`/secrets/KV from the Global Constraints, (c) the GitHub OAuth App callback URL (`https://auth.yourdomain.com/callback`), (d) how resource workers consume `auth-verify` via git dependency:

```markdown
## Resource workers

Install the verifier (separate repos, no npm account needed):

    pnpm add github:<you>/auth-verify#v1

Then guard a route:

    import { requireUser } from "auth-verify";

    const OPTS = {
      jwksUrl: "https://auth.yourdomain.com/.well-known/jwks.json",
      issuer: "https://auth.yourdomain.com",
      audience: "fleet",
    };

    const user = await requireUser(request, OPTS); // throws a 401 Response if invalid
```

Document that `packages/auth-verify` is developed here and pushed to its own GitHub repo (tagged `v1`) for consumers; on a 401 a browser app should redirect to `/authorize?redirect_uri=<self>`.

- [ ] **Step 3: Typecheck and full test run**

Run: `pnpm wrangler types && pnpm test && pnpm --filter auth-verify test`
Expected: types regenerate clean; all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: deployment prerequisites and resource-worker usage"
```

---

## Self-Review

**Spec coverage:**
- GitHub upstream via arctic → Task 7. ✓
- JWT/JWKS via jose, EdDSA → Tasks 2, 3. ✓
- Offline verification by resource workers → Task 9. ✓
- workers-oauth-provider seam → token/refresh modules isolated behind functions (Tasks 3, 4); documented as phase-2 in the spec. ✓
- Shared apex cookie SSO + bearer for APIs → Task 6 (cookies), Task 9 (reader). ✓
- Single-use state / CSRF → Task 5. ✓
- redirect_uri allowlist → Task 1 (`isAllowedRedirect`), enforced Task 8. ✓
- Rotating refresh tokens + theft detection → Task 4. ✓
- No hot-path denylist → resource verify (Task 9) does signature/exp/iss/aud only. ✓
- Fleet-wide audience → `AUDIENCE` var, enforced in verify. ✓
- Key rotation via kid/JWKS → kid in header (Task 3), JWKS publishes kid (Task 2), `createRemoteJWKSet` refetches on unknown kid (Task 9). ✓
- Testing strategy (vitest-pool-workers, stubbed GitHub) → Tasks throughout + Task 10 e2e. ✓
- auth-verify as git-dependency repo → Task 9 + Task 11 docs. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. The one explicit scope note (`/token` issues minimal claims) is called out, not a hidden gap.

**Type consistency:** `UserClaims`/`VerifiedUser` fields (`sub`, `email`, `name`, `scopes`) consistent across Tasks 1, 3, 7, 9. Cookie names `__Secure-fleet_at` / `__Secure-fleet_rt` consistent across Tasks 6, 8, 9, 10. Function names (`issueAccessToken`, `issueRefreshToken`, `rotateRefreshToken`, `revokeRefreshToken`, `createState`, `consumeState`, `githubAuthUrl`, `exchangeGithubCode`, `getPublicJwks`, `loadSigningKey`, `requireUser`) match between their producing task and every consumer.
