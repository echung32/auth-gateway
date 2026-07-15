import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { requireUser } from "auth-verify";
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
});
