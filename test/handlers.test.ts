import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { githubRoutes, json, stubFetch } from "./helpers";
import app from "../src/index";
import { issueAccessToken } from "../src/tokens";

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

	it("returns 401 when the GitHub code exchange fails", async () => {
		// Token endpoint replies with an OAuth error -> arctic throws -> 401.
		stubFetch([
			{
				match: (u, m) => u.includes("github.com/login/oauth/access_token") && m === "POST",
				respond: () => json({ error: "bad_verification_code" }, 400),
			},
		]);
		const authRes = await app.request("/authorize?redirect_uri=https://app1.yourdomain.com/cb", {}, env, ctx());
		const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;
		const res = await app.request(`/callback?code=bad&state=${state}`, {}, env, ctx());
		expect(res.status).toBe(401);
		expect(res.headers.getSetCookie().length).toBe(0);
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
});
