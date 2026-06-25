import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { githubRoutes, json, stubFetch } from "./helpers";
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
