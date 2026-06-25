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
