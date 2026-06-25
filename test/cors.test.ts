import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import app from "../src/index";

function ctx() {
	return { ...env, waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
}

describe("CORS for browser refresh", () => {
	it("answers preflight for an allowlisted origin with credentialed CORS", async () => {
		const res = await app.request(
			"/token",
			{ method: "OPTIONS", headers: { origin: "https://app1.yourdomain.com" } },
			env,
			ctx(),
		);
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe("https://app1.yourdomain.com");
		expect(res.headers.get("access-control-allow-credentials")).toBe("true");
		expect(res.headers.get("vary")).toContain("Origin");
	});

	it("rejects preflight from a non-allowlisted origin", async () => {
		const res = await app.request(
			"/token",
			{ method: "OPTIONS", headers: { origin: "https://evil.com" } },
			env,
			ctx(),
		);
		expect(res.status).toBe(403);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("echoes CORS headers on a POST /token from an allowlisted origin", async () => {
		const res = await app.request(
			"/token",
			{ method: "POST", headers: { origin: "https://app1.yourdomain.com" } },
			env,
			ctx(),
		);
		// No refresh cookie → 401, but CORS headers must still be present so the
		// browser can read the response.
		expect(res.headers.get("access-control-allow-origin")).toBe("https://app1.yourdomain.com");
		expect(res.headers.get("access-control-allow-credentials")).toBe("true");
	});
});

describe("CORS for /logout", () => {
	it("answers preflight for an allowlisted origin with credentialed CORS", async () => {
		const res = await app.request(
			"/logout",
			{ method: "OPTIONS", headers: { origin: "https://app1.yourdomain.com" } },
			env,
			ctx(),
		);
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe("https://app1.yourdomain.com");
		expect(res.headers.get("access-control-allow-credentials")).toBe("true");
	});

	it("POST /logout from an allowlisted origin carries CORS headers", async () => {
		const res = await app.request(
			"/logout",
			{ method: "POST", headers: { origin: "https://app1.yourdomain.com" } },
			env,
			ctx(),
		);
		expect(res.headers.get("access-control-allow-origin")).toBe("https://app1.yourdomain.com");
		expect(res.headers.get("access-control-allow-credentials")).toBe("true");
	});
});
