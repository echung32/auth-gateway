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
