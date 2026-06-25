import { env } from "cloudflare:test";
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
