import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { issueRefreshToken, revokeRefreshToken, rotateRefreshToken } from "../src/refresh";

describe("refresh tokens (Durable Object)", () => {
	it("issues a 3-part token that rotates and returns the same user", async () => {
		const t1 = await issueRefreshToken(env, "gh|1");
		expect(t1.split(".")).toHaveLength(3);
		const { userId, refreshToken: t2 } = await rotateRefreshToken(env, t1);
		expect(userId).toBe("gh|1");
		expect(t2).not.toBe(t1);
	});

	it("rejects a rotated (reused) token and revokes the whole family", async () => {
		const t1 = await issueRefreshToken(env, "gh|2");
		const { refreshToken: t2 } = await rotateRefreshToken(env, t1);
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow();
		await expect(rotateRefreshToken(env, t2)).rejects.toThrow();
	});

	it("rejects an unknown token", async () => {
		await expect(rotateRefreshToken(env, "fam.nope.nope")).rejects.toThrow();
	});

	it("rejects a malformed token (wrong part count)", async () => {
		const t1 = await issueRefreshToken(env, "gh|2b");
		await expect(rotateRefreshToken(env, `${t1}.junk`)).rejects.toThrow();
	});

	it("revokes on logout", async () => {
		const t1 = await issueRefreshToken(env, "gh|3");
		await revokeRefreshToken(env, t1);
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow();
	});

	it("revoke with a wrong secret does not invalidate the real token", async () => {
		const t1 = await issueRefreshToken(env, "gh|4");
		const [family, tokenId] = t1.split(".");
		await revokeRefreshToken(env, `${family}.${tokenId}.wrong`);
		await expect(rotateRefreshToken(env, t1)).resolves.toBeTruthy();
	});
});
