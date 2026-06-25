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

	it("revoke with a wrong secret does not invalidate the real token", async () => {
		const t1 = await issueRefreshToken(env, "gh|4");
		await revokeRefreshToken(env, t1.split(".")[0] + ".wrong");
		await expect(rotateRefreshToken(env, t1)).resolves.toBeDefined();
	});

	it("rotate rejects a token with extra segments", async () => {
		const t1 = await issueRefreshToken(env, "gh|5");
		await expect(rotateRefreshToken(env, t1 + ".junk")).rejects.toThrow();
	});
});
