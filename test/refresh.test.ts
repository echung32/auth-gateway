import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { issueRefreshToken, revokeRefreshToken, rotateRefreshToken } from "../src/refresh";
import type { UserClaims } from "../src/types";

describe("refresh tokens (Durable Object)", () => {
	it("issues a 3-part token that rotates and returns the same user", async () => {
		const claims: UserClaims = { sub: "gh|1", email: "a@b.com", name: "A", scopes: ["read"] };
		const t1 = await issueRefreshToken(env, claims);
		expect(t1.split(".")).toHaveLength(3);
		const { user, refreshToken: t2 } = await rotateRefreshToken(env, t1);
		expect(user).toEqual(claims);
		expect(t2).not.toBe(t1);
	});

	it("rejects a rotated (reused) token and revokes the whole family", async () => {
		const t1 = await issueRefreshToken(env, { sub: "gh|2", email: null, name: null, scopes: [] });
		const { refreshToken: t2 } = await rotateRefreshToken(env, t1);
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow("invalid refresh token");
		await expect(rotateRefreshToken(env, t2)).rejects.toThrow("invalid refresh token");
	});

	it("rejects an unknown token", async () => {
		await expect(rotateRefreshToken(env, "fam.nope.nope")).rejects.toThrow("invalid refresh token");
	});

	it("rejects a malformed token (wrong part count)", async () => {
		const t1 = await issueRefreshToken(env, { sub: "gh|2b", email: null, name: null, scopes: [] });
		await expect(rotateRefreshToken(env, `${t1}.junk`)).rejects.toThrow("malformed refresh token");
	});

	it("revokes on logout", async () => {
		const t1 = await issueRefreshToken(env, { sub: "gh|3", email: null, name: null, scopes: [] });
		await revokeRefreshToken(env, t1);
		await expect(rotateRefreshToken(env, t1)).rejects.toThrow("invalid refresh token");
	});

	it("serializes concurrent duplicate rotation (only one succeeds; family revoked)", async () => {
		const t1 = await issueRefreshToken(env, { sub: "gh|c", email: null, name: null, scopes: [] });
		const results = await Promise.allSettled([rotateRefreshToken(env, t1), rotateRefreshToken(env, t1)]);
		const fulfilled = results.filter((r) => r.status === "fulfilled");
		expect(fulfilled).toHaveLength(1);
		// The duplicate use is treated as reuse -> family revoked -> the successor is dead too.
		const successor = (fulfilled[0] as PromiseFulfilledResult<{ refreshToken: string }>).value.refreshToken;
		await expect(rotateRefreshToken(env, successor)).rejects.toThrow();
	});

	it("revoke with a wrong secret does not invalidate the real token", async () => {
		const t1 = await issueRefreshToken(env, { sub: "gh|4", email: null, name: null, scopes: [] });
		const [family, tokenId] = t1.split(".");
		await revokeRefreshToken(env, `${family}.${tokenId}.wrong`);
		await expect(rotateRefreshToken(env, t1)).resolves.toBeTruthy();
	});
});
