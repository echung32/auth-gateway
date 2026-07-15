import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { issueAccessToken } from "../src/tokens";
import { verifyAccessToken } from "../src/verifyAccess";

const user = { sub: "gh|9", email: "u@x.com", name: "U", scopes: ["read:user"] };

function req(headers: Record<string, string>) {
	return new Request("https://auth.ethanchung.dev/clients", { headers });
}

describe("verifyAccessToken", () => {
	it("accepts a valid self-issued token via Bearer", async () => {
		const token = await issueAccessToken(env, user);
		const claims = await verifyAccessToken(env, req({ authorization: `Bearer ${token}` }));
		expect(claims.sub).toBe("gh|9");
		expect(claims.scopes).toEqual(["read:user"]);
	});

	it("accepts a valid token via the access cookie", async () => {
		const token = await issueAccessToken(env, user);
		const claims = await verifyAccessToken(env, req({ cookie: `__Secure-fleet_at=${token}` }));
		expect(claims.email).toBe("u@x.com");
	});

	it("rejects a missing token", async () => {
		await expect(verifyAccessToken(env, req({}))).rejects.toMatchObject({ status: 401 });
	});

	it("rejects a tampered token", async () => {
		const token = await issueAccessToken(env, user);
		await expect(verifyAccessToken(env, req({ authorization: `Bearer ${token}x` }))).rejects.toMatchObject({ status: 401 });
	});
});
