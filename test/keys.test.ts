import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { getPublicJwks, loadSigningKey } from "../src/keys";

describe("keys", () => {
	it("loads the private key and exposes its kid", async () => {
		const { key, kid } = await loadSigningKey(env);
		expect(kid).toBe("test-kid");
		expect(key).toBeDefined();
	});

	it("publishes a public JWKS without the private 'd' field", async () => {
		const jwks = await getPublicJwks(env);
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0]).toMatchObject({ kid: "test-kid", alg: "EdDSA", use: "sig", crv: "Ed25519" });
		expect(jwks.keys[0]).not.toHaveProperty("d");
	});
});
