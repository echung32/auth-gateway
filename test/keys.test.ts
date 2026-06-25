import { env } from "cloudflare:workers";
import { exportJWK, generateKeyPair } from "jose";
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

	it("publishes active + previous public keys when SIGNING_PUBLIC_JWKS is set", async () => {
		const { publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
		const prev = await exportJWK(publicKey);
		prev.kid = "prev-kid"; prev.alg = "EdDSA"; prev.use = "sig";
		const envWith = { ...env, SIGNING_PUBLIC_JWKS: JSON.stringify([prev]) } as unknown as Env;
		const jwks = await getPublicJwks(envWith);
		const kids = jwks.keys.map((k) => k.kid);
		expect(kids).toContain("test-kid");
		expect(kids).toContain("prev-kid");
		expect(jwks.keys).toHaveLength(2);
	});
});
