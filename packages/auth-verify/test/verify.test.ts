import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { requireUser } from "../src/index";

const OPTS = { jwksUrl: "https://auth.test/jwks", issuer: "https://auth.test", audience: "fleet" };
let goodToken: string;

beforeAll(async () => {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
	const pub = await exportJWK(publicKey);
	pub.kid = "k1"; pub.alg = "EdDSA"; pub.use = "sig";

	globalThis.fetch = vi.fn(async () =>
		new Response(JSON.stringify({ keys: [pub] }), { headers: { "content-type": "application/json" } }),
	) as unknown as typeof fetch;

	goodToken = await new SignJWT({ email: "a@b.com", name: "A", scopes: ["read"] })
		.setProtectedHeader({ alg: "EdDSA", kid: "k1" })
		.setIssuer(OPTS.issuer).setAudience(OPTS.audience).setSubject("gh|1")
		.setIssuedAt().setExpirationTime("15m").sign(privateKey);
});

describe("requireUser", () => {
	it("returns claims for a valid bearer token", async () => {
		const req = new Request("https://app", { headers: { authorization: `Bearer ${goodToken}` } });
		const user = await requireUser(req, OPTS);
		expect(user.sub).toBe("gh|1");
		expect(user.email).toBe("a@b.com");
	});

	it("reads the token from the access cookie", async () => {
		const req = new Request("https://app", { headers: { cookie: `__Secure-fleet_at=${goodToken}` } });
		expect((await requireUser(req, OPTS)).sub).toBe("gh|1");
	});

	it("throws a 401 Response when no token is present", async () => {
		await expect(requireUser(new Request("https://app"), OPTS)).rejects.toMatchObject({ status: 401 });
	});

	it("throws a 401 Response for a tampered token", async () => {
		const req = new Request("https://app", { headers: { authorization: `Bearer ${goodToken}x` } });
		await expect(requireUser(req, OPTS)).rejects.toMatchObject({ status: 401 });
	});
});
