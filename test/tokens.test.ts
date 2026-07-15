import { env } from "cloudflare:workers";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { getPublicJwks } from "../src/keys";
import { issueAccessToken } from "../src/tokens";

describe("issueAccessToken", () => {
	it("mints a JWT that verifies against the public JWKS with correct claims", async () => {
		const token = await issueAccessToken(env, {
			sub: "gh|123", email: "a@b.com", name: "A B", scopes: ["read"],
		});
		const jwks = createLocalJWKSet(await getPublicJwks(env) as any);
		const { payload, protectedHeader } = await jwtVerify(token, jwks, {
			issuer: env.ISSUER,
			audience: env.AUDIENCE,
		});
		expect(protectedHeader.alg).toBe("EdDSA");
		expect(protectedHeader.kid).toBe("test-kid");
		expect(payload.sub).toBe("gh|123");
		expect(payload.email).toBe("a@b.com");
		expect(payload.scopes).toEqual(["read"]);
		expect(payload.jti).toBeDefined();
		expect(payload.name).toBe("A B");
		expect(typeof payload.iat).toBe("number");
		expect(typeof payload.exp).toBe("number");
		expect((payload.exp as number) - (payload.iat as number)).toBe(3600);
	});

	it("stamps marker claims when provided", async () => {
		const token = await issueAccessToken(
			env,
			{ sub: "gh|1", email: null, name: null, scopes: [] },
			{ token_use: "service", client_id: "svc_x" },
		);
		const jwks = createLocalJWKSet((await getPublicJwks(env)) as any);
		const { payload } = await jwtVerify(token, jwks, { issuer: env.ISSUER, audience: env.AUDIENCE });
		expect(payload.token_use).toBe("service");
		expect(payload.client_id).toBe("svc_x");
	});

	it("omits marker claims for user tokens", async () => {
		const token = await issueAccessToken(env, { sub: "gh|1", email: null, name: null, scopes: [] });
		const jwks = createLocalJWKSet((await getPublicJwks(env)) as any);
		const { payload } = await jwtVerify(token, jwks, { issuer: env.ISSUER, audience: env.AUDIENCE });
		expect(payload.token_use).toBeUndefined();
		expect(payload.client_id).toBeUndefined();
	});
});
