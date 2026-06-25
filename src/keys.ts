import { type JWK, importJWK } from "jose";

interface SigningKey {
	key: CryptoKey;
	kid: string;
}

function parsePrivateJwk(env: Env): JWK & { kid: string } {
	return JSON.parse(env.SIGNING_PRIVATE_JWK) as JWK & { kid: string };
}

export async function loadSigningKey(env: Env): Promise<SigningKey> {
	const jwk = parsePrivateJwk(env);
	const key = (await importJWK(jwk, "EdDSA")) as CryptoKey;
	return { key, kid: jwk.kid };
}

export async function getPublicJwks(env: Env): Promise<{ keys: Array<Record<string, unknown>> }> {
	// Drop the private `d` component; everything else forms the public JWK.
	const { d: _d, ...current } = parsePrivateJwk(env) as unknown as Record<string, unknown>;
	const extra = env.SIGNING_PUBLIC_JWKS
		? (JSON.parse(env.SIGNING_PUBLIC_JWKS) as Array<Record<string, unknown>>)
		: [];
	return { keys: [current, ...extra] };
}
