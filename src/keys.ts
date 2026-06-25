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
	const extra: Array<Record<string, unknown>> = [];
	if (env.SIGNING_PUBLIC_JWKS) {
		const seen = new Set<unknown>([current.kid]);
		try {
			const parsed = JSON.parse(env.SIGNING_PUBLIC_JWKS);
			if (Array.isArray(parsed)) {
				for (const k of parsed) {
					if (k && typeof k === "object" && !seen.has((k as Record<string, unknown>).kid)) {
						extra.push(k as Record<string, unknown>);
						seen.add((k as Record<string, unknown>).kid);
					}
				}
			}
		} catch {
			// Malformed config: fail open to the current key rather than breaking JWKS.
		}
	}
	return { keys: [current, ...extra] };
}
