import { createLocalJWKSet, jwtVerify } from "jose";
import { getConfig } from "./config";
import { readAccessToken } from "./cookies";
import { getPublicJwks } from "./keys";
import type { UserClaims } from "./types";

function unauthorized(): Response {
	return new Response("unauthorized", { status: 401 });
}

export async function verifyAccessToken(env: Env, request: Request): Promise<UserClaims> {
	const token = readAccessToken(request);
	if (!token) throw unauthorized();
	const cfg = getConfig(env);
	// getPublicJwks returns a JWKS-shaped object that jose's createLocalJWKSet accepts.
	const jwks = createLocalJWKSet((await getPublicJwks(env)) as Parameters<typeof createLocalJWKSet>[0]);
	try {
		const { payload } = await jwtVerify(token, jwks, { issuer: cfg.issuer, audience: cfg.audience });
		return {
			sub: payload.sub as string,
			email: (payload.email as string | undefined) ?? null,
			name: (payload.name as string | undefined) ?? null,
			scopes: (payload.scopes as string[] | undefined) ?? [],
		};
	} catch {
		throw unauthorized();
	}
}
