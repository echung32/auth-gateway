import { createRemoteJWKSet, jwtVerify } from "jose";

export interface VerifyOptions {
	jwksUrl: string;
	issuer: string;
	audience: string;
}

export interface VerifiedUser {
	sub: string;
	email: string | null;
	name: string | null;
	scopes: string[];
}

const ACCESS_COOKIE = "__Secure-fleet_at";
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: string) {
	let jwks = jwksCache.get(url);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(url));
		jwksCache.set(url, jwks);
	}
	return jwks;
}

function readToken(request: Request): string | null {
	const auth = request.headers.get("authorization");
	if (auth?.startsWith("Bearer ")) return auth.slice(7);
	const cookie = request.headers.get("cookie");
	if (!cookie) return null;
	for (const part of cookie.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === ACCESS_COOKIE) return v.join("=");
	}
	return null;
}

export async function requireUser(request: Request, opts: VerifyOptions): Promise<VerifiedUser> {
	const token = readToken(request);
	if (!token) throw new Response("Unauthorized", { status: 401 });
	try {
		const { payload } = await jwtVerify(token, getJwks(opts.jwksUrl), {
			issuer: opts.issuer,
			audience: opts.audience,
		});
		return {
			sub: String(payload.sub),
			email: (payload.email as string | null) ?? null,
			name: (payload.name as string | null) ?? null,
			scopes: (payload.scopes as string[]) ?? [],
		};
	} catch {
		throw new Response("Unauthorized", { status: 401 });
	}
}
