export interface Config {
	issuer: string;
	audience: string;
	cookieDomain: string;
	accessTtlSec: number;
	refreshTtlSec: number;
	redirectAllowlist: string[];
}

export function getConfig(env: Env): Config {
	return {
		issuer: env.ISSUER,
		audience: env.AUDIENCE,
		cookieDomain: env.COOKIE_DOMAIN,
		accessTtlSec: Number(env.ACCESS_TTL_SEC),
		refreshTtlSec: Number(env.REFRESH_TTL_SEC),
		redirectAllowlist: JSON.parse(env.REDIRECT_ALLOWLIST) as string[],
	};
}

export function isAllowedRedirect(env: Env, redirectUri: string): boolean {
	let origin: string;
	try {
		origin = new URL(redirectUri).origin;
	} catch {
		return false;
	}
	return getConfig(env).redirectAllowlist.includes(origin);
}
