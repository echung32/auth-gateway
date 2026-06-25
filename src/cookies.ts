const ACCESS = "__Secure-fleet_at";
const REFRESH = "__Secure-fleet_rt";

function readCookie(request: Request, name: string): string | null {
	const header = request.headers.get("cookie");
	if (!header) return null;
	for (const part of header.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === name) return v.join("=");
	}
	return null;
}

export function accessCookie(env: Env, token: string): string {
	return `${ACCESS}=${token}; Domain=${env.COOKIE_DOMAIN}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${env.ACCESS_TTL_SEC}`;
}

export function refreshCookie(env: Env, token: string): string {
	return `${REFRESH}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${env.REFRESH_TTL_SEC}`;
}

export function clearCookies(env: Env): string[] {
	return [
		`${ACCESS}=; Domain=${env.COOKIE_DOMAIN}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
		`${REFRESH}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
	];
}

export function readAccessToken(request: Request): string | null {
	const auth = request.headers.get("authorization");
	if (auth?.startsWith("Bearer ")) return auth.slice(7);
	return readCookie(request, ACCESS);
}

export function readRefreshToken(request: Request): string | null {
	return readCookie(request, REFRESH);
}
