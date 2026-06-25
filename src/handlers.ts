import type { Context } from "hono";
import { clearCookies, accessCookie, readRefreshToken, refreshCookie } from "./cookies";
import { isAllowedRedirect } from "./config";
import { exchangeGithubCode, githubAuthUrl } from "./github";
import { getPublicJwks } from "./keys";
import { issueRefreshToken, rotateRefreshToken, revokeRefreshToken } from "./refresh";
import { consumeState, createState } from "./state";
import { issueAccessToken } from "./tokens";

type Ctx = Context<{ Bindings: Env }>;

export async function authorize(c: Ctx): Promise<Response> {
	const redirectUri = c.req.query("redirect_uri") ?? "";
	if (!isAllowedRedirect(c.env, redirectUri)) return c.text("invalid redirect_uri", 400);
	const state = await createState(c.env, redirectUri);
	return c.redirect(githubAuthUrl(c.env, state).toString(), 302);
}

export async function callback(c: Ctx): Promise<Response> {
	const code = c.req.query("code");
	const state = c.req.query("state") ?? "";
	let redirectUri: string;
	try {
		redirectUri = await consumeState(c.env, state);
	} catch {
		return c.text("invalid state", 400);
	}
	if (!code) return c.text("missing code", 400);

	const user = await exchangeGithubCode(c.env, code);
	const access = await issueAccessToken(c.env, user);
	const refresh = await issueRefreshToken(c.env, user.sub);

	c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
	c.header("Set-Cookie", refreshCookie(c.env, refresh), { append: true });
	return c.redirect(redirectUri, 302);
}

export async function token(c: Ctx): Promise<Response> {
	const presented = readRefreshToken(c.req.raw);
	if (!presented) return c.text("no refresh token", 401);
	try {
		const { userId, refreshToken } = await rotateRefreshToken(c.env, presented);
		const access = await issueAccessToken(c.env, { sub: userId, email: null, name: null, scopes: [] });
		c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
		c.header("Set-Cookie", refreshCookie(c.env, refreshToken), { append: true });
		return c.body(null, 200);
	} catch {
		return c.text("invalid refresh token", 401);
	}
}

export async function logout(c: Ctx): Promise<Response> {
	const presented = readRefreshToken(c.req.raw);
	if (presented) await revokeRefreshToken(c.env, presented);
	for (const cookie of clearCookies(c.env)) c.header("Set-Cookie", cookie, { append: true });
	return c.body(null, 204);
}

export async function jwks(c: Ctx): Promise<Response> {
	return c.json(await getPublicJwks(c.env));
}
