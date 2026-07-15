import type { Context } from "hono";
import { createClient, deleteClient, listClients, verifyClientSecret } from "./clients";
import { clearCookies, accessCookie, readRefreshToken, refreshCookie } from "./cookies";
import { getConfig, isAllowedRedirect } from "./config";
import { corsHeaders } from "./cors";
import { exchangeGithubCode, githubAuthUrl } from "./github";
import { getPublicJwks } from "./keys";
import { issueRefreshToken, rotateRefreshToken, revokeRefreshToken } from "./refresh";
import { consumeState, createState } from "./state";
import { issueAccessToken } from "./tokens";
import type { UserClaims } from "./types";
import { verifyAccessToken } from "./verifyAccess";

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

	let user;
	try {
		user = await exchangeGithubCode(c.env, code);
	} catch {
		return c.text("authentication failed", 401);
	}
	const access = await issueAccessToken(c.env, user);
	const refresh = await issueRefreshToken(c.env, user);

	c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
	c.header("Set-Cookie", refreshCookie(c.env, refresh), { append: true });
	return c.redirect(redirectUri, 302);
}

async function clientCredentialsGrant(c: Ctx, clientId: string, secret: string): Promise<Response> {
	if (!clientId || !secret) return c.json({ error: "invalid_client" }, 401);
	const client = await verifyClientSecret(c.env, clientId, secret);
	if (!client) return c.json({ error: "invalid_client" }, 401);
	const access = await issueAccessToken(c.env, client.owner, { token_use: "service", client_id: client.client_id });
	return c.json({ access_token: access, token_type: "Bearer", expires_in: getConfig(c.env).accessTtlSec }, 200);
}

export async function token(c: Ctx): Promise<Response> {
	const contentType = c.req.header("content-type") ?? "";
	if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
		const form = await c.req.parseBody();
		if (form.grant_type === "client_credentials") {
			return clientCredentialsGrant(c, String(form.client_id ?? ""), String(form.client_secret ?? ""));
		}
	}
	const cors = corsHeaders(c.env, c.req.raw);
	const presented = readRefreshToken(c.req.raw);
	if (!presented) {
		if (cors) for (const [k, v] of Object.entries(cors)) c.header(k, v, { append: true });
		return c.text("no refresh token", 401);
	}
	try {
		const { user, refreshToken } = await rotateRefreshToken(c.env, presented);
		const access = await issueAccessToken(c.env, user);
		c.header("Set-Cookie", accessCookie(c.env, access), { append: true });
		c.header("Set-Cookie", refreshCookie(c.env, refreshToken), { append: true });
		if (cors) for (const [k, v] of Object.entries(cors)) c.header(k, v, { append: true });
		return c.body(null, 200);
	} catch {
		if (cors) for (const [k, v] of Object.entries(cors)) c.header(k, v, { append: true });
		return c.text("invalid refresh token", 401);
	}
}

export async function logout(c: Ctx): Promise<Response> {
	const cors = corsHeaders(c.env, c.req.raw);
	const presented = readRefreshToken(c.req.raw);
	if (presented) await revokeRefreshToken(c.env, presented);
	for (const cookie of clearCookies(c.env)) c.header("Set-Cookie", cookie, { append: true });
	if (cors) for (const [k, v] of Object.entries(cors)) c.header(k, v, { append: true });
	return c.body(null, 204);
}

export async function jwks(c: Ctx): Promise<Response> {
	return c.json(await getPublicJwks(c.env));
}

async function requireCaller(c: Ctx): Promise<UserClaims | Response> {
	try {
		return await verifyAccessToken(c.env, c.req.raw);
	} catch (e) {
		return e as Response;
	}
}

export async function createClientHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	const body = await c.req.json<{ label?: string }>().catch(() => ({}) as { label?: string });
	const label = typeof body.label === "string" ? body.label : null;
	const { client, secret } = await createClient(c.env, caller, label);
	return c.json(
		{ client_id: client.client_id, client_secret: secret, label: client.label, created_at: client.created_at },
		201,
	);
}

export async function listClientsHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	return c.json({ clients: await listClients(c.env, caller.sub) });
}

export async function deleteClientHandler(c: Ctx): Promise<Response> {
	const caller = await requireCaller(c);
	if (caller instanceof Response) return caller;
	const ok = await deleteClient(c.env, caller.sub, c.req.param("id") ?? "");
	return ok ? c.body(null, 204) : c.text("not found", 404);
}
