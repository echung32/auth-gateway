import type { Context } from "hono";
import { getConfig } from "./config";

// Credentialed CORS headers for a cross-origin request from an allowlisted app
// origin, or null when the origin is absent or not allowed. The allowlist is the
// same first-party app origin set used for redirect validation.
export function corsHeaders(env: Env, request: Request): Record<string, string> | null {
	const origin = request.headers.get("origin");
	if (!origin || !getConfig(env).redirectAllowlist.includes(origin)) return null;
	return {
		"Access-Control-Allow-Origin": origin,
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods": "POST, OPTIONS",
		"Access-Control-Allow-Headers": "content-type",
		Vary: "Origin",
	};
}

export function corsPreflight(c: Context<{ Bindings: Env }>): Response {
	const headers = corsHeaders(c.env, c.req.raw);
	if (!headers) return c.body(null, 403);
	return new Response(null, { status: 204, headers });
}
