import { vi } from "vitest";

export interface Route {
	match: (url: string, method: string) => boolean;
	respond: () => Response;
}

export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Replace globalThis.fetch with a router over the given routes. Call vi.unstubAllGlobals() in afterEach. */
export function stubFetch(routes: Route[]): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
			for (const r of routes) if (r.match(url, method)) return r.respond();
			throw new Error(`unexpected fetch: ${method} ${url}`);
		}),
	);
}

/** Routes that emulate the GitHub OAuth token exchange + profile + emails calls. */
export function githubRoutes(profile: { id: number; login: string; name: string | null }, email: string): Route[] {
	return [
		{
			match: (u, m) => u.includes("github.com/login/oauth/access_token") && m === "POST",
			respond: () => json({ access_token: "gho", token_type: "bearer", scope: "user:email" }),
		},
		// /user/emails MUST be matched before /user (both contain "api.github.com/user").
		{ match: (u) => u.includes("api.github.com/user/emails"), respond: () => json([{ email, primary: true, verified: true }]) },
		{ match: (u) => u.includes("api.github.com/user"), respond: () => json(profile) },
	];
}
