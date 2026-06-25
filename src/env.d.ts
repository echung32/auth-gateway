// Secret bindings are provided at deploy time via `wrangler secret put` and in
// tests via the Miniflare bindings in vitest.config.ts. They are NOT in
// wrangler.jsonc, so `wrangler types` cannot generate their types. Declare them
// here; this declaration-merges onto the generated `Env` interface and survives
// `wrangler types` regeneration.
interface Env {
	SIGNING_PRIVATE_JWK: string;
	SIGNING_PUBLIC_JWKS?: string;
	GITHUB_CLIENT_SECRET: string;
}
