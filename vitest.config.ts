import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// A real, valid Ed25519 private JWK used only in tests. Secrets are not in
// wrangler.jsonc, so the test harness supplies them via Miniflare bindings.
const TEST_SIGNING_JWK = JSON.stringify({
	crv: "Ed25519",
	d: "-bdIb7MCMNo7Xb8SPNI0dAgIoxMpyEdVBJLEN_uXaRk",
	x: "FxJI6vAKMXTSR84PL7fO4qK9J3zAyC_94XCdYasw4HU",
	kty: "OKP",
	alg: "EdDSA",
	use: "sig",
	kid: "test-kid",
});

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.jsonc" },
			miniflare: {
				// Only true secrets need stubbing here; GITHUB_CLIENT_ID is a public
				// var supplied via wrangler.jsonc. REDIRECT_ALLOWLIST is pinned to a
				// fixed test value so the suite is independent of the production
				// allowlist in wrangler.jsonc.
				bindings: {
					SIGNING_PRIVATE_JWK: TEST_SIGNING_JWK,
					GITHUB_CLIENT_SECRET: "test-client-secret",
					REDIRECT_ALLOWLIST: '["https://app1.yourdomain.com","https://app2.yourdomain.com"]',
				},
			},
		}),
	],
});
