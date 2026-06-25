const STATE_TTL_SEC = 600;

function randomNonce(): string {
	const buf = crypto.getRandomValues(new Uint8Array(24));
	return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function createState(env: Env, redirectUri: string): Promise<string> {
	const nonce = randomNonce();
	await env.AUTH_KV.put(`st:${nonce}`, redirectUri, { expirationTtl: STATE_TTL_SEC });
	return nonce;
}

// Single-use is enforced by get-then-delete. This is NOT atomic on KV (which
// has no compare-and-swap), so two concurrent /callback requests carrying the
// same state could both read it before either delete lands. We accept this
// residual race deliberately: the state's purpose here is CSRF protection,
// which the unguessable nonce provides regardless, and the actual replay attack
// (double login) is independently blocked by GitHub's authorization code, which
// is itself single-use — the second code→token exchange fails at GitHub. Truly
// atomic single-use would require a Durable Object, which the design avoids.
export async function consumeState(env: Env, nonce: string): Promise<string> {
	const redirectUri = await env.AUTH_KV.get(`st:${nonce}`);
	if (!redirectUri) throw new Error("invalid or expired state");
	await env.AUTH_KV.delete(`st:${nonce}`);
	return redirectUri;
}
