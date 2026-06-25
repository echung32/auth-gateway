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

export async function consumeState(env: Env, nonce: string): Promise<string> {
	const redirectUri = await env.AUTH_KV.get(`st:${nonce}`);
	if (!redirectUri) throw new Error("invalid or expired state");
	await env.AUTH_KV.delete(`st:${nonce}`);
	return redirectUri;
}
