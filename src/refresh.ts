import { getConfig } from "./config";

interface RefreshRecord {
	userId: string;
	secretHash: string;
	family: string;
}

function randomToken(bytes: number): string {
	const buf = crypto.getRandomValues(new Uint8Array(bytes));
	return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(input: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function writeToken(env: Env, userId: string, family: string): Promise<string> {
	const ttl = getConfig(env).refreshTtlSec;
	const tokenId = randomToken(16);
	const secret = randomToken(32);
	const record: RefreshRecord = { userId, secretHash: await sha256(secret), family };
	await env.AUTH_KV.put(`rt:${tokenId}`, JSON.stringify(record), { expirationTtl: ttl });
	await env.AUTH_KV.put(`fam:${family}`, tokenId, { expirationTtl: ttl });
	return `${tokenId}.${secret}`;
}

export async function issueRefreshToken(env: Env, userId: string): Promise<string> {
	return writeToken(env, userId, randomToken(16));
}

export async function rotateRefreshToken(
	env: Env,
	presented: string,
): Promise<{ userId: string; refreshToken: string }> {
	const [tokenId, secret] = presented.split(".");
	if (!tokenId || !secret) throw new Error("malformed refresh token");

	const raw = await env.AUTH_KV.get(`rt:${tokenId}`);
	if (!raw) throw new Error("unknown refresh token");
	const record = JSON.parse(raw) as RefreshRecord;

	if ((await sha256(secret)) !== record.secretHash) throw new Error("bad refresh secret");

	const head = await env.AUTH_KV.get(`fam:${record.family}`);
	if (head !== tokenId) {
		// Reuse of a rotated token → revoke the entire family.
		await env.AUTH_KV.delete(`fam:${record.family}`);
		await env.AUTH_KV.delete(`rt:${tokenId}`);
		throw new Error("refresh token reuse detected");
	}

	// Do NOT delete rt:${tokenId} here — keeping the old record allows
	// theft detection: if it is presented again after rotation, the fam: head
	// will no longer match and the whole family will be revoked.
	const refreshToken = await writeToken(env, record.userId, record.family);
	return { userId: record.userId, refreshToken };
}

export async function revokeRefreshToken(env: Env, presented: string): Promise<void> {
	const [tokenId] = presented.split(".");
	if (!tokenId) return;
	const raw = await env.AUTH_KV.get(`rt:${tokenId}`);
	if (raw) {
		const record = JSON.parse(raw) as RefreshRecord;
		await env.AUTH_KV.delete(`fam:${record.family}`);
	}
	await env.AUTH_KV.delete(`rt:${tokenId}`);
}
