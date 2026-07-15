import type { UserClaims } from "./types";

export interface ServiceClient {
	client_id: string;
	secret_hash: string;
	owner: UserClaims;
	label: string | null;
	created_at: string;
}

export interface ClientSummary {
	client_id: string;
	label: string | null;
	created_at: string;
}

function b64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateClientId(): string {
	return `svc_${b64url(crypto.getRandomValues(new Uint8Array(16)))}`;
}

export function generateClientSecret(): string {
	return b64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function hashSecret(secret: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let out = 0;
	for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return out === 0;
}

const clientKey = (id: string) => `client:${id}`;
const ownerKey = (sub: string, id: string) => `owner:${sub}:${id}`;

export async function createClient(env: Env, owner: UserClaims, label: string | null): Promise<{ client: ServiceClient; secret: string }> {
	const client_id = generateClientId();
	const secret = generateClientSecret();
	const client: ServiceClient = {
		client_id,
		secret_hash: await hashSecret(secret),
		owner,
		label,
		created_at: new Date().toISOString(),
	};
	await env.CLIENTS_KV.put(clientKey(client_id), JSON.stringify(client));
	await env.CLIENTS_KV.put(ownerKey(owner.sub, client_id), "");
	return { client, secret };
}

export async function getClient(env: Env, clientId: string): Promise<ServiceClient | null> {
	const raw = await env.CLIENTS_KV.get(clientKey(clientId));
	return raw ? (JSON.parse(raw) as ServiceClient) : null;
}

export async function listClients(env: Env, ownerSub: string): Promise<ClientSummary[]> {
	const prefix = ownerKey(ownerSub, "");
	const { keys } = await env.CLIENTS_KV.list({ prefix });
	const clients = await Promise.all(keys.map((k) => getClient(env, k.name.slice(prefix.length))));
	return clients
		.filter((c): c is ServiceClient => c !== null)
		.map((c) => ({ client_id: c.client_id, label: c.label, created_at: c.created_at }));
}

export async function deleteClient(env: Env, ownerSub: string, clientId: string): Promise<boolean> {
	const client = await getClient(env, clientId);
	if (!client || client.owner.sub !== ownerSub) return false;
	await env.CLIENTS_KV.delete(clientKey(clientId));
	await env.CLIENTS_KV.delete(ownerKey(ownerSub, clientId));
	return true;
}

export async function verifyClientSecret(env: Env, clientId: string, secret: string): Promise<ServiceClient | null> {
	const client = await getClient(env, clientId);
	if (!client) return null;
	return constantTimeEqual(await hashSecret(secret), client.secret_hash) ? client : null;
}
