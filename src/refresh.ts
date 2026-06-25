import { getConfig } from "./config";
import { randomToken } from "./crypto";
import type { RefreshFamily } from "./refreshFamily";

interface ParsedToken {
	family: string;
	tokenId: string;
	secret: string;
}

function parseToken(presented: string): ParsedToken | null {
	const parts = presented.split(".");
	if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;
	return { family: parts[0], tokenId: parts[1], secret: parts[2] };
}

function familyStub(env: Env, family: string): DurableObjectStub<RefreshFamily> {
	const ns = env.REFRESH_FAMILY as unknown as DurableObjectNamespace<RefreshFamily>;
	return ns.get(ns.idFromName(family));
}

export async function issueRefreshToken(env: Env, userId: string): Promise<string> {
	const family = randomToken(16);
	const token = await familyStub(env, family).issue(userId, getConfig(env).refreshTtlSec);
	return `${family}.${token}`;
}

export async function rotateRefreshToken(
	env: Env,
	presented: string,
): Promise<{ userId: string; refreshToken: string }> {
	const parsed = parseToken(presented);
	if (!parsed) throw new Error("malformed refresh token");
	const result = await familyStub(env, parsed.family).rotate(parsed.tokenId, parsed.secret, getConfig(env).refreshTtlSec);
	if (!result.ok) throw new Error("invalid refresh token");
	return { userId: result.userId, refreshToken: `${parsed.family}.${result.token}` };
}

export async function revokeRefreshToken(env: Env, presented: string): Promise<void> {
	const parsed = parseToken(presented);
	if (!parsed) return;
	await familyStub(env, parsed.family).revoke(parsed.tokenId, parsed.secret);
}
