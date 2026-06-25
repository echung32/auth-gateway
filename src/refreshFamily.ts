import { DurableObject } from "cloudflare:workers";
import { randomToken, sha256 } from "./crypto";

interface MintedToken {
	tokenId: string;
	secret: string;
	hash: string;
}

async function mintToken(): Promise<MintedToken> {
	const tokenId = randomToken(16);
	const secret = randomToken(32);
	return { tokenId, secret, hash: await sha256(secret) };
}

// One Durable Object instance per refresh-token family. A DO instance is
// single-threaded, so the head-check + rotate below is atomic — closing the race
// that an eventually-consistent KV read-then-write cannot. The DO name is the
// family id. Every issued token's secret hash is retained so reuse of any rotated
// token is detected (and proof-of-possession is checked before any revocation).
export class RefreshFamily extends DurableObject<Env> {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.ctx.storage.sql.exec(
			"CREATE TABLE IF NOT EXISTS tokens (token_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL)",
		);
	}

	private lookup(tokenId: string): string | undefined {
		const row = this.ctx.storage.sql
			.exec("SELECT secret_hash FROM tokens WHERE token_id = ?", tokenId)
			.toArray()[0] as { secret_hash: string } | undefined;
		return row?.secret_hash;
	}

	async issue(userId: string, ttlSec: number): Promise<string> {
		const { tokenId, secret, hash } = await mintToken();
		this.ctx.storage.sql.exec("INSERT INTO tokens (token_id, secret_hash) VALUES (?, ?)", tokenId, hash);
		await this.ctx.storage.put("userId", userId);
		await this.ctx.storage.put("head", tokenId);
		await this.ctx.storage.setAlarm(Date.now() + ttlSec * 1000);
		return `${tokenId}.${secret}`;
	}

	async rotate(tokenId: string, secret: string, ttlSec: number): Promise<{ userId: string; token: string }> {
		const hash = this.lookup(tokenId);
		if (!hash) throw new Error("unknown refresh token");
		if ((await sha256(secret)) !== hash) throw new Error("bad refresh secret");

		const head = await this.ctx.storage.get<string>("head");
		if (head !== tokenId) {
			// Reuse of an already-rotated token → revoke the entire family.
			await this.ctx.storage.deleteAll();
			throw new Error("refresh token reuse detected");
		}

		const userId = (await this.ctx.storage.get<string>("userId")) ?? "";
		const next = await mintToken();
		this.ctx.storage.sql.exec("INSERT INTO tokens (token_id, secret_hash) VALUES (?, ?)", next.tokenId, next.hash);
		await this.ctx.storage.put("head", next.tokenId);
		await this.ctx.storage.setAlarm(Date.now() + ttlSec * 1000);
		return { userId, token: `${next.tokenId}.${next.secret}` };
	}

	async revoke(tokenId: string, secret: string): Promise<void> {
		const hash = this.lookup(tokenId);
		if (!hash) return;
		if ((await sha256(secret)) !== hash) return;
		await this.ctx.storage.deleteAll();
	}

	async alarm(): Promise<void> {
		// Family TTL elapsed — drop all state.
		await this.ctx.storage.deleteAll();
	}
}
