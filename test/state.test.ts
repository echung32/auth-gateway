import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { consumeState, createState } from "../src/state";

describe("oauth state", () => {
	it("round-trips the redirect uri and is single-use", async () => {
		const nonce = await createState(env, "https://app1.yourdomain.com/cb");
		expect(await consumeState(env, nonce)).toBe("https://app1.yourdomain.com/cb");
		await expect(consumeState(env, nonce)).rejects.toThrow();
	});

	it("rejects an unknown state", async () => {
		await expect(consumeState(env, "bogus")).rejects.toThrow();
	});
});
