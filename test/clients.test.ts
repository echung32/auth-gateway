import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
	constantTimeEqual,
	createClient,
	deleteClient,
	generateClientId,
	generateClientSecret,
	getClient,
	hashSecret,
	listClients,
	verifyClientSecret,
} from "../src/clients";

const owner = { sub: "gh|1", email: "a@b.com", name: "A", scopes: ["read:user"] };

describe("clients", () => {
	it("generates svc_ ids and distinct secrets", () => {
		expect(generateClientId()).toMatch(/^svc_[A-Za-z0-9_-]+$/);
		expect(generateClientSecret()).not.toBe(generateClientSecret());
	});

	it("hashes deterministically and compares in constant time", async () => {
		expect(await hashSecret("x")).toBe(await hashSecret("x"));
		expect(constantTimeEqual("abc", "abc")).toBe(true);
		expect(constantTimeEqual("abc", "abd")).toBe(false);
		expect(constantTimeEqual("abc", "ab")).toBe(false);
	});

	it("creates, fetches, and verifies a client", async () => {
		const { client, secret } = await createClient(env, owner, "ci");
		const fetched = await getClient(env, client.client_id);
		expect(fetched?.owner.sub).toBe("gh|1");
		expect(fetched?.label).toBe("ci");
		expect(fetched?.secret_hash).not.toBe(secret); // stored hashed, not plaintext
		expect(await verifyClientSecret(env, client.client_id, secret)).not.toBeNull();
		expect(await verifyClientSecret(env, client.client_id, "wrong")).toBeNull();
		expect(await verifyClientSecret(env, "svc_missing", secret)).toBeNull();
	});

	it("lists only the owner's clients and scopes deletion by owner", async () => {
		const a = await createClient(env, { ...owner, sub: "gh|A" }, null);
		const b = await createClient(env, { ...owner, sub: "gh|B" }, null);
		const listA = await listClients(env, "gh|A");
		expect(listA.some((c) => c.client_id === a.client.client_id)).toBe(true);
		expect(listA.some((c) => c.client_id === b.client.client_id)).toBe(false);
		expect(await deleteClient(env, "gh|B", a.client.client_id)).toBe(false); // not owner
		expect(await deleteClient(env, "gh|A", a.client.client_id)).toBe(true);
		expect(await getClient(env, a.client.client_id)).toBeNull();
	});
});
