import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exchangeGithubCode, githubAuthUrl } from "../src/github";
import { githubRoutes, stubFetch } from "./helpers";

afterEach(() => vi.unstubAllGlobals());

describe("github adapter", () => {
	it("builds an authorization url carrying the state", () => {
		const url = githubAuthUrl(env, "the-state");
		expect(url.hostname).toBe("github.com");
		expect(url.searchParams.get("state")).toBe("the-state");
	});

	it("exchanges a code into normalized user claims", async () => {
		stubFetch(githubRoutes({ id: 99, login: "octocat", name: "Octo Cat" }, "octo@github.com"));
		const user = await exchangeGithubCode(env, "code123");
		expect(user.sub).toBe("gh|99");
		expect(user.email).toBe("octo@github.com");
		expect(user.name).toBe("Octo Cat");
	});
});
