import { GitHub } from "arctic";
import type { UserClaims } from "./types";

const SCOPES = ["read:user", "user:email"];
const UA = "auth-gateway";

function client(env: Env): GitHub {
	return new GitHub(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET, env.GITHUB_REDIRECT_URI);
}

export function githubAuthUrl(env: Env, state: string): URL {
	return client(env).createAuthorizationURL(state, SCOPES);
}

interface GithubUser { id: number; login: string; name: string | null }
interface GithubEmail { email: string; primary: boolean; verified: boolean }

export async function exchangeGithubCode(env: Env, code: string): Promise<UserClaims> {
	const tokens = await client(env).validateAuthorizationCode(code);
	const accessToken = tokens.accessToken();
	const headers = { authorization: `Bearer ${accessToken}`, "user-agent": UA, accept: "application/vnd.github+json" };

	const profileRes = await fetch("https://api.github.com/user", { headers });
	if (!profileRes.ok) throw new Error(`github /user ${profileRes.status}`);
	const profile = (await profileRes.json()) as GithubUser;
	if (typeof profile.id !== "number") throw new Error("github profile missing id");

	const emailsRes = await fetch("https://api.github.com/user/emails", { headers });
	if (!emailsRes.ok) throw new Error(`github /user/emails ${emailsRes.status}`);
	const emails = (await emailsRes.json()) as GithubEmail[];
	const primary = emails.find((e) => e.primary && e.verified) ?? null;

	return {
		sub: `gh|${profile.id}`,
		email: primary?.email ?? null,
		name: profile.name,
		scopes: SCOPES,
	};
}
