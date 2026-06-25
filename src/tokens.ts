import { SignJWT } from "jose";
import { getConfig } from "./config";
import { loadSigningKey } from "./keys";
import type { UserClaims } from "./types";

export async function issueAccessToken(env: Env, user: UserClaims): Promise<string> {
	const cfg = getConfig(env);
	const { key, kid } = await loadSigningKey(env);
	const jti = crypto.randomUUID();
	return new SignJWT({ email: user.email, name: user.name, scopes: user.scopes })
		.setProtectedHeader({ alg: "EdDSA", kid })
		.setIssuer(cfg.issuer)
		.setAudience(cfg.audience)
		.setSubject(user.sub)
		.setJti(jti)
		.setIssuedAt()
		.setExpirationTime(`${cfg.accessTtlSec}s`)
		.sign(key);
}
