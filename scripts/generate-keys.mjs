import { exportJWK, generateKeyPair } from "jose";
import { randomBytes } from "node:crypto";

const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
const jwk = await exportJWK(privateKey);
jwk.alg = "EdDSA";
jwk.use = "sig";
jwk.kid = randomBytes(8).toString("hex");

console.log("Set this as the SIGNING_PRIVATE_JWK secret:\n");
console.log(JSON.stringify(jwk));
