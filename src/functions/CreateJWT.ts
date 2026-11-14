import { CompactSign } from "jose";
import { getPrivateKey, PRIVATE_KEY_ID } from "../config/SecurityCofing";
import { audienceHost, jwtAudience, jwtIssuer } from "../config/TokenClaims";
import type { SessionUser } from "../types";

/**
 * Signs a session token for `user`. It carries the issuer
 * (`VARIAMOS_JWT_ISSUER`) and the platform audience
 * (`VARIAMOS_JWT_AUDIENCE`), followed by the host the user goes to, when
 * one is given: `aud` is then `[platform, host]`. Given the `aud` of a
 * token being refreshed, the host is kept and the platform set again.
 */
export const createJwt = async (user: SessionUser, aud?: string | string[]) => {
  const key = getPrivateKey();

  if (!user) {
    console.error("User is undefined");
    throw new Error("No user information provided");
  }

  if (!key) {
    console.error("Private key not found in keystore");
    throw new Error("Error on jwt creation");
  }

  const { id, name, user: userName, email, roles, permissions } = user;

  const expiresInSeconds = Number(
    process.env.VARIAMOS_JWT_EXP_IN_SECONDS ?? 900,
  );
  const currentDateInSeconds = Math.floor(Date.now() / 1000);
  const host = audienceHost(aud);

  const payload = {
    sub: id,
    name,
    userName,
    email,
    roles,
    permissions,
    iat: currentDateInSeconds,
    exp: currentDateInSeconds + expiresInSeconds,
    iss: jwtIssuer(),
    aud: host ? [jwtAudience(), host] : jwtAudience(),
  };

  // Compact JWS, RS256. The protected header stays `{"alg":"RS256","kid":...}`,
  // the same bytes the previous node-jose signer produced.
  const createdToken = await new CompactSign(
    Buffer.from(JSON.stringify(payload), "utf8"),
  )
    .setProtectedHeader({ alg: "RS256", kid: PRIVATE_KEY_ID })
    .sign(key);

  return createdToken;
};
