import jose from "node-jose";
import { getPrivateKey } from "../config/SecurityCofing";
import { SessionUser } from "../types";

export const createJwt = async (user: SessionUser, aud?: string) => {
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
    process.env.VARIAMOS_JWT_EXP_IN_SECONDS ?? 900
  );
  const currentDateInSeconds = Math.floor(Date.now() / 1000);

  const payload = {
    sub: id,
    name,
    userName,
    email,
    roles,
    permissions,
    iat: currentDateInSeconds,
    exp: currentDateInSeconds + expiresInSeconds,
    aud,
  };

  const createdToken = await jose.JWS.createSign(
    { format: "compact", alg: "RS256" },
    key
  )
    .update(JSON.stringify(payload), 'utf8')
    .final();

  return createdToken;
};
