import { generateKeyPairSync, KeyObject } from "crypto";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { CompactSign } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initKeyStore } from "../config/SecurityCofing";
import { audienceHost } from "../config/TokenClaims";
import { createJwt } from "./CreateJWT";
import { validateRolesAndPermissions } from "./HasPermissions";
import { validateSession, validateToken } from "./IsAuthenticated";

const user = {
  id: "user-1",
  name: "Ada",
  user: "ada",
  email: "ada@example.com",
  roles: ["admin"],
  permissions: ["users::query"],
};

const pair = () =>
  generateKeyPairSync("rsa", { modulusLength: 2048 }) as {
    privateKey: KeyObject;
    publicKey: KeyObject;
  };
const platformKeys = pair();
const otherKeys = pair();
const now = () => Math.floor(Date.now() / 1000);

// A token signed by hand, as another issuer, an older version or an
// attacker would sign it
const signed = async (
  payload: Record<string, unknown>,
  { key = platformKeys.privateKey, alg = "RS256" } = {}
) =>
  new CompactSign(Buffer.from(JSON.stringify(payload), "utf8"))
    .setProtectedHeader({ alg, kid: "private-signing-key" })
    .sign(key);

const claims = (extra: Record<string, unknown> = {}) => ({
  sub: user.id,
  name: user.name,
  userName: user.user,
  email: user.email,
  roles: user.roles,
  permissions: user.permissions,
  iat: now(),
  exp: now() + 900,
  iss: "variamos_ms_admin",
  aud: ["variamos-platform", "app.variamos.com"],
  ...extra,
});

let dir: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "variamos-security-"));
  const privatePath = join(dir, "private.pem");
  const publicPath = join(dir, "public.pem");
  writeFileSync(
    privatePath,
    platformKeys.privateKey.export({ type: "pkcs8", format: "pem" })
  );
  writeFileSync(
    publicPath,
    platformKeys.publicKey.export({ type: "spki", format: "pem" })
  );
  vi.stubEnv("VARIAMOS_PRIVATE_KEY_PATH", privatePath);
  vi.stubEnv("VARIAMOS_PUBLIC_KEY_PATH", publicPath);
  vi.spyOn(console, "info").mockImplementation(() => {});
  await initKeyStore();
});

// The key store is loaded once: only the claim settings change per test
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

const quietly = () => {
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  return { warn, error };
};

describe("createJwt", () => {
  const payloadOf = (token: string) =>
    JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));

  it("sets the issuer and the platform audience, followed by the host", async () => {
    const payload = payloadOf(await createJwt(user, "app.variamos.com"));

    expect(payload.iss).toBe("variamos_ms_admin");
    expect(payload.aud).toEqual(["variamos-platform", "app.variamos.com"]);
    expect(payload.exp - payload.iat).toBe(900);
  });

  it("sets the platform audience alone without a host", async () => {
    expect(payloadOf(await createJwt(user)).aud).toBe("variamos-platform");
  });

  it("keeps the host of a token being refreshed, old or new", async () => {
    const refreshed = await createJwt(user, [
      "variamos-platform",
      "app.variamos.com",
    ]);
    const fromOld = await createJwt(user, "app.variamos.com");

    expect(payloadOf(refreshed).aud).toEqual([
      "variamos-platform",
      "app.variamos.com",
    ]);
    expect(payloadOf(fromOld).aud).toEqual(payloadOf(refreshed).aud);
  });

  it("follows VARIAMOS_JWT_ISSUER and VARIAMOS_JWT_AUDIENCE", async () => {
    vi.stubEnv("VARIAMOS_JWT_ISSUER", "issuer-x");
    vi.stubEnv("VARIAMOS_JWT_AUDIENCE", "audience-x");

    const payload = payloadOf(await createJwt(user, "host"));

    expect(payload.iss).toBe("issuer-x");
    expect(payload.aud).toEqual(["audience-x", "host"]);
  });

  it("keeps the protected header of the previous signer", async () => {
    const header = JSON.parse(
      Buffer.from((await createJwt(user)).split(".")[0], "base64url").toString(
        "utf8"
      )
    );
    expect(header).toEqual({ alg: "RS256", kid: "private-signing-key" });
  });
});

describe("validateToken", () => {
  it("accepts a token of createJwt in every mode", async () => {
    for (const mode of ["off", "warn", "enforce"]) {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", mode);
      const response = await validateToken(
        await createJwt(user, "app.variamos.com")
      );
      expect(response.errorCode).toBeUndefined();
      expect(response.data?.sub).toBe("user-1");
    }
  });

  it("refuses a token signed by another key", async () => {
    quietly();
    const token = await signed(claims(), { key: otherKeys.privateKey });

    expect((await validateToken(token)).errorCode).toBe(401);
  });

  it("refuses an algorithm other than RS256, even signed by the platform key", async () => {
    quietly();
    const token = await signed(claims(), { alg: "RS384" });

    expect((await validateToken(token)).errorCode).toBe(401);
  });

  it("refuses a token signed with a shared secret (HS256)", async () => {
    quietly();
    const secret = new Uint8Array(32).fill(7);
    const token = await new CompactSign(
      Buffer.from(JSON.stringify(claims()), "utf8")
    )
      .setProtectedHeader({ alg: "HS256" })
      .sign(secret);

    expect((await validateToken(token)).errorCode).toBe(401);
  });

  it("refuses a missing or malformed token", async () => {
    quietly();
    expect((await validateToken()).errorCode).toBe(401);
    expect((await validateToken("not.a.token")).errorCode).toBe(401);
  });

  describe("issuer and audience, by VARIAMOS_JWT_CLAIMS_MODE", () => {
    // A token issued before 0.0.17: no issuer, the host as audience
    const oldToken = () =>
      signed(claims({ iss: undefined, aud: "app.variamos.com" }));

    it("off: accepts a token without them, silently", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "off");
      const { warn } = quietly();

      expect((await validateToken(await oldToken())).errorCode).toBeUndefined();
      expect(warn).not.toHaveBeenCalled();
    });

    it("warn, the default: accepts it and says why", async () => {
      const { warn } = quietly();

      const response = await validateToken(await oldToken());

      expect(response.errorCode).toBeUndefined();
      expect(warn).toHaveBeenCalledWith("JWT accepted although no issuer (iss)");
    });

    it("enforce: refuses a token without issuer", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
      quietly();

      expect((await validateToken(await oldToken())).errorCode).toBe(401);
    });

    it("enforce: refuses another issuer, or an audience without the platform", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
      const { error } = quietly();

      const otherIssuer = await signed(claims({ iss: "someone-else" }));
      const hostOnly = await signed(claims({ aud: "app.variamos.com" }));

      expect((await validateToken(otherIssuer)).errorCode).toBe(401);
      expect((await validateToken(hostOnly)).errorCode).toBe(401);
      expect(error).toHaveBeenCalledWith(
        'JWT refused: audience (aud) does not hold "variamos-platform"'
      );
    });

    it("enforce: follows VARIAMOS_JWT_ISSUER and VARIAMOS_JWT_AUDIENCE", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
      vi.stubEnv("VARIAMOS_JWT_ISSUER", "issuer-x");
      vi.stubEnv("VARIAMOS_JWT_AUDIENCE", "audience-x");
      quietly();

      const token = await signed(claims({ iss: "issuer-x", aud: "audience-x" }));

      expect((await validateToken(token)).errorCode).toBeUndefined();
      expect((await validateToken(await signed(claims()))).errorCode).toBe(401);
    });

    it("counts an unknown mode as warn", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforced");
      const { warn } = quietly();

      expect((await validateToken(await oldToken())).errorCode).toBeUndefined();
      expect(warn).toHaveBeenCalledWith(
        'VARIAMOS_JWT_CLAIMS_MODE "enforced" is not one of off, warn, enforce: "warn" is used'
      );
    });
  });

  describe("an expired token", () => {
    const expired = (extra: Record<string, unknown> = {}) =>
      signed(claims({ iat: now() - 7200, exp: now() - 3600, ...extra }));

    it("is still returned, for the refresh of the admin service", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");

      const response = await validateToken(await expired());

      expect(response.errorCode).toBeUndefined();
      expect(response.data?.sub).toBe("user-1");
    });

    it("is refused by validateSession", async () => {
      const response = await validateSession(await expired());

      expect(response.errorCode).toBe(401);
      expect(response.message).toBe(
        "Your session has expired, please log in again."
      );
    });

    it("keeps its issuer checked", async () => {
      vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
      quietly();

      expect(
        (await validateToken(await expired({ iss: "someone-else" }))).errorCode
      ).toBe(401);
    });

    it("signed by another key, is refused", async () => {
      quietly();
      const token = await signed(
        claims({ iat: now() - 7200, exp: now() - 3600 }),
        { key: otherKeys.privateKey }
      );

      expect((await validateToken(token)).errorCode).toBe(401);
    });
  });

  it("accepts a clock up to 30 s ahead (nbf)", async () => {
    vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
    quietly();

    const soon = await signed(claims({ nbf: now() + 20 }));
    const later = await signed(claims({ nbf: now() + 120 }));

    expect((await validateToken(soon)).errorCode).toBeUndefined();
    expect((await validateToken(later)).errorCode).toBe(401);
  });
});

describe("validateRolesAndPermissions", () => {
  it("goes through the same checks", async () => {
    vi.stubEnv("VARIAMOS_JWT_CLAIMS_MODE", "enforce");
    quietly();

    const valid = await createJwt(user, "app.variamos.com");
    const foreign = await signed(claims({ iss: "someone-else" }));

    expect(
      (await validateRolesAndPermissions(valid, ["users::query"])).errorCode
    ).toBeUndefined();
    expect(
      (await validateRolesAndPermissions(foreign, ["users::query"])).errorCode
    ).toBe(401);
  });
});

describe("audienceHost", () => {
  it("gives the host of a new or old audience, never the platform", () => {
    expect(audienceHost(["variamos-platform", "app.variamos.com"])).toBe(
      "app.variamos.com"
    );
    expect(audienceHost("app.variamos.com")).toBe("app.variamos.com");
    expect(audienceHost("variamos-platform")).toBeUndefined();
    expect(audienceHost(undefined)).toBeUndefined();
  });
});
