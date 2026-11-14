/**
 * The claims a session token must carry besides its signature: who issued
 * it (`iss`) and what it is for (`aud`). Every VariaMos service accepts the
 * same session token (single sign-on), so the audience names the platform,
 * not one service.
 */
export const DEFAULT_JWT_ISSUER = "variamos_ms_admin";
export const DEFAULT_JWT_AUDIENCE = "variamos-platform";

/** The only algorithm the issuer signs with. */
export const JWT_ALGORITHMS = ["RS256"];

/** Clock difference accepted between services, in seconds. */
export const JWT_CLOCK_TOLERANCE_SECONDS = 30;

/**
 * What a verifier does with a token whose issuer or audience is wrong or
 * missing:
 * - `off`: nothing, as before;
 * - `warn` (default): accepts it and logs it;
 * - `enforce`: refuses it.
 */
export type ClaimsMode = "off" | "warn" | "enforce";

const MODES: ClaimsMode[] = ["off", "warn", "enforce"];
const MODE_NAMES: ReadonlySet<string> = new Set(MODES);
const isClaimsMode = (value: string): value is ClaimsMode =>
  MODE_NAMES.has(value);
let unknownModeLogged = false;

/** `VARIAMOS_JWT_ISSUER`, or the default issuer. */
export const jwtIssuer = (): string =>
  process.env.VARIAMOS_JWT_ISSUER?.trim() || DEFAULT_JWT_ISSUER;

/** `VARIAMOS_JWT_AUDIENCE`, or the default platform audience. */
export const jwtAudience = (): string =>
  process.env.VARIAMOS_JWT_AUDIENCE?.trim() || DEFAULT_JWT_AUDIENCE;

/** `VARIAMOS_JWT_CLAIMS_MODE`; an unknown value counts as `warn`. */
export const claimsMode = (): ClaimsMode => {
  const value = process.env.VARIAMOS_JWT_CLAIMS_MODE?.trim().toLowerCase();
  if (!value) return "warn";
  if (isClaimsMode(value)) return value;
  if (!unknownModeLogged) {
    unknownModeLogged = true;
    console.warn(
      `VARIAMOS_JWT_CLAIMS_MODE "${value}" is not one of ${MODES.join(", ")}: "warn" is used`,
    );
  }
  return "warn";
};

const audiences = (aud: unknown): unknown[] => {
  if (Array.isArray(aud)) return aud;
  return aud === undefined ? [] : [aud];
};

/**
 * Why the issuer or the audience of a verified payload is not the expected
 * one, or `null` when both are.
 */
export const claimsProblem = (payload: {
  iss?: unknown;
  aud?: unknown;
}): string | null => {
  const issuer = jwtIssuer();
  if (payload.iss !== issuer) {
    return payload.iss === undefined
      ? "no issuer (iss)"
      : `issuer (iss) is not "${issuer}"`;
  }
  const audience = jwtAudience();
  if (!audiences(payload.aud).includes(audience)) {
    return `audience (aud) does not hold "${audience}"`;
  }
  return null;
};

/**
 * The host a token was issued for, without the platform audience: the
 * `aud` of a session token holds both, `[platform, host]`. A token issued
 * before 0.0.17 holds the host alone.
 */
export const audienceHost = (aud?: string | string[]): string | undefined => {
  const platform = jwtAudience();
  return audiences(aud).find(
    (entry): entry is string => typeof entry === "string" && entry !== platform,
  );
};
