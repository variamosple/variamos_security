/**
 * How long a session token lasts: `VARIAMOS_JWT_EXP_IN_SECONDS`, a whole
 * number of seconds above zero. Any other value (empty, not a number,
 * negative, zero, a decimal) would sign a token that is expired at once, or
 * that has no valid expiry: the default is used instead, and a warning says
 * so.
 */
export const DEFAULT_JWT_EXP_IN_SECONDS = 900;

const WHOLE_SECONDS = /^\d+$/;
let lastRefusedValue: string | undefined;

/** `VARIAMOS_JWT_EXP_IN_SECONDS`, or the default lifetime. */
export const jwtExpiresInSeconds = (): number => {
  const raw = process.env.VARIAMOS_JWT_EXP_IN_SECONDS;
  if (raw === undefined) return DEFAULT_JWT_EXP_IN_SECONDS;
  const value = raw.trim();
  const seconds = WHOLE_SECONDS.test(value) ? Number(value) : 0;
  if (Number.isSafeInteger(seconds) && seconds > 0) return seconds;
  // Once per refused value, not at every signature
  if (lastRefusedValue !== raw) {
    lastRefusedValue = raw;
    console.warn(
      `VARIAMOS_JWT_EXP_IN_SECONDS "${raw}" is not a whole number of seconds above 0: ${DEFAULT_JWT_EXP_IN_SECONDS} is used`,
    );
  }
  return DEFAULT_JWT_EXP_IN_SECONDS;
};
