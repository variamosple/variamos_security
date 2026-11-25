import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_JWT_EXP_IN_SECONDS,
  jwtExpiresInSeconds,
} from "./TokenLifetime";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const warnings = () => vi.spyOn(console, "warn").mockImplementation(() => {});

describe("jwtExpiresInSeconds", () => {
  it("is 900 seconds without the variable, silently", () => {
    vi.stubEnv("VARIAMOS_JWT_EXP_IN_SECONDS", undefined);
    const warn = warnings();

    expect(jwtExpiresInSeconds()).toBe(DEFAULT_JWT_EXP_IN_SECONDS);
    expect(DEFAULT_JWT_EXP_IN_SECONDS).toBe(900);
    expect(warn).not.toHaveBeenCalled();
  });

  it.each([
    ["3600", 3600],
    [" 60 ", 60],
    ["1", 1],
  ])("reads %j as %i seconds, silently", (value, seconds) => {
    vi.stubEnv("VARIAMOS_JWT_EXP_IN_SECONDS", value);
    const warn = warnings();

    expect(jwtExpiresInSeconds()).toBe(seconds);
    expect(warn).not.toHaveBeenCalled();
  });

  // Each value once in this file: the warning is given once per value
  it.each([
    "",
    "   ",
    "abc",
    "15m",
    "-60",
    "0",
    "1.5",
    "1e3",
    "+900",
    "99999999999999999999",
  ])("uses the default for %j and says it", (value) => {
    vi.stubEnv("VARIAMOS_JWT_EXP_IN_SECONDS", value);
    const warn = warnings();

    expect(jwtExpiresInSeconds()).toBe(DEFAULT_JWT_EXP_IN_SECONDS);
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain(
      `VARIAMOS_JWT_EXP_IN_SECONDS "${value}" is not a whole number of seconds above 0: 900 is used`,
    );
  });

  it("says it once per refused value, not at every signature", () => {
    const warn = warnings();

    vi.stubEnv("VARIAMOS_JWT_EXP_IN_SECONDS", "-1");
    jwtExpiresInSeconds();
    jwtExpiresInSeconds();
    expect(warn).toHaveBeenCalledOnce();

    vi.stubEnv("VARIAMOS_JWT_EXP_IN_SECONDS", "-2");
    jwtExpiresInSeconds();
    expect(warn).toHaveBeenCalledTimes(2);
  });
});
