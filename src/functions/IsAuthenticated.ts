import { createPublicKey } from "crypto";
import { NextFunction, Request, Response } from "express";
import { errors, JWTPayload, jwtVerify } from "jose";
import { getPrivateKey, getPublicKey } from "../config/SecurityCofing";
import {
  claimsMode,
  claimsProblem,
  JWT_ALGORITHMS,
  JWT_CLOCK_TOLERANCE_SECONDS,
} from "../config/TokenClaims";
import { ResponseModel, SessionInfo } from "../types";
import { sessionInfoToSessionUser } from "./Mappers";

export const getToken = (request: Request): string => {
  if (request.cookies.authToken) {
    return request.cookies.authToken;
  }

  const token = request.headers.authorization;

  return !token ? "" : token.replace("Bearer ", "");
};

/**
 * Checks if the session has expired.
 *
 * @param {number} [expirationDateInSeconds] - The expiration date of the session in seconds.
 * @returns {boolean} - `true` if the session has expired; otherwise, `false`.
 */
export const isSessionExpired = (expirationDateInSeconds?: number): boolean => {
  return (
    !expirationDateInSeconds || Date.now() > expirationDateInSeconds * 1000
  );
};

/**
 * Validates a given JWT token and returns session information.
 *
 * The signature must be RS256 by the platform key. The issuer and the
 * audience are checked as `VARIAMOS_JWT_CLAIMS_MODE` says (see
 * `config/TokenClaims`). An expired token is still returned: the admin
 * service refreshes it; `validateSession` refuses it.
 *
 * @param {string} [token] - The JWT token to be validated. If not provided, an error response is returned.
 * @returns {Promise<ResponseModel<SessionInfo>>} - A promise that resolves to a ResponseModel containing session information or an error message.
 *
 * @example
 * const response = await validateToken("your-jwt-token");
 * if (response.errorCode) {
 *   console.error(response.message);
 * } else {
 *   console.log(response.data);
 * }
 */
export const validateToken = async (
  token?: string
): Promise<ResponseModel<SessionInfo>> => {
  const response = new ResponseModel<SessionInfo>();

  if (!token) {
    return response.withError(401, "Please log in.");
  }

  let key = getPublicKey();

  if (!key) {
    // Verification needs the public half: derive it from the private key.
    const privateKey = getPrivateKey();
    key = privateKey && createPublicKey(privateKey);
  }

  if (!key) {
    console.error("Public and/or private key not found in keystore");
    return response.withError(
      401,
      "Error on session validation, please try again."
    );
  }

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, key, {
      algorithms: JWT_ALGORITHMS,
      clockTolerance: JWT_CLOCK_TOLERANCE_SECONDS,
    }));
  } catch (err) {
    if (!(err instanceof errors.JWTExpired)) {
      console.error("Error verifying JWT:", err);
      return response.withError(
        401,
        "Error on session validation, please try again."
      );
    }
    // jose checks the signature before the claims: an expired token is
    // genuine. Its expiry is checked by validateSession.
    payload = err.payload;
  }

  const problem = claimsProblem(payload);
  if (problem) {
    const mode = claimsMode();
    if (mode === "enforce") {
      console.error(`JWT refused: ${problem}`);
      return response.withError(
        401,
        "Error on session validation, please try again."
      );
    }
    if (mode === "warn") {
      console.warn(`JWT accepted although ${problem}`);
    }
  }

  return response.withResponse(payload as unknown as SessionInfo);
};

export const validateSession = async (
  token?: string
): Promise<ResponseModel<SessionInfo>> => {
  const validationResponse = await validateToken(token);

  if (validationResponse.errorCode) {
    return validationResponse;
  } else if (isSessionExpired(validationResponse.data?.exp)) {
    return new ResponseModel<SessionInfo>().withError(
      401,
      "Your session has expired, please log in again."
    );
  }

  return validationResponse;
};

/**
 * Middleware function to authenticate a request by validating the JWT token and attaching user information.
 *
 * @param {Request} request - The Express request object. The JWT token should be in cookies, and the middleware will attach the decoded user information to the request object.
 * @param {Response} response - The Express response object, used to send responses to the client.
 * @param {NextFunction} next - The Express next function, used to pass control to the next middleware or route handler.
 *
 * @returns {Promise<void>} - A promise that resolves when the middleware completes its operation.
 *
 * If token validation is successful:
 * - The decoded user information is attached to `request.user`.
 * - Calls `next()` to proceed to the next middleware or route handler.
 *
 * If an error occurs:
 * - Logs the error.
 * - Responds with a `401 Unauthorized` status and a JSON error message: "Session validation error".
 */
export const isAuthenticated = async (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  try {
    const validationResponse = await validateSession(getToken(request));

    if (validationResponse.errorCode) {
      return response
        .status(validationResponse.errorCode)
        .json(validationResponse);
    }

    request.user = sessionInfoToSessionUser(validationResponse.data);
    next();
  } catch (err) {
    console.error("Error verifying session:", err);
    response
      .status(401)
      .json(
        new ResponseModel().withError(
          401,
          "Error on session validation, please try again."
        )
      );
  }
};
