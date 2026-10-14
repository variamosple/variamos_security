import { createPublicKey } from "crypto";
import { NextFunction, Request, Response } from "express";
import { compactVerify } from "jose";
import { getPrivateKey, getPublicKey } from "../config/SecurityCofing";
import { ResponseModel, SessionInfo } from "../types";
import { sessionInfoToSessionUser } from "./Mappers";

// RSA signature algorithms accepted on verification, same set node-jose allowed for RSA keys.
const SIGNATURE_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];

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

  try {
    // compactVerify checks the signature only: exp and aud stay in validateSession.
    const result = await compactVerify(token, key, {
      algorithms: SIGNATURE_ALGORITHMS,
    });

    response.withResponse(
      JSON.parse(Buffer.from(result.payload).toString("utf8"))
    );
  } catch (err) {
    console.error("Error verifying JWT:", err);
    response.withError(401, "Error on session validation, please try again.");
  }

  return response;
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
