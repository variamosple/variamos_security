import { NextFunction, Request, Response } from "express";
import { ResponseModel, SessionInfo } from "../types";
import { validateSession } from "./IsAuthenticated";
import { sessionInfoToSessionUser } from "./Mappers";

/**
 * Validates if the user associated with the provided token has at least one of the required roles.
 *
 * @param token - The token representing the user's session.
 * @param roles - An array of roles to check against the user's roles.
 * @returns A promise that resolves to a `ResponseModel<SessionInfo>` object.
 *          If the user does not have the required roles, the response will contain an error with a 403 status code.
 *          Otherwise, it will return the validation response from `validateSession`.
 */
export const validateRoles = async (
  token: string,
  roles: string[]
): Promise<ResponseModel<SessionInfo>> => {
  const response = new ResponseModel<SessionInfo>();
  const validationResponse = await validateSession(token);

  if (validationResponse.errorCode) {
    return validationResponse;
  }

  const userRoles = validationResponse.data?.roles || [];

  if (!userRoles.some((role) => roles.includes(role))) {
    return response.withError(403, "Access denied, not enough permissions.");
  }

  return validationResponse;
};

/**
 * Middleware function to check if a user has the required roles to access a route.
 *
 * @param {string[]} roles - An array of roles that are required to access the route.
 *                          If no roles are provided, the middleware will allow access to users with any roles.
 * @returns {(req: Request, res: Response, next: NextFunction) => Promise<void>} - An Express middleware function that:
 *  - Validates the JWT token from the request using the `validateRoles` function.
 *  - Attaches the decoded user information to the request object.
 *  - Calls `next()` to proceed to the next middleware or route handler if the user has the required roles.
 *  - Responds with a `401 Unauthorized` status and an error message if token validation fails.
 *  - Responds with a `403 Forbidden` status and an error message if the user does not have the required roles.
 *  - Responds with a `500 Internal Server Error` status and an error message if an error occurs during role checking.
 *
 * @param {Request} request - The Express request object. Expected to contain a JWT token in cookies.
 * @param {Response} response - The Express response object, used to send responses to the client.
 * @param {NextFunction} next - The Express next function, used to pass control to the next middleware or route handler.
 *
 * @returns {Promise<void>} - A promise that resolves when the middleware completes its operation.
 */
export const hasRoles =
  (roles: string[] = []) =>
  async (request: Request, response: Response, next: NextFunction) => {
    try {
      const validationResponse = await validateRoles(
        request.cookies.authToken,
        roles
      );

      if (validationResponse.errorCode) {
        return response
          .status(validationResponse.errorCode)
          .json(validationResponse);
      }
      request.user = sessionInfoToSessionUser(validationResponse.data);

      return next();
    } catch (err) {
      console.error("Error verifying user roles:", err);
      response.status(500).json({ errorMessage: "Internal server error" });
    }
  };
