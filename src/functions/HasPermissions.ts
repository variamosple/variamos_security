import { NextFunction, Request, Response } from "express";
import { ResponseModel, SessionInfo } from "../types";
import { getToken, validateSession } from "./IsAuthenticated";
import { sessionInfoToSessionUser } from "./Mappers";

/**
 * Validates the roles and permissions of a user based on the provided token.
 *
 * @param token - The authentication token of the user.
 * @param permissions - An optional array of required permissions.
 * @param roles - An optional array of required roles.
 * @returns A promise that resolves to a `ResponseModel<SessionInfo>` object.
 *          If the user does not have the required roles or permissions, the response will contain an error with a 403 status code.
 *          Otherwise, it will return the validation response from `validateSession`.
 */
export const validateRolesAndPermissions = async (
  token: string,
  permissions: string[] = [],
  roles: string[] = []
): Promise<ResponseModel<SessionInfo>> => {
  const response = new ResponseModel<SessionInfo>().withError(
    403,
    "Access denied, not enough permissions."
  );
  const validationResponse = await validateSession(token);

  if (validationResponse.errorCode) {
    return validationResponse;
  }

  const userRoles = validationResponse.data?.roles || [];

  if (
    !!roles &&
    roles.length != 0 &&
    !userRoles.some((role) => roles.includes(role))
  ) {
    return response;
  }

  const userPermission = validationResponse.data?.permissions || [];

  if (!userPermission.some((permission) => permissions.includes(permission))) {
    return response;
  }

  return validationResponse;
};

/**
 * Middleware function to check if a user has the required permissions and/or roles to access a route.
 *
 * @param {string[]} permissions - An array of permissions required to access the route.
 * @param {string[]} roles - An array of roles required to access the route.
 *                           If no roles are provided, the middleware will only check for permissions.
 * @returns {(req: Request, res: Response, next: NextFunction) => Promise<void>} - An Express middleware function that:
 *  - Validates the JWT token from the request using the `validateSession` function.
 *  - Attaches the decoded user information to the request object.
 *  - Checks if the user has at least one of the required roles (if roles are provided).
 *  - Checks if the user has at least one of the required permissions.
 *  - Calls `next()` to proceed to the next middleware or route handler if the user has the required roles and/or permissions.
 *  - Responds with a `401 Unauthorized` status and an error message if token validation fails.
 *  - Responds with a `403 Forbidden` status and an error message if the user does not have the required roles or permissions.
 *  - Responds with a `500 Internal Server Error` status and an error message if an error occurs during role or permission checking.

 *
 * @param {Request} request - The Express request object. Expected to contain a JWT token in cookies.
 * @param {Response} response - The Express response object, used to send responses to the client.
 * @param {NextFunction} next - The Express next function, used to pass control to the next middleware or route handler.
 *
 * @returns {Promise<void>} - A promise that resolves when the middleware completes its operation.
 */
export const hasPermissions =
  (permissions: string[] = [], roles: string[] = []) =>
  async (request: Request, response: Response, next: NextFunction) => {
    try {
      const validationResponse = await validateRolesAndPermissions(
        getToken(request),
        permissions,
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
      console.error(
        "Error verifying user permissions and roles:",
        permissions,
        roles,
        err
      );
      response.status(500).json({ errorMessage: "Internal server error" });
    }
  };
