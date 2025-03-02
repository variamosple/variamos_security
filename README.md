# VariaMos Security

## Overview

This project utilizes JSON Web Tokens (JWT) for authentication and authorization. It includes key management using `node-jose` and middleware functions to handle role-based and permission-based access control.

## Config

### Environment Variables

To configure the key management, you need to set the following environment variables:

- **`VARIAMOS_PRIVATE_KEY_PATH`**: The path to the private key file used for signing JWT tokens. This file should be in PEM format. For example:

  ```sh
  VARIAMOS_PRIVATE_KEY_PATH=path/to/private-key.pem
  ```

- **`VARIAMOS_PUBLIC_KEY_PATH`**: The path to the public key file used for verifying JWT tokens. This file should be in PEM format. For example:
  ```sh
  VARIAMOS_PUBLIC_KEY_PATH=path/to/public-key.pem
  ```

Ensure that these environment variables are set in your environment or in a `.env` file if you are using a package like `dotenv` to manage environment variables.

### Example `.env` File

Create a `.env` file in the root of your project with the following content:

```env
VARIAMOS_PRIVATE_KEY_PATH=path/to/private-key.pem
VARIAMOS_PUBLIC_KEY_PATH=path/to/public-key.pem
```

## Key Management

### Dependencies

- `fs` - File system module to read key files.
- `node-jose` - Library for handling JSON Web Keys (JWK).
- `path` - Module to handle and transform file paths.
- `@types/express` - Type definitions for Express.

### Key Management Functions

#### `initKeyStore`

Initializes the key store by loading public and private keys from the filesystem and adding them to the JWK key store.

**Function Signature:**

```typescript
export const initKeyStore: () => Promise<void>;
```

**Description:**

- Reads the private key from the path specified in the environment variable `VARIAMOS_PRIVATE_KEY_PATH`.
- Reads the public key from the path specified in `VARIAMOS_PUBLIC_KEY_PATH`.
- Adds the private key to the key store with a key ID of "private-signing-key" and usage set to "sig".
- Adds the public key to the key store with a key ID of "public-verification-key" and usage set to "sig".
- Logs a success message with the contents of the key store if initialization is successful.
- Logs an error message if an exception occurs during initialization.

## Middleware Functions

### `isAuthenticated`

Checks if the request is authenticated by validating the JWT token.

**Middleware Function Signature:**

```typescript
export const isAuthenticated: (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void>;
```

**Description:**

- Validates the JWT token from the request.
- Attaches user information to the request object if validation is successful.
- Calls `next()` to proceed to the next middleware or route handler.
- Responds with a `401 Unauthorized` status and an error message if token validation fails.

### `hasRoles`

Checks if the authenticated user has the required roles to access a route.

**Middleware Function Signature:**

```typescript
export const hasRoles: (
  roles: string[]
) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
```

**Description:**

- Validates the JWT token and attaches user information to the request object.
- Checks if the user has at least one of the required roles.
- Calls `next()` if the user has the required roles.
- Responds with a `403 Forbidden` status and an error message if the user does not have the required roles.

### `hasPermissions`

Checks if the authenticated user has the required permissions and/or roles to access a route.

**Middleware Function Signature:**

```typescript
export const hasPermissions: (
  permissions: string[],
  roles: string[]
) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
```

**Description:**

- Validates the JWT token and attaches user information to the request object.
- Checks if the user has at least one of the required permissions and/or roles.
- Calls `next()` if the user meets the required permissions and/or roles.
- Responds with a `403 Forbidden` status and an error message if the user does not have the required permissions or roles.
