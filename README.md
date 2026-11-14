# VariaMos Security

## Overview

This project utilizes JSON Web Tokens (JWT) for authentication and authorization. It includes key management using `jose` and middleware functions to handle role-based and permission-based access control.

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

### Issuer, audience and algorithm of session tokens (0.0.17)

Every VariaMos service accepts the same session token (single sign-on). Besides its signature, a token is checked for:

- **its algorithm**: RS256 only, the one `createJwt` signs with. Any other algorithm is refused.
- **its issuer** (`iss`): `VARIAMOS_JWT_ISSUER`, `variamos_ms_admin` by default.
- **its audience** (`aud`): it must hold `VARIAMOS_JWT_AUDIENCE`, `variamos-platform` by default. The audience names the platform, not one service.

`createJwt(user, host)` sets the issuer and `aud: ["variamos-platform", host]`. The host is the domain the user goes to, as before. Given the `aud` of a token being refreshed, it keeps the host and sets the platform again. `audienceHost(aud)` returns that host, for a token issued before or after 0.0.17.

`VARIAMOS_JWT_CLAIMS_MODE` says what a verifier does with a token whose issuer or audience is wrong or missing:

| Value | Effect |
| --- | --- |
| `off` | Nothing, as before 0.0.17. |
| `warn` (default) | The token is accepted and the reason is logged (`JWT accepted although ...`). |
| `enforce` | The token is refused with a 401. |

An unknown value counts as `warn`. Tokens issued before 0.0.17 have no issuer: switch a service to `enforce` only once the issuer runs 0.0.17 and those tokens have expired.

`validateToken` still returns an expired token, so the admin service can refresh it. Its signature, issuer and audience are checked as for any other token. `validateSession` refuses it.

Ensure that these environment variables are set in your environment or in a `.env` file if you are using a package like `dotenv` to manage environment variables.

### Example `.env` File

Create a `.env` file in the root of your project with the following content:

```env
VARIAMOS_PRIVATE_KEY_PATH=path/to/private-key.pem
VARIAMOS_PUBLIC_KEY_PATH=path/to/public-key.pem
# Optional (0.0.17): defaults shown
VARIAMOS_JWT_ISSUER=variamos_ms_admin
VARIAMOS_JWT_AUDIENCE=variamos-platform
VARIAMOS_JWT_CLAIMS_MODE=warn
```

## Development

Requires Node 26 (`.nvmrc`, `.mise.toml`). `npm install` sets up the Git hooks: Biome and cspell on the staged files before a commit, the conventional commit format, and typecheck, lint and tests before a push. The CI runs the same commands on every pull request; the package is published to npm by hand.

```sh
npm ci
npm run typecheck
npm run lint            # Biome (shared configuration of the admin module), no rule silenced in a comment
npm run spell           # cspell
npm run find-deadcode   # knip: unused files, exports and dependencies
npm test
npm run build
npm run check-package   # what npm pack would publish, then publint
```

`npm run format` formats the code with Biome.

## Key Management

### Dependencies

- `fs` - File system module to read key files.
- `jose` - Library for signing and verifying JSON Web Signatures (JWS, RS256).
- `crypto` - Node.js module that parses PEM keys (KeyObject).
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
