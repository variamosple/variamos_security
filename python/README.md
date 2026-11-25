# VariaMos Security Library

This library provides security functionalities for the VariaMos platform, including JWT creation, session validation, role and permission checks, and exception handling.

## Installation

Install it from PyPI, with the FastAPI helpers (`is_authenticated`, `has_roles`, `has_permissions`):

```bash
pip install "variamos-security[fastapi]"
```

## Session tokens signed by variamos_ms_admin (0.0.3)

`variamos_ms_admin` signs the session tokens with the Node library of this repository (`@variamosple/variamos-security`). Since its 0.0.17, a token carries:

- an issuer, `iss`: `variamos_ms_admin`;
- an audience, `aud`, that is a list: `["variamos-platform", host]`.

Version 0.0.2 of this package read `aud` as a string only: such a token failed its validation and every authenticated request answered 500. Version 0.0.3 reads `aud` as a string or a list and keeps `iss` (`SessionInfo.iss`, `SessionInfo.aud`).

## Verification (0.0.4)

The verifier follows the rules of the Node library:

- **Signature**: RS256 only, with the public key (`VARIAMOS_PUBLIC_KEY_PATH`). With the private key alone, its public half is used and a warning is logged.
- **Issuer and audience**: the issuer must be `VARIAMOS_JWT_ISSUER` (`variamos_ms_admin` by default) and the audience must hold `VARIAMOS_JWT_AUDIENCE` (`variamos-platform` by default). `VARIAMOS_JWT_CLAIMS_MODE` says what happens to a token whose issuer or audience is wrong or missing:

| Value | Effect |
| --- | --- |
| `off` | Nothing. |
| `warn` (default) | The token is accepted and the reason is logged (`JWT accepted although ...`). |
| `enforce` | The token is refused with a 401 (`JWT refused: ...`). |

- **Session fields**: a genuine token without the fields of a session (`sub`, `name`, `userName`, `email`), or with a field of the wrong type, is refused with a 401, not a 500. The log names the fields, never their values.
- **Cookie and header**: the `authToken` cookie is read first. When it is refused as unauthenticated (expired, invalid), the `Authorization: Bearer` header is tried. A valid cookie without the permission answers 403: the header is not tried to gain rights.

`create_jwt(user, host)` signs as the Node library does: the issuer, and `aud: ["variamos-platform", host]`, or `"variamos-platform"` without host. Given the `aud` of a token being refreshed, it keeps the host.

## Configuration

1. **Create Public and Private Keys for Session Management:**

   - Generate a private key:
     ```bash
     openssl genpkey -algorithm RSA -out jwtRS256.key -pkeyopt rsa_keygen_bits:4096
     ```
   - Generate a public key:
     ```bash
     openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub
     ```

2. **Set Environment Variables:**

   - Set the `VARIAMOS_PRIVATE_KEY_PATH` in your environment:
     ```env
     VARIAMOS_PRIVATE_KEY_PATH=./jwtRS256.key
     ```
   - Set the `VARIAMOS_PUBLIC_KEY_PATH` in your environment:
     ```env
     VARIAMOS_PUBLIC_KEY_PATH=./jwtRS256.key.pub
     ```
   - Set the `VARIAMOS_JWT_EXP_IN_SECONDS` in your environment (optional, default is 900 seconds):
     ```env
     VARIAMOS_JWT_EXP_IN_SECONDS=900
     ```
     It must be a whole number of seconds above 0, spaces around it aside. Any other value (empty, not a number, negative, `0`, a decimal) counts as the default, and a warning names it once, as in the Node library 0.1.1. Before 0.0.5, such a value stopped `create_jwt` with a `ValueError` or signed tokens that were expired at once.

## Usage

### Functions

#### `create_jwt`

- **Function:** `create_jwt(user: SessionUser, aud: str | List[str] = None) -> str`
- **Description:** Creates a JWT for the given user, with the issuer and the platform audience.
- **Parameters:**
  - `user` (SessionUser): The user for whom the JWT is created.
  - `aud` (str or list, optional): The host the user goes to, or the `aud` of the token being refreshed.
- **Returns:** The generated JWT as a string.

#### `is_authenticated`

- **Function:** `is_authenticated(request: Request) -> SessionUser`
- **Description:** Validates the session and returns the authenticated user.
- **Parameters:**
  - `request` (Request): The incoming request.
- **Returns:** The authenticated user as a `SessionUser`.

#### `has_roles`

- **Function:** `has_roles(roles: List[str] = [])`
- **Description:** Middleware to check if the user has the required roles.
- **Parameters:**
  - `roles` (List[str]): The list of roles to check.
- **Returns:** The authenticated user as a `SessionUser`.

#### `has_permissions`

- **Function:** `has_permissions(permissions: List[str] = [], roles: List[str] = [])`
- **Description:** Middleware to check if the user has the required permissions and roles.
- **Parameters:**
  - `permissions` (List[str]): The list of permissions to check.
  - `roles` (List[str]): The list of roles to check.
- **Returns:** The authenticated user as a `SessionUser`.

### Exception Handling

#### `variamos_security_exception`

- **Class:** `VariamosSecurityException`
- **Description:** Custom exception class for security-related errors.
- **Parameters:**

  - `status_code` (int): The HTTP status code.
  - `detail` (ResponseModel): The response model containing error details.
  - `headers` (dict, optional): Additional headers.

- **Function:** `variamos_security_exception_handler(request: Request, exc: VariamosSecurityException)`
- **Description:** Exception handler for `VariamosSecurityException`.
- **Parameters:**
  - `request` (Request): The incoming request.
  - `exc` (VariamosSecurityException): The raised exception.
- **Returns:** A JSON response with the error details.

### Configuration

#### `security_config`

- **Function:** `load_keys()`
- **Description:** Loads the private and public keys from the environment.
- **Function:** `get_private_key()`
- **Description:** Returns the private key.
- **Function:** `get_public_key()`
- **Description:** Returns the public key.

## Models

### `session_info`

- **Class:** `SessionInfo`
- **Description:** Model representing session information.

### `session_user`

- **Class:** `SessionUser`
- **Description:** Model representing a session user.

### `response_model`

- **Class:** `ResponseModel`
- **Description:** Model representing a response with data or error information.

## Development

The source of this package lives in the `python/` folder of [variamos_security](https://github.com/variamosple/variamos_security), next to the Node library. Its tests check, among other things, that a token signed by the Node library is accepted here. With Python 3.9 or later, and Node 26 for that check:

```bash
npm ci && npm run build
cd python
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes --only-binary :all: -r requirements-test.txt
python -m pytest
```

The test and build dependencies are listed in `requirements-test.in` and `requirements-build.in`, and locked with their hashes in the matching `.txt` files. After a change to a `.in` file, compile it again with the command written at its top.

Without Node or without `npm run build`, the tests of Node tokens are skipped; the CI runs them.

## Release

A release is published to PyPI by GitHub Actions (trusted publishing, no token):

1. Raise `version` in `setup.py` in a pull request, and merge it.
2. Push the tag `python-vX.Y.Z` on that commit of `main`: the workflow `publish-python.yml` checks that the tag matches the version, runs the tests, builds the package and waits for an approval in the `pypi` environment.
3. Once approved, the version is on PyPI.

## License

This project is licensed under the MIT License.
