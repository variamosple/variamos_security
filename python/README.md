# VariaMos Security Library

This library provides security functionalities for the VariaMos platform, including JWT creation, session validation, role and permission checks, and exception handling.

## Installation

To install the dependencies, run:

```bash
pip install -r requirements.txt
```

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

## Usage

### Functions

#### `create_jwt`

- **Function:** `create_jwt(user: SessionUser, aud: str = None) -> str`
- **Description:** Creates a JWT for the given user.
- **Parameters:**
  - `user` (SessionUser): The user for whom the JWT is created.
  - `aud` (str, optional): The audience for the JWT.
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

## License

This project is licensed under the MIT License.
