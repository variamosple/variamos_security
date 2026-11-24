import logging
from typing import List, Optional
from datetime import datetime, timezone
from jose import jwt, JWTError
from pydantic import ValidationError
from fastapi import Request
from variamos_security.config.security_config import get_private_key, get_public_key
from variamos_security.config.token_claims import (
    JWT_ALGORITHMS,
    JWT_CLOCK_TOLERANCE_SECONDS,
    claims_mode,
    claims_problem,
)
from variamos_security.model.session_info import SessionInfo
from variamos_security.model.session_user import SessionUser
from variamos_security.model.response_model import ResponseModel
from variamos_security.functions.mappers import session_info_to_session_user
from variamos_security.exceptions.variamos_security_exception import VariamosSecurityException

logger = logging.getLogger(__name__)

_SESSION_ERROR = "Error on session validation, please try again."

def get_token(request: Request) -> str:
    if "authToken" in request.cookies:
        return request.cookies["authToken"]

    token = request.headers.get("Authorization")
    return "" if not token else token.replace("Bearer ", "")



def get_tokens(request: Request) -> List[str]:
    """
    The session tokens a request carries, the cookie first, then the
    Authorization header when it holds another one: a stale cookie must not
    hide a valid header. At least one entry, empty without any token.
    """
    tokens = []
    cookie = request.cookies.get("authToken")
    if cookie:
        tokens.append(cookie)

    header = request.headers.get("Authorization")
    header_token = header.replace("Bearer ", "") if header else ""
    if header_token and header_token not in tokens:
        tokens.append(header_token)

    return tokens or [""]



def first_valid(tokens: List[str], validate) -> ResponseModel:
    """
    The answer of validate for the first token it does not refuse as
    unauthenticated (401), or its answer for the last one. A valid token
    without the permission (403) ends the search: the next token is not
    tried to gain rights.
    """
    response = None
    for token in tokens:
        response = validate(token)
        if response.errorCode != 401:
            return response
    return response



def is_session_expired(expiration_date_in_seconds: Optional[int]) -> bool:
    return not expiration_date_in_seconds or datetime.now(timezone.utc).timestamp() > expiration_date_in_seconds



def _verification_key():
    """
    The public key, or the public half of the private key when only that one
    is configured (as the Node library does). A service that only verifies
    needs the public key alone.
    """
    public_key = get_public_key()
    if public_key:
        return public_key

    private_key = get_private_key()
    if private_key:
        logger.warning("No public key (VARIAMOS_PUBLIC_KEY_PATH): the public half of the private key verifies the session")
        return private_key.public_key()

    return None



def validate_token(token: Optional[str]) -> ResponseModel[SessionInfo]:
    """
    Validates a session token: RS256 signature by the platform key, then its
    fields, then its issuer and audience as VARIAMOS_JWT_CLAIMS_MODE says
    (config/token_claims). An expired token is still returned:
    validate_session refuses it.
    """
    response = ResponseModel[SessionInfo]()

    if not token:
        return response.with_error(401, "Please log in.")

    key = _verification_key()

    if not key:
        logger.error("Public and/or private key not found")
        return response.with_error(401, _SESSION_ERROR)

    try:
        payload = jwt.decode(
            token,
            key.to_pem().decode('utf-8'),
            algorithms=JWT_ALGORITHMS,
            options={"verify_exp": False, "verify_aud": False, "verify_iss": False, "leeway": JWT_CLOCK_TOLERANCE_SECONDS},
        )
    except JWTError as err:
        logger.error("Error verifying JWT: %s", err)
        return response.with_error(401, _SESSION_ERROR)

    try:
        session_info = SessionInfo(**payload)
    except ValidationError as err:
        # A genuine token without the fields of a session: no session
        # The field names and error types only, never the values
        fields = ", ".join(f"{'.'.join(str(part) for part in error['loc'])} ({error['type']})" for error in err.errors())
        logger.error("JWT refused, not a session token: %s", fields)
        return response.with_error(401, _SESSION_ERROR)

    problem = claims_problem(payload)
    if problem:
        mode = claims_mode()
        if mode == "enforce":
            logger.error("JWT refused: %s", problem)
            return response.with_error(401, _SESSION_ERROR)
        if mode == "warn":
            logger.warning("JWT accepted although %s", problem)

    return response.with_response(session_info)



def validate_session(token: Optional[str]) -> ResponseModel[SessionInfo]:
    validation_response: ResponseModel[SessionInfo] = validate_token(token)

    if validation_response.errorCode:
        return validation_response
    elif is_session_expired(validation_response.data.exp):
        return ResponseModel().with_error(401, "Your session has expired, please log in again.")

    return validation_response

def is_authenticated(request: Request) -> SessionUser:
    validation_response = first_valid(get_tokens(request), validate_session)

    if validation_response.errorCode:
        raise VariamosSecurityException(status_code=validation_response.errorCode, detail=validation_response)

    user = session_info_to_session_user(validation_response.data)
    if not user:
        raise VariamosSecurityException(status_code=401, detail=ResponseModel(errorCode=401, message="User not found in session"))

    request.state.user = user

    return user


