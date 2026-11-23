import logging
from typing import Optional
from datetime import datetime, timezone
from jose import jwt, JWTError
from fastapi import Request
from variamos_security.config.security_config import get_private_key, get_public_key
from variamos_security.model.session_info import SessionInfo
from variamos_security.model.session_user import SessionUser
from variamos_security.model.response_model import ResponseModel
from variamos_security.functions.mappers import session_info_to_session_user
from variamos_security.exceptions.variamos_security_exception import VariamosSecurityException

logger = logging.getLogger(__name__)

def get_token(request: Request) -> str:
    if "authToken" in request.cookies:
        return request.cookies["authToken"]

    token = request.headers.get("Authorization")
    return "" if not token else token.replace("Bearer ", "")



def is_session_expired(expiration_date_in_seconds: Optional[int]) -> bool:
    return not expiration_date_in_seconds or datetime.now(timezone.utc).timestamp() > expiration_date_in_seconds



def validate_token(token: Optional[str]) -> ResponseModel[SessionInfo]:
    response = ResponseModel[SessionInfo]()

    if not token:
        return response.with_error(401, "Please log in.")

    key = get_public_key() or get_private_key()

    if not key:
        logger.error("Public and/or private key not found")
        return response.with_error(401, "Error on session validation, please try again.")

    try:
        payload = jwt.decode(token, key.to_pem().decode('utf-8'), algorithms=['RS256'], options={"verify_exp": False, "verify_aud": False})
        response.with_response(SessionInfo(**payload))
    except JWTError as err:
        logger.error("Error verifying JWT: %s", err)
        response.with_error(401, "Error on session validation, please try again.")

    return response



def validate_session(token: Optional[str]) -> ResponseModel[SessionInfo]:
    validation_response: ResponseModel[SessionInfo] = validate_token(token)

    if validation_response.errorCode:
        return validation_response
    elif is_session_expired(validation_response.data.exp):
        return ResponseModel().with_error(401, "Your session has expired, please log in again.")

    return validation_response

def is_authenticated(request: Request) -> SessionUser:
    validation_response = validate_session(get_token(request))

    if validation_response.errorCode:
        raise VariamosSecurityException(status_code=validation_response.errorCode, detail=validation_response)

    user = session_info_to_session_user(validation_response.data)
    if not user:
        raise VariamosSecurityException(status_code=401, detail=ResponseModel(errorCode=401, message="User not found in session"))

    request.state.user = user

    return user


