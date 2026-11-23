import logging
from typing import List
from fastapi import Request
from fastapi.responses import JSONResponse
from variamos_security.model.response_model import ResponseModel
from variamos_security.model.session_info import SessionInfo
from variamos_security.model.session_user import SessionUser
from variamos_security.functions.is_authenticated import get_token, validate_session
from variamos_security.functions.mappers import session_info_to_session_user
from variamos_security.exceptions.variamos_security_exception import VariamosSecurityException

logger = logging.getLogger(__name__)

def validate_roles(token: str, roles: List[str]) -> ResponseModel[SessionInfo]:
    response = ResponseModel[SessionInfo]()
    validation_response = validate_session(token)

    if validation_response.errorCode:
        return validation_response

    user_roles = validation_response.data.roles if validation_response.data else []

    if not any(role in roles for role in user_roles):
        return response.with_error(403, "Access denied, not enough permissions.")

    return validation_response

def has_roles(roles: List[str] = []):
    def middleware(request: Request) -> SessionUser:
        try:
            token = get_token(request)
            validation_response = validate_roles(token, roles)

            if validation_response.errorCode:
                raise VariamosSecurityException(status_code=validation_response.errorCode, detail=validation_response)

            user = session_info_to_session_user(validation_response.data)
            request.state.user = user
            
            return user
        except Exception as err:
            if isinstance(err, VariamosSecurityException):
                raise
            
            logger.error("Error verifying user roles: %s", err)

            raise VariamosSecurityException(status_code=500, detail=ResponseModel(errorCode=500, message="Internal server error"))


    return middleware