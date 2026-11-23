import os
import logging
from datetime import datetime, timezone
from jose import jwt
from variamos_security.config.security_config import get_private_key
from variamos_security.model.session_user import SessionUser

logger = logging.getLogger(__name__)

def create_jwt(user: SessionUser, aud: str = None) -> str:
    key = get_private_key()

    if not user:
        logger.error("User is undefined")
        raise ValueError("No user information provided")

    if not key:
        logger.error("Private key not found")
        raise ValueError("Error on jwt creation")

    expires_in_seconds = int(os.getenv('VARIAMOS_JWT_EXP_IN_SECONDS', 900))
    current_date_in_seconds = int(datetime.now(timezone.utc).timestamp())

    payload = {
        "sub": user.id,
        "name": user.name,
        "userName": user.user,
        "email": user.email,
        "roles": user.roles,
        "permissions": user.permissions,
        "iat": current_date_in_seconds,
        "exp": current_date_in_seconds + expires_in_seconds,
        "aud": aud,
    }

    token = jwt.encode(payload, key.to_pem().decode('utf-8'), algorithm='RS256')
    return token