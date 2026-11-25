import logging
from datetime import datetime, timezone
from typing import List, Optional, Union
from jose import jwt
from variamos_security.config.security_config import get_private_key
from variamos_security.config.token_claims import audience_host, jwt_audience, jwt_issuer
from variamos_security.config.token_lifetime import jwt_expires_in_seconds
from variamos_security.model.session_user import SessionUser

logger = logging.getLogger(__name__)

def create_jwt(user: SessionUser, aud: Optional[Union[str, List[str]]] = None) -> str:
    """
    Signs a session token for user, as the Node library does: it carries the
    issuer (VARIAMOS_JWT_ISSUER) and the platform audience
    (VARIAMOS_JWT_AUDIENCE), followed by the host the user goes to when one
    is given: aud is then [platform, host]. Given the aud of a token being
    refreshed, the host is kept and the platform set again.
    """
    key = get_private_key()

    if not user:
        logger.error("User is undefined")
        raise ValueError("No user information provided")

    if not key:
        logger.error("Private key not found")
        raise ValueError("Error on jwt creation")

    expires_in_seconds = jwt_expires_in_seconds()
    current_date_in_seconds = int(datetime.now(timezone.utc).timestamp())

    host = audience_host(aud)

    payload = {
        "sub": user.id,
        "name": user.name,
        "userName": user.user,
        "email": user.email,
        "roles": user.roles,
        "permissions": user.permissions,
        "iat": current_date_in_seconds,
        "exp": current_date_in_seconds + expires_in_seconds,
        "iss": jwt_issuer(),
        "aud": [jwt_audience(), host] if host else jwt_audience(),
    }

    token = jwt.encode(payload, key.to_pem().decode('utf-8'), algorithm='RS256')
    return token