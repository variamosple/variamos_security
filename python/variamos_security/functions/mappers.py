from typing import Optional
from variamos_security.model.session_info import SessionInfo
from variamos_security.model.session_user import SessionUser

def session_info_to_session_user(session_info: Optional[SessionInfo]) -> Optional[SessionUser]:
    if not session_info or not session_info.model_dump():
        return None

    return SessionUser(
        id=session_info.sub,
        name=session_info.name,
        user=session_info.userName,
        email=session_info.email,
        roles=session_info.roles,
        permissions=session_info.permissions
    )