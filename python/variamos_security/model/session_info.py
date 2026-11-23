from typing import List, Optional, Union
from pydantic import BaseModel

class SessionInfo(BaseModel):
    sub: str
    name: str
    userName: str
    email: str
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    # Who signed the token: variamos_ms_admin since variamos-security 0.0.17
    # (Node). Older tokens have none.
    iss: Optional[str] = None
    # The host alone in older tokens, [platform, host] since 0.0.17 (Node)
    aud: Optional[Union[str, List[str]]] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
