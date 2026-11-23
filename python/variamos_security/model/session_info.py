from typing import List, Optional
from pydantic import BaseModel

class SessionInfo(BaseModel):
    sub: str
    name: str
    userName: str
    email: str
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    aud: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None