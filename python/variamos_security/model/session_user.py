from typing import List, Optional
from pydantic import BaseModel

class SessionUser(BaseModel):
    id: str
    name: str
    user: str
    email: str
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
