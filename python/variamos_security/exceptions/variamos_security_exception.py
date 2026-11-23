from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from variamos_security.model.response_model import ResponseModel

class VariamosSecurityException(HTTPException):
    def __init__(self, status_code: int, detail: ResponseModel, headers: dict = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)

async def variamos_security_exception_handler(request: Request, exc: VariamosSecurityException):
    response: ResponseModel = exc.detail

    return JSONResponse(
        status_code=exc.status_code,
        content={"error": response.model_dump()},
    )