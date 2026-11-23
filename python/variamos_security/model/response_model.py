from typing import Generic, TypeVar, Optional
from pydantic import BaseModel

Type = TypeVar('T')

class ResponseModel(BaseModel, Generic[Type]):
    transactionId: Optional[str] = None
    errorCode: Optional[int] = None
    message: Optional[str] = None
    totalCount: Optional[int] = None
    data: Optional[Type] = None

    def with_response(self, data: Type, totalCount: Optional[int] = None) -> 'ResponseModel[Type]':
        self.data = data
        self.totalCount = totalCount
        return self

    def with_error(self, errorCode: int, errorMessage: str) -> 'ResponseModel[Type]':
        self.errorCode = errorCode
        self.message = errorMessage
        return self