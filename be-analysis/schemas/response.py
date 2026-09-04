from pydantic import BaseModel


class ApiResponse(BaseModel):
    success: bool = True
    message: str = "OK"
    data: object | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    errors: object | None = None