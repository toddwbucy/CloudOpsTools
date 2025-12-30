"""Type definitions for API components"""

from datetime import datetime
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar

from fastapi import Path, Query
from pydantic import BaseModel

# Generic type for Pydantic models
T = TypeVar("T")
CreateSchemaType = TypeVar("CreateSchemaType")
UpdateSchemaType = TypeVar("UpdateSchemaType")


# Pagination parameters
class PaginationParams:
    """Pagination parameters for list endpoints"""

    def __init__(
        self,
        skip: int = 0,
        limit: int = 100,
    ):
        self.skip = skip
        self.limit = limit


# Response models
class StatusResponse(BaseModel):
    """Standard status response"""

    success: bool
    message: str


class ErrorResponse(BaseModel):
    """Standard error response"""

    error: str
    detail: Optional[str] = None
    status_code: int


class ItemListResponse(BaseModel, Generic[T]):
    """Generic response for lists of items"""

    items: List[T]
    total: int
    skip: int
    limit: int


# API responses
SuccessResponse = Dict[str, Any]
ListResponse = Dict[str, Any]
DetailResponse = Dict[str, Any]

# Dependency types
DependencyCallable = Callable[..., Any]

# Path parameters
PathId = Path(..., title="Item ID", ge=1)

# Common query parameters
StatusFilter = Query(None, title="Status filter")
StartDateFilter = Query(None, title="Start date filter")
EndDateFilter = Query(None, title="End date filter")


# Authentication types
class TokenData(BaseModel):
    """JWT token data"""

    sub: str
    exp: datetime
    iat: datetime
    scope: List[str] = []
