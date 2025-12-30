"""
AWS Script Runner API endpoints
"""

from fastapi import APIRouter

router = APIRouter()

# Import all API endpoints
from . import accounts, aws_operations, changes, executions, org

# Include all routers
router.include_router(accounts.router, prefix="/accounts", tags=["accounts"])
router.include_router(
    aws_operations.router, prefix="/aws-operations", tags=["aws-operations"]
)
router.include_router(changes.router, prefix="/changes", tags=["changes"])
router.include_router(org.router, prefix="/org", tags=["organization"])
router.include_router(executions.router, prefix="/executions", tags=["executions"])

# Export router for main app to discover
__all__ = ["router"]
