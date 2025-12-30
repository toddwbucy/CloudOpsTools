"""
Execution API endpoints module.

This module contains all execution-related endpoints split into logical groups:
- single.py: Single execution endpoints
- batch.py: Batch execution endpoints
- status.py: Status and monitoring endpoints
- reports.py: Report generation endpoints
- tasks.py: Background task functions
"""

from fastapi import APIRouter

from .reports import router as reports_router

# Import routers from submodules
from .single import router as single_router

# from .batch import router as batch_router  # Disabled - using main executions.py implementation
from .status import router as status_router

# Create main executions router
router = APIRouter(
    tags=["executions"],
    responses={
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)

# Include all sub-routers
router.include_router(single_router)
# router.include_router(batch_router)  # Disabled - using main executions.py implementation
router.include_router(status_router)
router.include_router(reports_router)
