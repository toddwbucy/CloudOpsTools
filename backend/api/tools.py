"""
Tools API endpoints with rate limiting.

This module provides tool management endpoints including tool execution.
Execution endpoints are rate limited more strictly due to resource consumption.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.core.limiter import limiter

# Create router for tools endpoints
router = APIRouter(prefix="/api/tools", tags=["tools"])


class ToolExecuteRequest(BaseModel):
    """Request model for tool execution."""

    parameters: Optional[Dict[str, Any]] = Field(
        None, description="Optional parameters for tool execution"
    )


class ToolExecuteResponse(BaseModel):
    """Response model for tool execution."""

    tool_id: str
    status: str
    message: str
    result: Optional[Dict[str, Any]] = None


# In-memory storage for demo purposes
# In production, this would be a database
_tools_store: Dict[str, Dict[str, Any]] = {
    "1": {
        "id": "1",
        "name": "health_check",
        "description": "Performs a health check on target systems",
        "enabled": True,
    },
    "2": {
        "id": "2",
        "name": "disk_cleanup",
        "description": "Cleans up temporary files on target systems",
        "enabled": True,
    },
    "3": {
        "id": "3",
        "name": "log_collector",
        "description": "Collects logs from target systems",
        "enabled": False,
    },
}


@router.post("/{tool_id}/execute", response_model=ToolExecuteResponse)
@limiter.limit(settings.rate_limit_execution_endpoints)
async def execute_tool(
    request: Request,
    tool_id: str,
    execute_request: Optional[ToolExecuteRequest] = None,
):
    """
    Execute a specific tool by its ID.

    This endpoint is rate limited more strictly (5/minute) because tool
    execution consumes significant server resources and may interact
    with external systems.

    Rate limit: 5 requests per minute per IP address.

    Args:
        request: FastAPI request object (required for rate limiting)
        tool_id: The unique identifier of the tool to execute
        execute_request: Optional parameters for execution

    Returns:
        ToolExecuteResponse with execution status and results

    Raises:
        HTTPException: If tool not found or disabled
    """
    # Check if tool exists
    tool = _tools_store.get(tool_id)
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool with ID '{tool_id}' not found"
        )

    # Check if tool is enabled
    if not tool.get("enabled", False):
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{tool['name']}' is currently disabled"
        )

    # Simulate tool execution
    # In production, this would actually execute the tool
    parameters = execute_request.parameters if execute_request else {}

    return ToolExecuteResponse(
        tool_id=tool_id,
        status="completed",
        message=f"Tool '{tool['name']}' executed successfully",
        result={
            "executed_with_parameters": parameters,
            "tool_name": tool["name"],
        },
    )
