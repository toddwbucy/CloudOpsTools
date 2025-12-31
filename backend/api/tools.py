from typing import Any, Dict, List, Optional, cast

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.limiter import limiter
from backend.core.schemas.script import Tool
from backend.db.models.script import Tool as ToolModel
from backend.db.session import get_db

# Create router
router = APIRouter()


@router.get("/", response_model=List[Tool])
@limiter.limit(settings.rate_limit_read_endpoints)
async def list_tools(request: Request, db: Session = Depends(get_db)) -> List[Tool]:
    """
    List all available tools.

    This endpoint retrieves all registered tools that can be used for script execution.
    Rate limit: Read endpoints limit per minute per IP address.
    """
    tools = db.query(ToolModel).all()
    # Convert SQLAlchemy models to Pydantic schemas
    return [Tool.from_orm(tool) for tool in tools]


@router.get("/{tool_id}", response_model=Tool)
@limiter.limit(settings.rate_limit_read_endpoints)
async def get_tool(request: Request, tool_id: int, db: Session = Depends(get_db)) -> Tool:
    """
    Get a specific tool by ID.

    This endpoint retrieves detailed information about a tool.
    Rate limit: Read endpoints limit per minute per IP address.
    """
    tool = db.query(ToolModel).filter(ToolModel.id == tool_id).first()

    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool with ID {tool_id} not found",
        )

    # Convert SQLAlchemy model to Pydantic schema
    return cast(Tool, Tool.from_orm(tool))


@router.post("/{tool_id}/execute", response_model=Dict[str, Any])
@limiter.limit(settings.rate_limit_execution_endpoints)
async def execute_tool(
    request: Request,
    tool_id: int,
    parameters: Dict[str, Any] = Body(...),
    account_id: Optional[str] = Query(
        None, description="AWS account ID to run the tool on"
    ),
    region: Optional[str] = Query(None, description="AWS region to run the tool in"),
    instance_id: str = Query(..., description="EC2 instance ID to run the tool on"),
    environment: str = Query(..., description="AWS environment (gov or com)"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Execute a specific tool with provided parameters.

    This endpoint allows for direct execution of a tool with custom parameters
    without creating a script. The tool will be executed on the specified instance.
    This endpoint is rate limited more strictly due to resource consumption.
    """
    import logging
    from pathlib import Path

    from backend.providers.aws.common.services.credential_manager import (
        CredentialManager,
    )

    # Placeholder classes for type checking only
    class EC2Service:
        # Placeholder for type checking - actual implementation required
        def __init__(self, session: Any, region: str) -> None:
            self.session = session
            self.region = region

        def get_instance(self, instance_id: str) -> Dict[str, Any]:
            raise NotImplementedError("EC2Service is a placeholder - actual implementation required")

    # Placeholder for type checking - actual implementation required
    class ScriptRunner:
        def __init__(self, session: Any, region: str) -> None:
            self.session = session
            self.region = region

        def run_command(
            self, instance_id: str, command: str, **kwargs: Any
        ) -> Dict[str, Any]:
            raise NotImplementedError("ScriptRunner is a placeholder - actual implementation required")

    logger = logging.getLogger(__name__)

    # Check if tool exists
    tool = db.query(ToolModel).filter(ToolModel.id == tool_id).first()

    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool with ID {tool_id} not found",
        )

    # Validate environment
    environment = environment.lower()
    if environment not in ["gov", "com"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Environment must be 'gov' or 'com'",
        )

    # Get AWS credentials
    credential_manager = CredentialManager()
    if not credential_manager.are_credentials_valid(environment):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Valid AWS credentials for {environment} environment are required",
        )

    # Create AWS session
    session = credential_manager.create_session(environment)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create AWS session for {environment} environment",
        )

    # Get script path
    script_path = tool.script_path
    if not script_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No script path defined for tool '{tool.name}'",
        )

    # Get actual script path on server
    base_path = Path(__file__).parent.parent.parent
    full_script_path = base_path / script_path.lstrip("/")

    if not full_script_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Script not found at {script_path}",
        )

    # Special handling for the disk_checker tool
    if tool.name == "disk_checker":
        # Process parameters
        output_format = parameters.get("output_format", "json")
        output_file = parameters.get("output_file", "")

        # Build command
        command = f"{script_path}"
        if output_format == "text":
            command += " --no-json"
        if output_file:
            command += f" --output {output_file}"

        # Set up EC2 service
        # Ensure region is not None before passing to EC2Service
        safe_region = (
            region if region is not None else "us-east-1"
        )  # Default to us-east-1 if region is None
        ec2_service = EC2Service(session, safe_region)

        try:
            # Verify instance exists
            instance = ec2_service.get_instance(instance_id)
            if not instance:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Instance {instance_id} not found in region {region}",
                )

            # Check platform
            platform = instance.get("platform", "linux")
            if platform != tool.platform:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Tool '{tool.name}' is for {tool.platform} platforms, but instance is {platform}",
                )

            # Create script runner
            # Ensure region is not None before passing to ScriptRunner
            safe_region = (
                region if region is not None else "us-east-1"
            )  # Default to us-east-1 if region is None
            script_runner = ScriptRunner(session, safe_region)

            # Execute script
            logger.info(f"Executing {tool.name} on {instance_id}")
            result = script_runner.run_command(
                instance_id=instance_id,
                command=command,
                working_dir="/tmp",
                script_content=full_script_path.read_text(),
                timeout=300,  # 5 minutes timeout
            )

            return {
                "tool_id": tool_id,
                "tool_name": tool.name,
                "status": "success" if result["exit_code"] == 0 else "error",
                "instance_id": instance_id,
                "exit_code": result["exit_code"],
                "output": result["stdout"],
                "error": result["stderr"] if result["stderr"] else None,
                "execution_time": (
                    result["execution_time"] if "execution_time" in result else None
                ),
            }

        except Exception as e:
            logger.error(f"Error executing tool: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error executing tool: {str(e)}",
            )
    else:
        # Generic handler for other tools
        return {
            "tool_id": tool_id,
            "tool_name": tool.name,
            "status": "not_implemented",
            "message": f"Execution for tool '{tool.name}' not implemented yet",
            "parameters": parameters,
        }


@router.get("/{tool_id}/scripts", response_model=List[Dict[str, Any]])
@limiter.limit(settings.rate_limit_read_endpoints)
async def list_tool_scripts(
    request: Request, tool_id: int, db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """
    List all scripts associated with a specific tool.

    This endpoint retrieves all scripts that use a particular tool.
    Rate limit: Read endpoints limit per minute per IP address.
    """
    # Check if tool exists
    tool = db.query(ToolModel).filter(ToolModel.id == tool_id).first()

    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool with ID {tool_id} not found",
        )

    # Return scripts associatedwith this tool
    scripts: List[Dict[str, Any]] = []
    if tool.scripts is not None:
        scripts = [
            {
                "id": script.id,
                "name": script.name,
                "description": script.description,
                "script_type": script.script_type,
            }
            for script in tool.scripts
        ]

    return scripts