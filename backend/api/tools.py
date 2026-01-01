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
    from backend.providers.aws.script_runner.services.ec2_manager import EC2Manager
    from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor

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

        # Set up EC2 manager
        # Ensure region is not None before making API calls
        safe_region = (
            region if region is not None else "us-east-1"
        )  # Default to us-east-1 if region is None

        # Get account_id if not provided
        if not account_id:
            credential_manager_temp = CredentialManager()
            ec2_manager_temp = EC2Manager(credential_manager_temp)
            account_id = await ec2_manager_temp.get_account_id(environment)
            if not account_id:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to determine AWS account ID",
                )

        ec2_manager = EC2Manager(credential_manager)

        try:
            # Verify instance exists
            instances = await ec2_manager.describe_instances(
                account_id=account_id,
                region=safe_region,
                environment=environment,
                instance_ids=[instance_id]
            )

            if not instances:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Instance {instance_id} not found in region {safe_region}",
                )

            instance = instances[0]

            # Check platform
            platform = instance.get("Platform", "linux").lower()
            if platform != tool.platform:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Tool '{tool.name}' is for {tool.platform} platforms, but instance is {platform}",
                )

            # Create SSM executor
            ssm_executor = SSMExecutor(credential_manager)

            # Read script content
            script_content = full_script_path.read_text()

            # Execute script
            logger.info(f"Executing {tool.name} on {instance_id}")

            # Send command and wait for completion
            command_id = await ssm_executor.send_command(
                instance_id=instance_id,
                command=script_content,
                account_id=account_id,
                region=safe_region,
                environment=environment,
                comment=f"Executing tool: {tool.name}",
                timeout_seconds=300,  # 5 minutes timeout
            )

            if not command_id:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to send command to instance",
                )

            # Wait for command to complete
            result = await ssm_executor.wait_for_command_completion(
                command_id=command_id,
                instance_id=instance_id,
                account_id=account_id,
                region=safe_region,
                environment=environment,
                timeout_seconds=300,
            )

            # Parse result and return
            status_value = result.get("Status", "Unknown")
            exit_code = result.get("ExitCode", -1)
            output = result.get("Output", "")
            error = result.get("Error", "")

            return {
                "tool_id": tool_id,
                "tool_name": tool.name,
                "status": "success" if status_value == "Success" else "error",
                "instance_id": instance_id,
                "exit_code": exit_code,
                "output": output,
                "error": error if error else None,
                "command_id": command_id,
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