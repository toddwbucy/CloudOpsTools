from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from backend.core.utils.type_helpers import (
    safe_int,
    safe_str,
)
from backend.db.models.account import Account as AccountModel
from backend.db.models.account import Instance as InstanceModel
from backend.db.models.account import Region as RegionModel
from backend.db.models.execution import Execution as ExecutionModel
from backend.db.models.execution import ExecutionBatch as ExecutionBatchModel
from backend.db.models.script import Script as ScriptModel
from backend.db.session import get_db
from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.docs.executions import (
    BATCH_PROGRESS_EXAMPLE,
    CREATE_EXECUTION_DESCRIPTION,
    EXECUTION_LIST_EXAMPLE,
    EXECUTION_RESPONSE_EXAMPLE,
    EXECUTION_STATUS_EXAMPLE,
    GET_BATCH_PROGRESS_DESCRIPTION,
    GET_EXECUTION_DESCRIPTION,
    GET_EXECUTION_STATUS_DESCRIPTION,
    LIST_EXECUTIONS_DESCRIPTION,
)
from backend.providers.aws.script_runner.schemas.execution import (
    CommandInfo,
    Execution,
    ExecutionBatchCreate,
    ExecutionBatchWithCommands,
    ExecutionCreate,
    ExecutionList,
    ExecutionProgress,
    ExecutionStatus,
    InstanceData,
)
from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor

# Create router
router = APIRouter(
    tags=["executions"],
    responses={
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)


async def execute_script_task_with_metadata(
    execution_id: int, db_session: Session, aws_credentials
) -> None:
    """
    Background task to execute a script on an EC2 instance using metadata.

    Args:
        execution_id: ID of the execution record
        db_session: Database session
        aws_credentials: AWS credentials (AWSCredentials object or dict)
    """
    # Get execution from database
    execution = (
        db_session.query(ExecutionModel)
        .filter(ExecutionModel.id == execution_id)
        .first()
    )
    if not execution:
        return

    # Update status to running
    execution.status = ExecutionStatus.RUNNING.value
    db_session.commit()

    try:
        # Get script details
        script = (
            db_session.query(ScriptModel)
            .filter(ScriptModel.id == execution.script_id)
            .first()
        )
        if not script:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Script not found in database"
            db_session.commit()
            return

        # Get instance data from execution metadata
        metadata: dict[str, str] = execution.execution_metadata or {}
        instance_id = metadata.get("instance_id")
        account_id = metadata.get("account_id")
        region = metadata.get("region")
        environment = metadata.get("environment")

        if not all([instance_id, account_id, region, environment]):
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Missing instance metadata for execution"
            db_session.commit()
            return

        # Set up credential manager with the provided credentials
        temp_credential_manager = CredentialManager()
        temp_credential_manager.store_credentials(aws_credentials)

        # Create SSM executor with the credentials
        temp_ssm_executor = SSMExecutor(temp_credential_manager)

        # Extract the values we need for SSM execution
        instance_id_str = safe_str(instance_id)
        # Normalize line endings - convert Windows CRLF (\r\n) to Unix LF (\n)
        raw_content = safe_str(script.content)
        command_str = raw_content.replace("\r\n", "\n").replace("\r", "\n")
        account_id_str = safe_str(account_id)
        region_str = safe_str(region)
        environment_str = safe_str(environment)

        # Execute the script via SSM
        command_id = await temp_ssm_executor.send_command(
            instance_id=instance_id_str,
            command=command_str,
            account_id=account_id_str,
            region=region_str,
            environment=environment_str,
            comment=f"Execution ID: {execution_id}",
        )

        if not command_id:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Failed to send command to instance"
            db_session.commit()
            return

        # Update execution record with command ID
        execution.command_id = command_id
        db_session.commit()

        # Wait for command completion
        result = await temp_ssm_executor.wait_for_command_completion(
            command_id=command_id,
            instance_id=instance_id_str,
            account_id=account_id_str,
            region=region_str,
            environment=environment_str,
        )

        # Update execution record with results
        execution.output = result.get("Output", "") + "\n" + result.get("Error", "")
        execution.exit_code = result.get("ExitCode")
        execution.status = (
            ExecutionStatus.COMPLETED.value
            if result.get("Status") == "Success"
            else ExecutionStatus.FAILED.value
        )
        execution.end_time = datetime.utcnow()
        db_session.commit()

    except Exception as e:
        # Handle any exceptions
        execution.status = ExecutionStatus.FAILED.value
        execution.output = f"Error executing script: {str(e)}"
        execution.end_time = datetime.utcnow()
        db_session.commit()


async def monitor_command_task(
    execution_id: int, db_session: Session, aws_credentials
) -> None:
    """
    Background task to monitor an existing SSM command.
    This assumes the command has already been sent and has a command_id.

    Args:
        execution_id: ID of the execution record (with existing command_id)
        db_session: Database session
        aws_credentials: AWS credentials (AWSCredentials object or dict)
    """
    execution = (
        db_session.query(ExecutionModel)
        .filter(ExecutionModel.id == execution_id)
        .first()
    )
    if not execution:
        return

    # Check if command_id exists (should have been set in main request)
    if not execution.command_id:
        execution.status = ExecutionStatus.FAILED.value
        execution.output = "No command ID found for monitoring"
        execution.end_time = datetime.utcnow()
        db_session.commit()
        return

    try:
        # Get instance data from execution metadata
        metadata: dict[str, str] = execution.execution_metadata or {}
        instance_id = metadata.get("instance_id")
        account_id = metadata.get("account_id")
        region = metadata.get("region")
        environment = metadata.get("environment")

        if not all([instance_id, account_id, region, environment]):
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Missing instance metadata for monitoring"
            execution.end_time = datetime.utcnow()
            db_session.commit()
            return

        # Set up credential manager with the provided credentials
        temp_credential_manager = CredentialManager()
        temp_credential_manager.store_credentials(aws_credentials)

        # Create SSM executor with the credentials
        temp_ssm_executor = SSMExecutor(temp_credential_manager)

        # Extract the values we need for SSM monitoring
        instance_id_str = safe_str(instance_id)
        account_id_str = safe_str(account_id)
        region_str = safe_str(region)
        environment_str = safe_str(environment)

        # Wait for command completion
        result = await temp_ssm_executor.wait_for_command_completion(
            command_id=execution.command_id,
            instance_id=instance_id_str,
            account_id=account_id_str,
            region=region_str,
            environment=environment_str,
        )

        # Update execution record with results
        execution.output = result.get("Output", "") + "\n" + result.get("Error", "")
        execution.exit_code = result.get("ExitCode")
        execution.status = (
            ExecutionStatus.COMPLETED.value
            if result.get("Status") == "Success"
            else ExecutionStatus.FAILED.value
        )
        execution.end_time = datetime.utcnow()
        db_session.commit()

    except Exception as e:
        # Handle any exceptions
        execution.status = ExecutionStatus.FAILED.value
        execution.output = f"Error monitoring command: {str(e)}"
        execution.end_time = datetime.utcnow()
        db_session.commit()


async def execute_script_task(execution_id: int, db_session: Session) -> None:
    """
    Background task to execute a script on an EC2 instance.

    Args:
        execution_id: ID of the execution record
        db_session: Database session
    """
    # Get execution from database
    execution = (
        db_session.query(ExecutionModel)
        .filter(ExecutionModel.id == execution_id)
        .first()
    )
    if not execution:
        return

    # Update status to running
    execution.status = ExecutionStatus.RUNNING.value
    db_session.commit()

    try:
        # Get instance details
        instance = (
            db_session.query(InstanceModel)
            .filter(InstanceModel.id == execution.instance_id)
            .first()
        )
        if not instance:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Instance not found in database"
            db_session.commit()
            return

        # Get region and account details
        region = (
            db_session.query(RegionModel)
            .filter(RegionModel.id == instance.region_id)
            .first()
        )
        if not region:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Region not found in database"
            db_session.commit()
            return

        account = (
            db_session.query(AccountModel)
            .filter(AccountModel.id == region.account_id)
            .first()
        )
        if not account:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Account not found in database"
            db_session.commit()
            return

        # Get script details
        script = (
            db_session.query(ScriptModel)
            .filter(ScriptModel.id == execution.script_id)
            .first()
        )
        if not script:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Script not found in database"
            db_session.commit()
            return

        # Check if all required objects are available and get the values we need
        if instance is None or script is None or account is None or region is None:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = (
                "Missing required instance, script, account, or region information"
            )
            db_session.commit()
            return

        # Extract the values we need for SSM execution with safe string conversion
        instance_id_str = safe_str(instance.instance_id)
        # Normalize line endings - convert Windows CRLF (\r\n) to Unix LF (\n)
        raw_content = safe_str(script.content)
        command_str = raw_content.replace("\r\n", "\n").replace("\r", "\n")
        account_id_str = safe_str(account.account_id)
        region_str = safe_str(region.name)
        environment_str = safe_str(account.environment)

        # Initialize credential manager and SSM executor
        credential_manager = CredentialManager()
        ssm_executor = SSMExecutor(credential_manager)

        # Execute the script via SSM
        command_id = await ssm_executor.send_command(
            instance_id=instance_id_str,
            command=command_str,
            account_id=account_id_str,
            region=region_str,
            environment=environment_str,
            comment=f"Execution ID: {execution_id}",
        )

        if not command_id:
            execution.status = ExecutionStatus.FAILED.value
            execution.output = "Failed to send command to instance"
            db_session.commit()
            return

        # Update execution record with command ID
        execution.command_id = command_id
        db_session.commit()

        # Wait for command completion
        result = await ssm_executor.wait_for_command_completion(
            command_id=command_id,
            instance_id=instance_id_str,
            account_id=account_id_str,
            region=region_str,
            environment=environment_str,
        )

        # Update execution record with results
        execution.output = result.get("Output", "") + "\n" + result.get("Error", "")
        execution.exit_code = result.get("ExitCode")
        execution.status = (
            ExecutionStatus.COMPLETED.value
            if result.get("Status") == "Success"
            else ExecutionStatus.FAILED.value
        )
        execution.end_time = datetime.utcnow()
        db_session.commit()

    except Exception as e:
        # Handle any exceptions
        execution.status = ExecutionStatus.FAILED.value
        execution.output = f"Error executing script: {str(e)}"
        execution.end_time = datetime.utcnow()
        db_session.commit()


@router.post(
    "/",
    response_model=Execution,
    status_code=status.HTTP_201_CREATED,
    summary="Create Execution",
    description=CREATE_EXECUTION_DESCRIPTION,
    response_description="Created execution details",
    responses={
        201: {
            "content": {"application/json": {"example": EXECUTION_RESPONSE_EXAMPLE}},
        },
        404: {"description": "Script or instance not found"},
    },
)
async def create_execution(
    execution: ExecutionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Execution:
    """
    Create a new script execution.

    This endpoint creates a new execution record and starts the script execution
    on the specified EC2 instance as a background task.
    """
    # Check if script exists
    script = db.query(ScriptModel).filter(ScriptModel.id == execution.script_id).first()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Script with ID {execution.script_id} not found",
        )

    # Check if instance exists
    instance = (
        db.query(InstanceModel)
        .filter(InstanceModel.id == execution.instance_id)
        .first()
    )
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Instance with ID {execution.instance_id} not found",
        )

    # Create execution record
    db_execution = ExecutionModel(
        script_id=execution.script_id,
        instance_id=execution.instance_id,
        status=ExecutionStatus.PENDING.value,
        start_time=datetime.utcnow(),
    )

    # Save to database
    db.add(db_execution)
    db.commit()
    db.refresh(db_execution)

    # Start background task to execute the script
    # Get the execution ID as an integer to pass to the background task
    execution_id = safe_int(db_execution.id)
    # Start the background task with the execution ID and a new database session
    background_tasks.add_task(execute_script_task, execution_id, db)

    # Convert SQLAlchemy model to Pydantic schema
    return Execution.from_orm(db_execution)


@router.get(
    "/",
    response_model=ExecutionList,
    summary="List Executions",
    description=LIST_EXECUTIONS_DESCRIPTION,
    response_description="List of executions with pagination info",
    responses={
        200: {
            "content": {"application/json": {"example": EXECUTION_LIST_EXAMPLE}},
        }
    },
)
def list_executions(
    status: Optional[str] = None,
    script_id: Optional[int] = None,
    instance_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> ExecutionList:
    """
    List all executions with optional filtering.

    This endpoint retrieves executions with pagination and filtering options.
    """
    # Build query with joins to get script names
    query = db.query(ExecutionModel).join(
        ScriptModel, ExecutionModel.script_id == ScriptModel.id
    )

    # Apply filters
    if status:
        query = query.filter(ExecutionModel.status == status)

    if script_id:
        query = query.filter(ExecutionModel.script_id == script_id)

    if instance_id:
        query = query.filter(ExecutionModel.instance_id == instance_id)

    # Get total count
    total = query.count()

    # Apply ordering first, then pagination
    if hasattr(ExecutionModel, "start_time") and ExecutionModel.start_time is not None:
        ordered_query = query.order_by(ExecutionModel.start_time.desc())
    else:
        ordered_query = query

    # Apply pagination after ordering
    executions = ordered_query.offset(skip).limit(limit).all()

    # Convert SQLAlchemy models to Pydantic schemas with script names
    pydantic_executions = []
    for execution in executions:
        # Build execution data dictionary with proper types
        execution_data = {
            "id": execution.id,
            "script_id": execution.script_id,
            "instance_id": execution.instance_id,
            "status": (
                ExecutionStatus(execution.status)
                if isinstance(execution.status, str)
                else execution.status
            ),
            "start_time": execution.start_time,
            "end_time": execution.end_time,
            "output": execution.output,
            "exit_code": execution.exit_code,
            "command_id": execution.command_id,
            "batch_id": execution.batch_id,
            "script_name": (
                execution.script.name
                if execution.script
                else f"Script {execution.script_id}"
            ),
            "error_message": getattr(execution, "error_message", None),
            "metadata": execution.execution_metadata,
        }

        # Handle instance data for matrix display
        if execution.instance:
            execution_data["instance_id"] = execution.instance.instance_id
        elif (
            execution.execution_metadata
            and "instance_id" in execution.execution_metadata
        ):
            execution_data["instance_id"] = execution.execution_metadata["instance_id"]
        else:
            execution_data["instance_id"] = f"Instance_{execution.instance_id}"

        pydantic_executions.append(Execution.model_validate(execution_data))

    return ExecutionList(executions=pydantic_executions, total=total)


@router.get(
    "/{execution_id}",
    response_model=Execution,
    summary="Get Execution",
    description=GET_EXECUTION_DESCRIPTION,
    response_description="Detailed execution information",
    responses={
        200: {
            "content": {"application/json": {"example": EXECUTION_RESPONSE_EXAMPLE}},
        },
        404: {"description": "Execution not found"},
    },
)
def get_execution(execution_id: int, db: Session = Depends(get_db)) -> Execution:
    """
    Get a specific execution by ID.
    """
    execution = (
        db.query(ExecutionModel)
        .join(ScriptModel, ExecutionModel.script_id == ScriptModel.id)
        .filter(ExecutionModel.id == execution_id)
        .first()
    )

    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution with ID {execution_id} not found",
        )

    # Convert SQLAlchemy model to Pydantic schema with script name
    execution_data = {
        "id": execution.id,
        "script_id": execution.script_id,
        "instance_id": execution.instance_id,
        "status": (
            ExecutionStatus(execution.status)
            if isinstance(execution.status, str)
            else execution.status
        ),
        "start_time": execution.start_time,
        "end_time": execution.end_time,
        "output": execution.output,
        "exit_code": execution.exit_code,
        "command_id": execution.command_id,
        "batch_id": execution.batch_id,
        "script_name": (
            execution.script.name
            if execution.script
            else f"Script {execution.script_id}"
        ),
        "error_message": getattr(execution, "error_message", None),
        "metadata": execution.execution_metadata,
    }

    # Handle instance data for matrix display
    if execution.instance:
        execution_data["instance_id"] = execution.instance.instance_id
    elif execution.execution_metadata and "instance_id" in execution.execution_metadata:
        execution_data["instance_id"] = execution.execution_metadata["instance_id"]
    else:
        execution_data["instance_id"] = f"Instance_{execution.instance_id}"

    return Execution.model_validate(execution_data)


@router.get(
    "/{execution_id}/status",
    response_model=Dict[str, Any],
    summary="Get Execution Status",
    description=GET_EXECUTION_STATUS_DESCRIPTION,
    response_description="Current execution status",
    responses={
        200: {
            "content": {"application/json": {"example": EXECUTION_STATUS_EXAMPLE}},
        },
        404: {"description": "Execution not found"},
    },
)
async def get_execution_status(
    execution_id: int,
    refresh: bool = Query(False, description="Refresh status from AWS if applicable"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get the current status of an execution.

    This endpoint retrieves the current status of an execution and optionally
    refreshes it from AWS if the execution is still running.
    """
    execution = (
        db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
    )

    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution with ID {execution_id} not found",
        )

    # If refresh is requested and the execution is still running with a command ID
    if (
        refresh
        and execution.status == ExecutionStatus.RUNNING.value
        and execution.command_id
    ):
        try:
            # Get instance details
            instance = (
                db.query(InstanceModel)
                .filter(InstanceModel.id == execution.instance_id)
                .first()
            )
            if not instance:
                return {"status": execution.status, "message": "Instance not found"}

            # Get region and account details
            region = (
                db.query(RegionModel)
                .filter(RegionModel.id == instance.region_id)
                .first()
            )
            if not region:
                return {"status": execution.status, "message": "Region not found"}

            account = (
                db.query(AccountModel)
                .filter(AccountModel.id == region.account_id)
                .first()
            )
            if not account:
                return {"status": execution.status, "message": "Account not found"}

            # Initialize credential manager and SSM executor
            credential_manager = CredentialManager()
            ssm_executor = SSMExecutor(credential_manager)

            # Get latest status from AWS
            result = await ssm_executor.get_command_status(
                command_id=execution.command_id,
                instance_id=instance.instance_id,
                account_id=account.account_id,
                region=region.name,
                environment=account.environment,
            )

            # Update execution if status has changed
            aws_status = result.get("Status")
            if aws_status in ["Success", "Failed", "Cancelled", "TimedOut"]:
                if aws_status == "Success":
                    execution.status = ExecutionStatus.COMPLETED.value
                else:
                    execution.status = ExecutionStatus.FAILED.value

                execution.output = (
                    result.get("Output", "") + "\n" + result.get("Error", "")
                )
                execution.exit_code = result.get("ExitCode")
                execution.end_time = datetime.utcnow()
                db.commit()

            return {
                "execution_id": execution_id,
                "status": execution.status,
                "aws_status": aws_status,
                "exit_code": result.get("ExitCode"),
                "last_updated": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            return {
                "execution_id": execution_id,
                "status": execution.status,
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat(),
            }

    # Return current status from database
    return {
        "execution_id": execution_id,
        "status": execution.status,
        "start_time": (
            execution.start_time.isoformat() if execution.start_time else None
        ),
        "end_time": execution.end_time.isoformat() if execution.end_time else None,
        "exit_code": execution.exit_code,
    }


@router.post(
    "/batch",
    response_model=ExecutionBatchWithCommands,
    status_code=status.HTTP_201_CREATED,
)
async def create_execution_batch(
    batch: ExecutionBatchCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    x_aws_access_key: Optional[str] = Header(None, alias="X-AWS-Access-Key"),
    x_aws_secret_key: Optional[str] = Header(None, alias="X-AWS-Secret-Key"),
    x_aws_session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token"),
    x_aws_environment: Optional[str] = Header(None, alias="X-AWS-Environment"),
) -> ExecutionBatchWithCommands:
    """
    Create multiple script executions on different instances.

    This endpoint allows executing the same script on multiple instances in a single API call.
    """
    import logging

    logger = logging.getLogger(__name__)
    logger.debug(f"Received batch execution request: {batch}")
    logger.debug(f"Batch script_id: {batch.script_id}")
    logger.debug(f"Batch instances: {batch.instances}")
    logger.debug(f"Batch name: {batch.name}")
    logger.debug(f"Batch description: {batch.description}")
    logger.debug(f"AWS credentials provided: {bool(x_aws_access_key)}")
    logger.debug(f"AWS environment: {x_aws_environment}")

    # Handle credentials - either from headers or from stored credentials
    credentials = None
    environment = None

    if x_aws_access_key and x_aws_secret_key and x_aws_environment:
        # Credentials provided in headers - use them directly
        logger.debug("Using credentials from request headers")
        environment = x_aws_environment

        from backend.core.config import AWSCredentials, AWSEnvironment

        credentials = AWSCredentials(
            access_key=x_aws_access_key,
            secret_key=x_aws_secret_key,
            session_token=x_aws_session_token,
            environment=AWSEnvironment(x_aws_environment),
        )
        logger.debug(f"Using credentials for environment: {x_aws_environment}")

        # Create local instance of credential manager
        credential_manager = CredentialManager()

        # Store the credentials in credential manager
        credential_manager.store_credentials(credentials)

        # Validate credentials using credential manager
        validation_result = credential_manager.are_credentials_valid(x_aws_environment)
        if not validation_result["valid"]:
            logger.error(
                f"Invalid AWS credentials for environment: {x_aws_environment}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid AWS credentials for {x_aws_environment} environment",
            )

        logger.debug(
            f"AWS credentials validated successfully for environment: {x_aws_environment}"
        )

    else:
        # No credentials in headers - check for stored credentials
        logger.debug("No credentials in headers, checking stored credentials")

        # Create local instance of credential manager for stored credentials lookup
        credential_manager = CredentialManager()

        # Determine environment from instances
        environments_needed = set()
        for instance in batch.instances:
            if instance.region and "gov" in instance.region.lower():
                environments_needed.add("gov")
            else:
                environments_needed.add("com")

        # Use the first available environment with credentials
        for env in ["gov", "com"]:  # Prioritize gov if both are needed
            if env in environments_needed:
                # Use the public interface for credential retrieval
                try:
                    # First check if credentials are available
                    logger.debug(f"Checking for credentials in environment: {env}")
                    credentials = credential_manager.get_credentials(env)
                    if credentials:
                        environment = env
                        logger.debug(f"Retrieved credentials for environment: {env}")
                        logger.debug(f"Credentials type: {type(credentials)}")
                        logger.debug(
                            f"Has access_key: {hasattr(credentials, 'access_key')}"
                        )
                        break
                    else:
                        logger.debug(f"No credentials found for environment: {env}")
                except Exception as cred_error:
                    logger.warning(
                        f"Error accessing credentials for {env}: {cred_error}"
                    )
                    import traceback

                    logger.warning(f"Traceback: {traceback.format_exc()}")
                    continue

        if not credentials or not environment:
            logger.error(
                "No valid stored credentials found for any required environment"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AWS credentials are required. Please provide credentials in headers or configure them in the system.",
            )

    # Check if script exists
    script = db.query(ScriptModel).filter(ScriptModel.id == batch.script_id).first()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Script with ID {batch.script_id} not found",
        )

    # Validate instances data
    if not batch.instances or len(batch.instances) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No instances provided for batch execution",
        )

    logger.debug(f"Processing {len(batch.instances)} instances for execution")

    # Validate that all instances have required fields
    for i, instance in enumerate(batch.instances):
        if not instance.instance_id or not instance.account_id or not instance.region:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Instance {i} is missing required fields (instance_id, account_id, region)",
            )
        logger.debug(
            f"Instance {i}: {instance.instance_id} in {instance.account_id}/{instance.region}"
        )

    # Auto-generate name if not provided
    batch_name = (
        batch.name
        or f"Batch-{batch.change_number or 'Unknown'}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    )
    batch_description = (
        batch.description
        or f"Script execution batch for change {batch.change_number or 'Unknown'} on {len(batch.instances)} instances"
    )

    logger.debug(f"Creating batch: {batch_name}")

    # Create execution batch record
    db_batch = ExecutionBatchModel(
        name=batch_name,
        description=batch_description,
        status=ExecutionStatus.PENDING.value,
        start_time=datetime.utcnow(),
        parameters=batch.parameters,
    )

    # Save batch to database
    db.add(db_batch)
    db.commit()
    db.refresh(db_batch)

    # Group instances by account + region for efficient SSM command sending
    instance_groups: Dict[Tuple[str, str, str], List[InstanceData]] = {}
    for instance_data in batch.instances:
        key = (
            instance_data.account_id,
            instance_data.region,
            instance_data.environment,
        )
        if key not in instance_groups:
            instance_groups[key] = []
        instance_groups[key].append(instance_data)

    logger.debug(f"Grouped instances into {len(instance_groups)} account/region groups")

    # Create SSM executor
    ssm_executor = SSMExecutor(credential_manager)
    command_mapping = {}

    # Send SSM commands per group and create execution records
    execution_ids: list[int] = []

    for (account_id, region, environment), instances in instance_groups.items():
        logger.debug(
            f"Processing group: {account_id}/{region} ({environment}) with {len(instances)} instances"
        )

        # Normalize line endings in script content
        raw_content = safe_str(script.content)
        command_str = raw_content.replace("\r\n", "\n").replace("\r", "\n")

        # Extract instance IDs for this group
        instance_ids = [inst.instance_id for inst in instances]

        # Send single command to all instances in this region
        logger.info(
            f"Sending SSM command to {len(instance_ids)} instances in {account_id}/{region}"
        )
        command_id = await ssm_executor.send_command_to_multiple_instances(
            instance_ids=instance_ids,
            command=command_str,
            account_id=safe_str(account_id),
            region=safe_str(region),
            environment=safe_str(environment),
            comment=f"Batch {db_batch.id} - Change {batch.change_number or 'Unknown'}",
        )

        if command_id:
            logger.info(
                f"Command {command_id} sent successfully to {len(instance_ids)} instances"
            )

            # Store command mapping
            command_mapping[command_id] = CommandInfo(
                account=safe_str(account_id),
                region=safe_str(region),
                instanceIDs=[safe_str(inst_id) for inst_id in instance_ids],
            )

            # Create execution records for each instance with the same command ID
            for instance_data in instances:
                db_execution = ExecutionModel(
                    script_id=batch.script_id,
                    instance_id=None,  # We don't have a database instance ID
                    status=ExecutionStatus.RUNNING.value,
                    start_time=datetime.utcnow(),
                    batch_id=db_batch.id,
                    command_id=command_id,  # All instances in group share same command ID
                    # Store instance data in execution metadata
                    execution_metadata={
                        "instance_id": instance_data.instance_id,
                        "account_id": instance_data.account_id,
                        "region": instance_data.region,
                        "environment": instance_data.environment,
                        "change_number": batch.change_number,
                    },
                )

                # Save execution to database
                db.add(db_execution)
                db.commit()
                db.refresh(db_execution)

                if db_execution.id is not None:
                    execution_ids.append(db_execution.id)
                    logger.debug(
                        f"Created execution {db_execution.id} for instance {instance_data.instance_id} with command {command_id}"
                    )
        else:
            logger.error(f"Failed to send command to group {account_id}/{region}")

            # Create failed execution records for tracking
            for instance_data in instances:
                db_execution = ExecutionModel(
                    script_id=batch.script_id,
                    instance_id=None,
                    status=ExecutionStatus.FAILED.value,
                    start_time=datetime.utcnow(),
                    end_time=datetime.utcnow(),
                    batch_id=db_batch.id,
                    output=f"Failed to send SSM command to region {region}",
                    execution_metadata={
                        "instance_id": instance_data.instance_id,
                        "account_id": instance_data.account_id,
                        "region": instance_data.region,
                        "environment": instance_data.environment,
                        "change_number": batch.change_number,
                    },
                )

                db.add(db_execution)
                db.commit()
                db.refresh(db_execution)

                if db_execution.id is not None:
                    execution_ids.append(db_execution.id)

    # Start background tasks ONLY for monitoring existing commands
    for execution_id in execution_ids:
        execution_id_int = safe_int(execution_id)
        logger.debug(
            f"Starting monitoring background task for execution {execution_id_int}"
        )
        background_tasks.add_task(
            monitor_command_task, execution_id_int, db, credentials
        )

    # Return command mapping response
    # Ensure batch_id and start_time are not None to satisfy mypy
    batch_id = db_batch.id if db_batch.id is not None else 0
    start_time = (
        db_batch.start_time if db_batch.start_time is not None else datetime.utcnow()
    )

    # Ensure command_mapping is properly typed as Dict[str, CommandInfo]
    # (It should already be correctly typed from the earlier code, but this ensures mypy is satisfied)
    typed_command_mapping: Dict[str, CommandInfo] = command_mapping

    return ExecutionBatchWithCommands(
        batch_id=batch_id,
        status=ExecutionStatus.RUNNING,
        start_time=start_time,
        command_mapping=typed_command_mapping,
        total_instances=len(batch.instances),
        change_number=batch.change_number,
    )


@router.get(
    "/batch/{batch_id}/status",
    response_model=Dict[str, Any],
    summary="Get Real-time Batch Status",
    description="Get current status of all executions in a batch for real-time monitoring",
    responses={
        200: {"description": "Current execution status for all instances"},
        404: {"description": "Batch not found"},
    },
)
def get_batch_status(batch_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Get real-time status of all executions in a batch.
    Returns current status for frontend polling and matrix display.
    """
    # Check if batch exists
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution batch with ID {batch_id} not found",
        )

    # Get all executions in this batch
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id).all()
    )

    # Build status response
    instance_status = {}
    completed_count = 0
    failed_count = 0
    running_count = 0

    for execution in executions:
        metadata: dict[str, str] = execution.execution_metadata or {}
        instance_id = metadata.get("instance_id", f"unknown-{execution.id}")

        status_info = {
            "instance_id": instance_id,
            "command_id": execution.command_id,
            "status": execution.status,
            "start_time": (
                execution.start_time.isoformat() if execution.start_time else None
            ),
            "end_time": execution.end_time.isoformat() if execution.end_time else None,
            "account_id": metadata.get("account_id"),
            "region": metadata.get("region"),
            "output": execution.output,
            "exit_code": execution.exit_code,
        }

        instance_status[instance_id] = status_info

        # Count statuses
        if execution.status == ExecutionStatus.COMPLETED.value:
            completed_count += 1
        elif execution.status == ExecutionStatus.FAILED.value:
            failed_count += 1
        else:
            running_count += 1

    # Determine overall batch status
    total_count = len(executions)
    if running_count == 0:
        overall_status = "completed" if failed_count == 0 else "partial_failure"
    else:
        overall_status = "running"

    return {
        "batch_id": batch_id,
        "overall_status": overall_status,
        "total_instances": total_count,
        "completed": completed_count,
        "failed": failed_count,
        "running": running_count,
        "instances": instance_status,
        "last_updated": datetime.utcnow().isoformat(),
    }


@router.get(
    "/batch/{batch_id}/progress",
    response_model=ExecutionProgress,
    summary="Get Batch Progress",
    description=GET_BATCH_PROGRESS_DESCRIPTION,
    response_description="Batch execution progress summary",
    responses={
        200: {
            "content": {"application/json": {"example": BATCH_PROGRESS_EXAMPLE}},
        },
        404: {"description": "Batch not found"},
    },
)
def get_batch_progress(
    batch_id: int, db: Session = Depends(get_db)
) -> ExecutionProgress:
    """
    Get the progress of a batch execution.

    This endpoint provides a summary of the status of all executions in a batch.
    """
    # Check if batch exists
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution batch with ID {batch_id} not found",
        )

    # Count executions by status
    total_query = db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id)
    total_instances = total_query.count()

    completed_instances = total_query.filter(
        ExecutionModel.status == ExecutionStatus.COMPLETED.value
    ).count()
    failed_instances = total_query.filter(
        ExecutionModel.status == ExecutionStatus.FAILED.value
    ).count()
    pending_instances = total_instances - completed_instances - failed_instances

    # Determine overall status
    overall_status = ExecutionStatus.PENDING
    if total_instances == 0:
        overall_status = ExecutionStatus.PENDING
    elif pending_instances == 0:
        if failed_instances == 0:
            overall_status = ExecutionStatus.COMPLETED
        else:
            overall_status = ExecutionStatus.FAILED
    else:
        overall_status = ExecutionStatus.RUNNING

    return ExecutionProgress(
        total_instances=total_instances,
        completed_instances=completed_instances,
        failed_instances=failed_instances,
        pending_instances=pending_instances,
        overall_status=overall_status,
    )


@router.post(
    "/batch/{batch_id}/refresh-status",
    response_model=ExecutionProgress,
    summary="Refresh Batch Command Status",
    description="Refresh status of all command IDs in a batch from AWS SSM",
    response_description="Updated batch execution progress",
    responses={
        200: {"description": "Batch status refreshed successfully"},
        404: {"description": "Batch not found"},
        500: {"description": "Error refreshing status from AWS"},
    },
)
async def refresh_batch_status(
    batch_id: int, db: Session = Depends(get_db)
) -> ExecutionProgress:
    """
    Refresh the status of all executions in a batch by checking AWS SSM command status.

    This endpoint collects all command IDs from the batch and checks their current
    status in AWS SSM across multiple regions and accounts. It updates the execution
    records with the latest status and returns the updated progress.
    """
    import logging

    logger = logging.getLogger(__name__)

    # Check if batch exists
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found")

    # Get all executions in this batch
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id).all()
    )

    if not executions:
        logger.warning(f"No executions found for batch {batch_id}")
        return ExecutionProgress(
            total_instances=0,
            completed_instances=0,
            failed_instances=0,
            pending_instances=0,
            overall_status=ExecutionStatus.COMPLETED,
        )

    # Initialize credential manager and SSM executor
    credential_manager = CredentialManager()
    ssm_executor = SSMExecutor(credential_manager)

    # Refresh status for each execution that has a command_id
    updated_count = 0
    for execution in executions:
        if not execution.command_id:
            logger.debug(
                f"Execution {execution.id} has no command_id, skipping status refresh"
            )
            continue

        if execution.status in [
            ExecutionStatus.COMPLETED.value,
            ExecutionStatus.FAILED.value,
        ]:
            logger.debug(
                f"Execution {execution.id} already in terminal state {execution.status}, skipping"
            )
            continue

        try:
            # Extract instance metadata
            metadata: dict[str, str] = execution.execution_metadata or {}
            instance_id = metadata.get("instance_id")
            account_id = metadata.get("account_id")
            region = metadata.get("region")
            environment = metadata.get("environment")

            if not all([instance_id, account_id, region, environment]):
                logger.error(
                    f"Execution {execution.id} missing required metadata for status check"
                )
                continue

            # Type narrowing for mypy - we know these are strings after the check above
            instance_id_str: str = instance_id  # type: ignore
            account_id_str: str = account_id  # type: ignore
            region_str: str = region  # type: ignore
            environment_str: str = environment  # type: ignore

            # Check current status from AWS SSM
            logger.debug(
                f"Refreshing status for execution {execution.id}, command {execution.command_id}"
            )
            status_result = await ssm_executor.get_command_status(
                command_id=execution.command_id,
                instance_id=instance_id_str,
                account_id=account_id_str,
                region=region_str,
                environment=environment_str,
            )

            # Update execution based on current AWS status
            aws_status = status_result.get("Status", "Unknown")

            if aws_status == "Success":
                execution.status = ExecutionStatus.COMPLETED.value
                execution.output = status_result.get("Output", "")
                execution.exit_code = status_result.get("ExitCode", 0)
                if not execution.end_time:
                    execution.end_time = datetime.utcnow()
                updated_count += 1
                logger.info(f"Updated execution {execution.id} to completed status")

            elif aws_status in ["Failed", "Cancelled", "TimedOut"]:
                execution.status = ExecutionStatus.FAILED.value
                execution.output = (
                    status_result.get("Output", "")
                    + "\n"
                    + status_result.get("Error", "")
                )
                execution.exit_code = status_result.get("ExitCode", -1)
                if not execution.end_time:
                    execution.end_time = datetime.utcnow()
                updated_count += 1
                logger.info(
                    f"Updated execution {execution.id} to failed status ({aws_status})"
                )

            elif aws_status in ["InProgress", "Pending"]:
                execution.status = ExecutionStatus.RUNNING.value
                logger.debug(f"Execution {execution.id} still running")

            else:
                logger.warning(
                    f"Unknown AWS status '{aws_status}' for execution {execution.id}"
                )

        except Exception as e:
            logger.error(
                f"Error refreshing status for execution {execution.id}: {str(e)}"
            )
            # Don't fail the entire batch refresh for one execution error
            continue

    # Commit all updates
    if updated_count > 0:
        db.commit()
        logger.info(
            f"Refreshed status for {updated_count} executions in batch {batch_id}"
        )

    # Update batch status based on execution statuses
    execution_statuses = [exec.status for exec in executions]
    if all(
        status in [ExecutionStatus.COMPLETED.value, ExecutionStatus.FAILED.value]
        for status in execution_statuses
    ):
        batch.status = ExecutionStatus.COMPLETED.value
        batch.end_time = datetime.utcnow()
        db.commit()
    elif any(status == ExecutionStatus.RUNNING.value for status in execution_statuses):
        batch.status = ExecutionStatus.RUNNING.value
        db.commit()

    # Return updated progress
    return get_batch_progress(batch_id, db)


@router.get(
    "/batch/{batch_id}",
    response_model=ExecutionBatchWithCommands,
    summary="Get Batch Details",
    description="Get details of a specific execution batch",
    response_description="Batch details",
    responses={
        200: {"description": "Batch details retrieved successfully"},
        404: {"description": "Batch not found"},
    },
)
def get_batch_details(
    batch_id: int, db: Session = Depends(get_db)
) -> ExecutionBatchWithCommands:
    """
    Get details of a specific execution batch.
    """
    # Check if batch exists
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found")

    # Convert SQLAlchemy model to Pydantic schema with proper type conversion
    # Ensure status is converted to ExecutionStatus enum
    status_value = (
        ExecutionStatus(batch.status)
        if isinstance(batch.status, str)
        else (batch.status if batch.status is not None else ExecutionStatus.PENDING)
    )

    # Ensure command_mapping is properly typed as Dict[str, CommandInfo]
    command_mapping_raw = getattr(batch, "command_mapping", {})
    command_mapping: Dict[str, CommandInfo] = {}

    # Convert raw command mapping to properly typed CommandInfo objects
    for cmd_id, cmd_info in command_mapping_raw.items():
        if isinstance(cmd_info, dict):
            command_mapping[cmd_id] = CommandInfo(
                account=cmd_info.get("account", ""),
                region=cmd_info.get("region", ""),
                instanceIDs=cmd_info.get("instanceIDs", []),
            )
        else:
            # If it's already a CommandInfo object, use it directly
            command_mapping[cmd_id] = cmd_info

    # Ensure we have a valid status value (not None)
    final_status = status_value if status_value is not None else ExecutionStatus.PENDING

    return ExecutionBatchWithCommands(
        batch_id=batch.id if batch.id is not None else 0,
        status=final_status,
        start_time=(
            batch.start_time if batch.start_time is not None else datetime.utcnow()
        ),
        command_mapping=command_mapping,
        total_instances=getattr(batch, "total_instances", 0),
        change_number=getattr(batch, "change_number", None),
    )


@router.post(
    "/generate-report",
    response_model=Dict[str, Any],
    summary="Generate Compiled Report",
    description="Generate a compiled report from multiple command IDs across different instances",
    response_description="Report data with results from all selected instances",
    responses={
        200: {"description": "Report generated successfully"},
        400: {"description": "Invalid request data"},
        401: {"description": "Authentication required"},
        500: {"description": "Error generating report"},
    },
)
async def generate_report(
    report_request: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    x_aws_access_key: Optional[str] = Header(None, alias="X-AWS-Access-Key"),
    x_aws_secret_key: Optional[str] = Header(None, alias="X-AWS-Secret-Key"),
    x_aws_session_token: Optional[str] = Header(None, alias="X-AWS-Session-Token"),
    x_aws_environment: Optional[str] = Header(None, alias="X-AWS-Environment"),
) -> Dict[str, Any]:
    """
    Generate a compiled report from selected command IDs and instances.

    This endpoint collects results from multiple AWS SSM command executions
    across different instances, accounts, and regions.
    """
    import logging

    logger = logging.getLogger(__name__)

    logger.info(f"Generating report for request: {report_request}")

    # Validate request data
    instances = report_request.get("instances", [])
    report_format = report_request.get("format", "html")

    if not instances:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No instances provided for report generation",
        )

    # Validate credentials
    if not (x_aws_access_key and x_aws_secret_key and x_aws_environment):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AWS credentials are required. Please provide credentials in headers.",
        )

    # Set up credentials
    from backend.core.config import AWSCredentials, AWSEnvironment

    # Initialize credential manager
    credential_manager = CredentialManager()

    credentials = AWSCredentials(
        access_key=x_aws_access_key,
        secret_key=x_aws_secret_key,
        session_token=x_aws_session_token,
        environment=AWSEnvironment(x_aws_environment),
    )

    # Store credentials in credential manager
    credential_manager.store_credentials(credentials)

    # Validate credentials
    validation_result = credential_manager.are_credentials_valid(x_aws_environment)
    if not validation_result["valid"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid AWS credentials for {x_aws_environment} environment",
        )

    logger.info(f"Processing report for {len(instances)} instances")

    # Collect results from all command IDs
    results = []
    errors = []

    # Initialize SSM executor
    ssm_executor = SSMExecutor(credential_manager)

    for instance_data in instances:
        try:
            command_id = instance_data.get("command_id")
            instance_id = instance_data.get("instance_id")
            account_id = instance_data.get("account_id")
            region = instance_data.get("region")
            batch_id = instance_data.get("batch_id")

            if command_id == "N/A" or not command_id:
                logger.warning(f"Skipping instance {instance_id} - no command ID")
                continue

            logger.info(
                f"Fetching results for command {command_id} on instance {instance_id}"
            )

            # Get command results from AWS SSM
            result = await ssm_executor.get_command_status(
                command_id=command_id,
                instance_id=instance_id,
                account_id=account_id,
                region=region,
                environment=x_aws_environment,
            )

            # Add instance metadata to result
            result_with_metadata = {
                "batch_id": batch_id,
                "command_id": command_id,
                "instance_id": instance_id,
                "account_id": account_id,
                "region": region,
                "environment": x_aws_environment,
                "status": result.get("Status", "Unknown"),
                "output": result.get("Output", ""),
                "error": result.get("Error", ""),
                "exit_code": result.get("ExitCode"),
                "execution_start": result.get("ExecutionStartDateTime"),
                "execution_end": result.get("ExecutionEndDateTime"),
                "execution_time": result.get("ExecutionElapsedTime"),
            }

            results.append(result_with_metadata)
            logger.info(f"Successfully collected results for {instance_id}")

        except Exception as e:
            logger.error(
                f"Error collecting results for instance {instance_data}: {str(e)}"
            )
            errors.append(
                {"instance_id": instance_data.get("instance_id"), "error": str(e)}
            )

    # Format results based on requested format
    if report_format == "html":
        report_data = format_html_report(results, errors)
    elif report_format == "csv":
        report_data = format_csv_report(results, errors)
    elif report_format == "pdf":
        report_data = format_pdf_report(results, errors)
    else:
        report_data = {
            "results": results,
            "errors": errors,
            "summary": {
                "total_instances": len(instances),
                "successful_results": len(results),
                "errors": len(errors),
            },
        }

    logger.info(
        f"Report generation completed. {len(results)} successful results, {len(errors)} errors"
    )

    return {
        "success": True,
        "format": report_format,
        "data": report_data,
        "summary": {
            "total_instances": len(instances),
            "successful_results": len(results),
            "errors": len(errors),
        },
    }


def format_html_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Format results as HTML report data"""
    return {
        "type": "html",
        "results": results,
        "errors": errors,
        "generated_at": datetime.utcnow().isoformat(),
    }


def format_csv_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Format results as CSV report data"""
    import csv
    import io

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "batch_id",
            "command_id",
            "instance_id",
            "account_id",
            "region",
            "status",
            "exit_code",
            "execution_time",
            "output",
            "error",
        ],
    )

    writer.writeheader()
    for result in results:
        writer.writerow(
            {
                "batch_id": result.get("batch_id", ""),
                "command_id": result.get("command_id", ""),
                "instance_id": result.get("instance_id", ""),
                "account_id": result.get("account_id", ""),
                "region": result.get("region", ""),
                "status": result.get("status", ""),
                "exit_code": result.get("exit_code", ""),
                "execution_time": result.get("execution_time", ""),
                "output": result.get("output", "").replace("\n", " ").replace("\r", ""),
                "error": result.get("error", "").replace("\n", " ").replace("\r", ""),
            }
        )

    csv_content = output.getvalue()
    output.close()

    return {
        "type": "csv",
        "content": csv_content,
        "filename": f'execution_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv',
    }


def format_pdf_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Format results as PDF report data (placeholder implementation)"""
    return {
        "type": "pdf",
        "message": "PDF report generation not yet implemented",
        "results": results,
        "errors": errors,
    }
