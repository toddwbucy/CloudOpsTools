"""Single execution endpoints."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from backend.core.utils.type_helpers import (
    safe_str,
)
from backend.db.models.account import Instance as InstanceModel
from backend.db.models.execution import Execution as ExecutionModel
from backend.db.models.script import Script as ScriptModel
from backend.db.session import get_db
from backend.providers.aws.script_runner.docs.executions import (
    CREATE_EXECUTION_DESCRIPTION,
    EXECUTION_CREATE_EXAMPLE,
    EXECUTION_LIST_EXAMPLE,
    EXECUTION_RESPONSE_EXAMPLE,
    GET_EXECUTION_DESCRIPTION,
    LIST_EXECUTIONS_DESCRIPTION,
)
from backend.providers.aws.script_runner.schemas.execution import (
    Execution,
    ExecutionCreate,
    ExecutionList,
)

from .tasks import execute_script_task, execute_script_task_with_metadata

# Create router
router = APIRouter()


@router.post(
    "/",
    response_model=Execution,
    status_code=status.HTTP_201_CREATED,
    summary="Create Single Execution",
    description=CREATE_EXECUTION_DESCRIPTION,
    response_description="The created execution",
    responses={
        201: {
            "description": "Execution created successfully",
            "content": {"application/json": {"example": EXECUTION_RESPONSE_EXAMPLE}},
        },
        404: {"description": "Script or instance not found"},
        422: {"description": "Validation error"},
    },
)
async def create_execution(
    background_tasks: BackgroundTasks,
    execution: ExecutionCreate = Body(..., example=EXECUTION_CREATE_EXAMPLE),
    db: Session = Depends(get_db),
) -> Execution:
    """Create a new script execution on a single instance."""
    # Validate script exists
    script = db.query(ScriptModel).filter(ScriptModel.id == execution.script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    # Validate instance exists
    instance = (
        db.query(InstanceModel)
        .filter(InstanceModel.id == execution.instance_id)
        .first()
    )
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")

    # Create execution record
    db_execution = ExecutionModel(
        script_id=execution.script_id,
        instance_id=execution.instance_id,
        status="pending",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(db_execution)
    db.commit()
    db.refresh(db_execution)

    # Extract account info from instance->region->account relationship
    account_id = (
        safe_str(instance.region.account.account_id)
        if instance.region and instance.region.account
        else ""
    )
    environment = (
        safe_str(instance.region.account.environment)
        if instance.region and instance.region.account
        else "commercial"
    )

    # Add background task with enhanced validation if provided
    if hasattr(execution, "validate_hostname") and execution.validate_hostname:
        background_tasks.add_task(
            execute_script_task_with_metadata,
            execution_id=db_execution.id,
            account_id=account_id,
            environment=environment,
            use_change_credential=execution.use_change_credential,
            validate_hostname=execution.validate_hostname,
            validation_method=getattr(execution, "validation_method", None),
            hostname_patterns=getattr(execution, "hostname_patterns", None),
        )
    else:
        # Use simple task without validation
        background_tasks.add_task(
            execute_script_task,
            execution_id=db_execution.id,
            account_id=account_id,
            environment=environment,
            use_change_credential=execution.use_change_credential,
        )

    return Execution(
        id=db_execution.id,
        script_id=db_execution.script_id,
        instance_id=db_execution.instance_id,
        status=db_execution.status,
        result=db_execution.result,
        created_at=db_execution.created_at,
        updated_at=db_execution.updated_at,
    )


@router.get(
    "/",
    response_model=ExecutionList,
    summary="List Executions",
    description=LIST_EXECUTIONS_DESCRIPTION,
    response_description="List of executions with pagination",
    responses={
        200: {
            "description": "List of executions",
            "content": {"application/json": {"example": EXECUTION_LIST_EXAMPLE}},
        }
    },
)
def list_executions(
    skip: int = Query(0, ge=0, description="Number of executions to skip"),
    limit: int = Query(
        10, ge=1, le=100, description="Maximum number of executions to return"
    ),
    instance_id: Optional[int] = Query(None, description="Filter by instance ID"),
    script_id: Optional[int] = Query(None, description="Filter by script ID"),
    status: Optional[str] = Query(None, description="Filter by execution status"),
    db: Session = Depends(get_db),
) -> ExecutionList:
    """List executions with optional filtering."""
    query = db.query(ExecutionModel)

    # Apply filters
    if instance_id is not None:
        query = query.filter(ExecutionModel.instance_id == instance_id)
    if script_id is not None:
        query = query.filter(ExecutionModel.script_id == script_id)
    if status:
        query = query.filter(ExecutionModel.status == status)

    # Get total count
    total = query.count()

    # Get paginated results
    executions = (
        query.order_by(ExecutionModel.created_at.desc()).offset(skip).limit(limit).all()
    )

    # Convert to response model
    execution_list = [
        Execution(
            id=execution.id,
            script_id=execution.script_id,
            instance_id=execution.instance_id,
            status=execution.status,
            result=execution.result,
            created_at=execution.created_at,
            updated_at=execution.updated_at,
            command_id=execution.command_id,
            batch_id=execution.batch_id,
            ssm_status=execution.ssm_status,
            ssm_status_details=execution.ssm_status_details,
            execution_end_time=execution.execution_end_time,
        )
        for execution in executions
    ]

    return ExecutionList(executions=execution_list, total=total, skip=skip, limit=limit)


@router.get(
    "/{execution_id}",
    response_model=Execution,
    summary="Get Execution Details",
    description=GET_EXECUTION_DESCRIPTION,
    response_description="Execution details",
    responses={
        200: {
            "description": "Execution details",
            "content": {"application/json": {"example": EXECUTION_RESPONSE_EXAMPLE}},
        },
        404: {"description": "Execution not found"},
    },
)
def get_execution(execution_id: int, db: Session = Depends(get_db)) -> Execution:
    """Get details of a specific execution."""
    execution = (
        db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
    )
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    return Execution(
        id=execution.id,
        script_id=execution.script_id,
        instance_id=execution.instance_id,
        status=execution.status,
        result=execution.result,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
        command_id=execution.command_id,
        batch_id=execution.batch_id,
        ssm_status=execution.ssm_status,
        ssm_status_details=execution.ssm_status_details,
        execution_end_time=execution.execution_end_time,
    )
