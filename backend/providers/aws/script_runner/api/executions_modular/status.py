"""Status and monitoring endpoints for executions."""

from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.utils.type_helpers import safe_str
from backend.db.models.execution import Execution as ExecutionModel
from backend.db.session import get_db
from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.docs.executions import (
    EXECUTION_STATUS_EXAMPLE,
    GET_EXECUTION_STATUS_DESCRIPTION,
)
from backend.providers.aws.script_runner.schemas.execution import (
    ExecutionStatus,
)
from backend.providers.aws.script_runner.services.execution_state_manager import (
    AWSExecutionStateManager,
)
from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor

# Create router
router = APIRouter()


@router.get(
    "/{execution_id}/status",
    response_model=ExecutionStatus,
    summary="Get Execution Status",
    description=GET_EXECUTION_STATUS_DESCRIPTION,
    response_description="Current execution status",
    responses={
        200: {
            "description": "Execution status",
            "content": {"application/json": {"example": EXECUTION_STATUS_EXAMPLE}},
        },
        404: {"description": "Execution not found"},
    },
)
def get_execution_status(
    execution_id: int, db: Session = Depends(get_db)
) -> ExecutionStatus:
    """Get the current status of an execution."""
    execution = (
        db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
    )
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    # Get instance details for more context
    instance = execution.instance
    instance_name = instance.name if instance else "Unknown"

    # Get script name
    script_name = execution.script.name if execution.script else "Unknown"

    return ExecutionStatus(
        execution_id=execution.id,
        status=execution.status,
        instance_name=instance_name,
        script_name=script_name,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
        command_id=execution.command_id,
        ssm_status=execution.ssm_status,
        ssm_status_details=execution.ssm_status_details,
        execution_end_time=execution.execution_end_time,
    )


@router.get(
    "/{execution_id}/output",
    summary="Get Execution Output",
    description="Get the output/result of a completed execution",
    response_model=Dict[str, Any],
)
def get_execution_output(
    execution_id: int, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get the output of a specific execution."""
    execution = (
        db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
    )
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    return {
        "execution_id": execution.id,
        "status": execution.status,
        "output": execution.result or "",
        "ssm_status": execution.ssm_status,
        "ssm_status_details": execution.ssm_status_details,
        "command_id": execution.command_id,
        "execution_end_time": execution.execution_end_time,
    }


@router.get(
    "/batch/{batch_id}/status",
    response_model=Dict[str, Any],
    summary="Get Batch Status",
    description="Get the current status of a batch execution",
)
def get_batch_status(batch_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get the current status of a batch execution."""
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get execution statistics
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id).all()
    )

    status_counts = {
        "completed": sum(1 for e in executions if e.status == "completed"),
        "failed": sum(1 for e in executions if e.status == "failed"),
        "in_progress": sum(1 for e in executions if e.status == "in_progress"),
        "pending": sum(1 for e in executions if e.status == "pending"),
    }

    # Determine overall batch status
    if status_counts["failed"] == len(executions) and len(executions) > 0:
        batch_status = "failed"
    elif (
        status_counts["completed"] + status_counts["failed"] == len(executions)
        and len(executions) > 0
    ):
        # Check if we have mixed results
        if status_counts["completed"] > 0 and status_counts["failed"] > 0:
            batch_status = "partial_failure"
        else:
            batch_status = "completed"
    elif status_counts["in_progress"] > 0 or status_counts["pending"] > 0:
        batch_status = "in_progress"
    else:
        batch_status = batch.status

    return {
        "batch_id": batch.id,
        "status": batch_status,
        "total_instances": len(executions),
        "status_counts": status_counts,
        "created_at": batch.created_at,
        "updated_at": batch.updated_at,
    }


@router.post(
    "/batch/{batch_id}/refresh-status",
    response_model=Dict[str, str],
    summary="Refresh Batch Status",
    description="Trigger a refresh of batch execution status from AWS SSM",
)
def refresh_batch_status(
    batch_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
) -> Dict[str, str]:
    """Manually trigger a status refresh for all executions in a batch."""
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get all executions in the batch that are still in progress
    executions = (
        db.query(ExecutionModel)
        .filter(
            ExecutionModel.batch_id == batch_id, ExecutionModel.status == "in_progress"
        )
        .all()
    )

    if not executions:
        return {"message": "No in-progress executions to refresh"}

    # Group executions by command_id for efficient refresh
    command_groups: Dict[str, List[ExecutionModel]] = {}
    for execution in executions:
        if execution.command_id:
            if execution.command_id not in command_groups:
                command_groups[execution.command_id] = []
            command_groups[execution.command_id].append(execution)

    # Add background task to refresh status
    background_tasks.add_task(
        refresh_batch_status_task, batch_id=batch_id, command_groups=command_groups
    )

    return {"message": f"Status refresh initiated for {len(executions)} executions"}


async def refresh_batch_status_task(
    batch_id: int, command_groups: Dict[str, List[ExecutionModel]]
) -> None:
    """Background task to refresh batch execution status."""
    from backend.db.session import get_db_sync

    db = get_db_sync()

    try:
        cred_manager = CredentialManager()

        for command_id, executions in command_groups.items():
            # Get account/region info from first execution
            first_exec = executions[0]
            instance = first_exec.instance
            if not instance or not instance.region or not instance.region.account:
                continue

            account = instance.region.account
            region = instance.region

            # Create SSM executor
            ssm_executor = SSMExecutor(
                credential_manager=cred_manager,
                account_id=safe_str(account.account_id),
                environment=safe_str(account.environment),
            )

            # Use AWSExecutionStateManager for efficient status updates
            state_manager = AWSExecutionStateManager(ssm_executor=ssm_executor, db=db)

            # Get instance IDs for this command
            instance_ids = [e.instance.instance_id for e in executions if e.instance]

            # Refresh status for all instances in this command
            await state_manager.refresh_command_status(
                command_id=command_id,
                instance_ids=instance_ids,
                region_name=safe_str(region.name),
                batch_id=batch_id,
            )

        # Update batch status
        batch = (
            db.query(ExecutionBatchModel)
            .filter(ExecutionBatchModel.id == batch_id)
            .first()
        )
        if batch:
            executions = (
                db.query(ExecutionModel)
                .filter(ExecutionModel.batch_id == batch_id)
                .all()
            )
            completed = sum(1 for e in executions if e.status == "completed")
            failed = sum(1 for e in executions if e.status == "failed")

            if completed + failed == len(executions):
                batch.status = "completed" if failed == 0 else "failed"
            else:
                batch.status = "in_progress"

            batch.updated_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        print(f"Error refreshing batch status: {str(e)}")
    finally:
        db.close()


@router.get(
    "/batch/{batch_id}/instance/{instance_id}/output",
    summary="Get Batch Instance Output",
    description="Get the output for a specific instance in a batch execution",
    response_model=Dict[str, Any],
)
def get_batch_instance_output(
    batch_id: int, instance_id: int, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get the output for a specific instance in a batch execution."""
    execution = (
        db.query(ExecutionModel)
        .filter(
            ExecutionModel.batch_id == batch_id,
            ExecutionModel.instance_id == instance_id,
        )
        .first()
    )

    if not execution:
        raise HTTPException(
            status_code=404,
            detail=f"No execution found for instance {instance_id} in batch {batch_id}",
        )

    instance = execution.instance

    return {
        "batch_id": batch_id,
        "instance_id": instance_id,
        "instance_name": instance.name if instance else "Unknown",
        "execution_id": execution.id,
        "status": execution.status,
        "output": execution.result or "",
        "ssm_status": execution.ssm_status,
        "ssm_status_details": execution.ssm_status_details,
        "command_id": execution.command_id,
        "execution_end_time": execution.execution_end_time,
    }
