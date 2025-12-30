"""Batch execution endpoints."""

from datetime import datetime
from typing import Dict, List

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
    safe_list,
    safe_sqlalchemy_in,
    safe_str,
)
from backend.db.models.account import Instance as InstanceModel
from backend.db.models.execution import Execution as ExecutionModel
from backend.db.models.execution import ExecutionBatch as ExecutionBatchModel
from backend.db.models.script import Script as ScriptModel
from backend.db.session import get_db
from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.docs.executions import (
    BATCH_PROGRESS_EXAMPLE,
    EXECUTION_BATCH_CREATE_EXAMPLE,
    GET_BATCH_PROGRESS_DESCRIPTION,
)
from backend.providers.aws.script_runner.schemas.execution import (
    CommandInfo,
    ExecutionBatch,
    ExecutionBatchCreate,
    ExecutionBatchWithCommands,
    ExecutionProgress,
    InstanceData,
)
from backend.providers.aws.script_runner.services.execution_state_manager import (
    AWSExecutionStateManager,
)
from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor

# Create router
router = APIRouter()


@router.post(
    "/batch",
    response_model=ExecutionBatchWithCommands,
    status_code=status.HTTP_201_CREATED,
)
async def create_execution_batch(
    background_tasks: BackgroundTasks,
    batch: ExecutionBatchCreate = Body(..., example=EXECUTION_BATCH_CREATE_EXAMPLE),
    db: Session = Depends(get_db),
) -> ExecutionBatchWithCommands:
    """Create a batch execution for multiple instances using SSM send-command."""
    # Validate script exists
    script = db.query(ScriptModel).filter(ScriptModel.id == batch.script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    # Validate instances exist and get their details
    instance_ids = safe_list(batch.instance_ids)
    instances = (
        db.query(InstanceModel)
        .filter(safe_sqlalchemy_in(InstanceModel.id, instance_ids))
        .all()
    )

    if len(instances) != len(instance_ids):
        found_ids = {inst.id for inst in instances}
        missing_ids = set(instance_ids) - found_ids
        raise HTTPException(
            status_code=404, detail=f"Instances not found: {missing_ids}"
        )

    # Group instances by account and region
    instances_by_account_region: Dict[tuple, List[InstanceModel]] = {}
    for instance in instances:
        region = instance.region
        account = region.account if region else None
        if account and region:
            key = (account.account_id, account.environment, region.name)
            if key not in instances_by_account_region:
                instances_by_account_region[key] = []
            instances_by_account_region[key].append(instance)

    # Create batch record
    db_batch = ExecutionBatchModel(
        script_id=batch.script_id,
        total_instances=len(instances),
        status="pending",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(db_batch)
    db.commit()
    db.refresh(db_batch)

    # Create individual execution records for each instance
    executions = []
    for instance in instances:
        db_execution = ExecutionModel(
            script_id=batch.script_id,
            instance_id=instance.id,
            batch_id=db_batch.id,
            status="pending",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(db_execution)
        executions.append(db_execution)

    db.commit()

    # Execute commands by account/region groups
    command_infos = []
    cred_manager = CredentialManager()

    for (
        account_id,
        environment,
        region_name,
    ), region_instances in instances_by_account_region.items():
        try:
            # Create SSM executor for this account/environment
            ssm_executor = SSMExecutor(
                credential_manager=cred_manager,
                account_id=safe_str(account_id),
                environment=safe_str(environment),
            )

            # Get instance IDs for this group
            instance_id_list = [inst.instance_id for inst in region_instances]

            # Send command to all instances in this account/region
            command_response = await ssm_executor.send_command_to_instances(
                instance_ids=instance_id_list,
                script_content=safe_str(script.content),
                region_name=safe_str(region_name),
                script_name=safe_str(script.name),
                execution_timeout=batch.timeout_seconds or 600,
                use_change_credential=batch.use_change_credential,
            )

            if command_response and "Command" in command_response:
                command_id = command_response["Command"]["CommandId"]

                # Update executions with command ID
                for instance in region_instances:
                    execution = next(
                        (e for e in executions if e.instance_id == instance.id), None
                    )
                    if execution:
                        execution.command_id = command_id
                        execution.status = "in_progress"

                # Store command info
                command_info = CommandInfo(
                    command_id=command_id,
                    account_id=account_id,
                    environment=environment,
                    region=region_name,
                    instance_ids=instance_id_list,
                    status="InProgress",
                )
                command_infos.append(command_info)

                # Add background task to monitor this command
                background_tasks.add_task(
                    monitor_batch_command,
                    batch_id=db_batch.id,
                    command_id=command_id,
                    instance_ids=instance_id_list,
                    region_name=region_name,
                    account_id=account_id,
                    environment=environment,
                    use_change_credential=batch.use_change_credential,
                )
            else:
                # Mark executions as failed for this group
                for instance in region_instances:
                    execution = next(
                        (e for e in executions if e.instance_id == instance.id), None
                    )
                    if execution:
                        execution.status = "failed"
                        execution.result = "Failed to send command"

        except Exception as e:
            # Mark executions as failed for this group
            for instance in region_instances:
                execution = next(
                    (e for e in executions if e.instance_id == instance.id), None
                )
                if execution:
                    execution.status = "failed"
                    execution.result = str(e)

    # Update batch status
    db_batch.status = "in_progress" if command_infos else "failed"
    db.commit()

    # Prepare instance data for response
    instance_data = []
    for instance in instances:
        execution = next((e for e in executions if e.instance_id == instance.id), None)
        if execution:
            instance_data.append(
                InstanceData(
                    instance_id=instance.id,
                    instance_name=instance.name,
                    execution_id=execution.id,
                    status=execution.status,
                )
            )

    return ExecutionBatchWithCommands(
        id=db_batch.id,
        script_id=db_batch.script_id,
        total_instances=db_batch.total_instances,
        completed_instances=0,
        failed_instances=0,
        status=db_batch.status,
        created_at=db_batch.created_at,
        updated_at=db_batch.updated_at,
        commands=command_infos,
        instances=instance_data,
    )


async def monitor_batch_command(
    batch_id: int,
    command_id: str,
    instance_ids: List[str],
    region_name: str,
    account_id: str,
    environment: str,
    use_change_credential: bool = False,
) -> None:
    """Monitor SSM command execution for a batch."""
    from backend.db.session import get_db_sync

    db = get_db_sync()

    try:
        # Initialize services
        cred_manager = CredentialManager()
        ssm_executor = SSMExecutor(
            credential_manager=cred_manager,
            account_id=safe_str(account_id),
            environment=safe_str(environment),
        )

        # Use AWSExecutionStateManager for efficient batch monitoring
        state_manager = AWSExecutionStateManager(ssm_executor=ssm_executor, db=db)

        # Monitor the command
        await state_manager.monitor_batch_executions(
            batch_id=batch_id,
            command_id=command_id,
            instance_ids=instance_ids,
            region_name=region_name,
            use_change_credential=use_change_credential,
        )

    except Exception:
        # Update batch status on error
        batch = (
            db.query(ExecutionBatchModel)
            .filter(ExecutionBatchModel.id == batch_id)
            .first()
        )
        if batch:
            batch.status = "failed"
            batch.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.get(
    "/batch/{batch_id}/progress",
    response_model=ExecutionProgress,
    summary="Get Batch Execution Progress",
    description=GET_BATCH_PROGRESS_DESCRIPTION,
    responses={
        200: {
            "description": "Batch execution progress",
            "content": {"application/json": {"example": BATCH_PROGRESS_EXAMPLE}},
        },
        404: {"description": "Batch not found"},
    },
)
def get_batch_progress(
    batch_id: int,
    include_details: bool = Query(
        False, description="Include detailed instance information"
    ),
    db: Session = Depends(get_db),
) -> ExecutionProgress:
    """Get progress information for a batch execution."""
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get execution statistics
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id).all()
    )

    completed = sum(1 for e in executions if e.status == "completed")
    failed = sum(1 for e in executions if e.status == "failed")
    in_progress = sum(1 for e in executions if e.status == "in_progress")
    pending = sum(1 for e in executions if e.status == "pending")

    progress = ExecutionProgress(
        batch_id=batch_id,
        total=len(executions),
        completed=completed,
        failed=failed,
        in_progress=in_progress,
        pending=pending,
        status=batch.status,
    )

    if include_details:
        # Include instance details
        instance_details = []
        for execution in executions:
            instance = execution.instance
            if instance:
                instance_details.append(
                    {
                        "instance_id": instance.id,
                        "instance_name": instance.name,
                        "execution_id": execution.id,
                        "status": execution.status,
                        "result": execution.result,
                        "ssm_status": execution.ssm_status,
                    }
                )
        progress.instances = instance_details

    return progress


@router.get("/batch/{batch_id}", response_model=ExecutionBatch)
def get_batch_details(batch_id: int, db: Session = Depends(get_db)) -> ExecutionBatch:
    """Get details of a batch execution."""
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get execution counts
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.batch_id == batch_id).all()
    )
    completed = sum(1 for e in executions if e.status == "completed")
    failed = sum(1 for e in executions if e.status == "failed")

    return ExecutionBatch(
        id=batch.id,
        script_id=batch.script_id,
        total_instances=batch.total_instances,
        completed_instances=completed,
        failed_instances=failed,
        status=batch.status,
        created_at=batch.created_at,
        updated_at=batch.updated_at,
    )
