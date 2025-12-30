"""Background tasks for script execution."""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger("pcm_ops_tools.aws.tasks")

# Polling configuration constants
POLLING_MAX_ATTEMPTS = 60
POLLING_INTERVAL_SECONDS = 5

from backend.core.utils.type_helpers import safe_str
from backend.db.models.account import Account as AccountModel
from backend.db.models.account import Instance as InstanceModel
from backend.db.models.account import Region as RegionModel
from backend.db.models.execution import Execution as ExecutionModel
from backend.db.models.script import Script as ScriptModel
from backend.db.session import get_db_sync
from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor


async def execute_script_task_with_metadata(
    execution_id: int,
    account_id: str,
    environment: str,
    use_change_credential: bool = False,
    validate_hostname: bool = False,
    validation_method: Optional[str] = None,
    hostname_patterns: Optional[List[str]] = None,
) -> None:
    """
    Background task to execute a script and update its status with enhanced metadata.
    This function is designed to run asynchronously in the background.
    """

    try:
        with get_db_sync() as db:
            # Get execution from database
            execution = (
                db.query(ExecutionModel)
                .filter(ExecutionModel.id == execution_id)
                .first()
            )
            if not execution:
                logger.warning(f"Execution {execution_id} not found", extra={
                    "execution_id": execution_id,
                    "operation": "update_execution_status"
                })
                return

            execution.status = "in_progress"
            execution.updated_at = datetime.utcnow()

            # Get all related data
            script = (
                db.query(ScriptModel)
                .filter(ScriptModel.id == execution.script_id)
                .first()
            )
            if not script:
                execution.status = "failed"
                execution.result = "Script not found"
                execution.updated_at = datetime.utcnow()
                db.commit()
                return

            instance = (
                db.query(InstanceModel)
                .filter(InstanceModel.id == execution.instance_id)
                .first()
            )
            if not instance:
                execution.status = "failed"
                execution.result = "Instance not found"
                execution.updated_at = datetime.utcnow()
                db.commit()
                return

            region = (
                db.query(RegionModel)
                .filter(RegionModel.id == instance.region_id)
                .first()
            )
            if not region:
                execution.status = "failed"
                execution.result = "Region not found"
                execution.updated_at = datetime.utcnow()
                db.commit()
                return

            account = (
                db.query(AccountModel)
                .filter(AccountModel.id == region.account_id)
                .first()
            )
            if not account:
                execution.status = "failed"
                execution.result = "Account not found"
                execution.updated_at = datetime.utcnow()
                db.commit()
                return

            # Perform hostname validation if enabled
            if validate_hostname and validation_method and hostname_patterns:
                patterns = (
                    hostname_patterns
                    if isinstance(hostname_patterns, list)
                    else [hostname_patterns]
                )

                if validation_method == "prefix":
                    # Check if instance name starts with any of the patterns
                    valid = any(
                        instance.name.startswith(pattern) for pattern in patterns
                    )
                elif validation_method == "suffix":
                    # Check if instance name ends with any of the patterns
                    valid = any(instance.name.endswith(pattern) for pattern in patterns)
                elif validation_method == "contains":
                    # Check if instance name contains any of the patterns
                    valid = any(pattern in instance.name for pattern in patterns)
                else:
                    # Default to exact match
                    valid = instance.name in patterns

                if not valid:
                    execution.status = "failed"
                    execution.result = f"Hostname validation failed: {instance.name} does not match required patterns"
                    execution.updated_at = datetime.utcnow()
                    db.commit()
                    return
                db.commit()
                return

        # Initialize credential manager with actual account ID
        cred_manager = CredentialManager()

        # Execute script
        ssm_executor = SSMExecutor(
            credential_manager=cred_manager,
            account_id=safe_str(account_id),
            environment=safe_str(environment),
        )

        # Update execution with command ID
        command_response = await ssm_executor.execute_command(
            instance_id=safe_str(instance.instance_id),
            script_content=safe_str(script.content),
            region_name=safe_str(region.name),
            script_name=safe_str(script.name),
            execution_timeout=600,  # 10 minutes
            use_change_credential=use_change_credential,
        )

        # Store command ID for tracking
        if command_response and "CommandId" in command_response:
            execution.command_id = command_response["CommandId"]
            db.commit()

            # Start monitoring in a separate task with error handling
            async def safe_monitor():
                try:
                    await monitor_command_task(
                        execution_id=execution_id,
                        command_id=command_response["CommandId"],
                        instance_id=instance.instance_id,
                        region_name=region.name,
                        account_id=account_id,
                        environment=environment,
                        use_change_credential=use_change_credential,
                    )
                except Exception as e:
                    logger.error(
                        f"Error in monitor_command_task for execution {execution_id}: {str(e)}",
                        extra={
                            "execution_id": execution_id,
                            "error_type": type(e).__name__,
                            "operation": "monitor_command_task"
                        }
                    )

            task = asyncio.create_task(safe_monitor())

            # Store task reference and handle exceptions
            def handle_task_done(t):
                try:
                    # Check if task completed with an exception
                    if t.exception() is not None:
                        logger.error(
                            f"Monitor task for execution {execution_id} failed: {t.exception()}",
                            extra={
                                "execution_id": execution_id,
                                "error_type": type(t.exception()).__name__ if t.exception() else "unknown",
                                "operation": "monitor_task_completion"
                            }
                        )
                except asyncio.CancelledError:
                    logger.info(f"Monitor task for execution {execution_id} was cancelled", extra={
                        "execution_id": execution_id,
                        "operation": "monitor_task_cancelled"
                    })

            task.add_done_callback(handle_task_done)
            # Keep reference to prevent garbage collection
            if not hasattr(asyncio.current_task(), "_monitor_tasks"):
                asyncio.current_task()._monitor_tasks = []
            asyncio.current_task()._monitor_tasks.append(task)
        else:
            execution.status = "failed"
            execution.result = "Failed to get command ID from SSM"
            execution.updated_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        execution = (
            db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
        )
        if execution:
            execution.status = "failed"
            execution.result = str(e)
            execution.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def monitor_command_task(
    execution_id: int,
    command_id: str,
    instance_id: str,
    region_name: str,
    account_id: str,
    environment: str,
    use_change_credential: bool = False,
) -> None:
    """Monitor SSM command execution and update status."""
    db = get_db_sync()

    try:
        # Initialize services
        cred_manager = CredentialManager()
        ssm_executor = SSMExecutor(
            credential_manager=cred_manager,
            account_id=safe_str(account_id),
            environment=safe_str(environment),
        )

        # Poll for command completion
        attempt = 0

        while attempt < POLLING_MAX_ATTEMPTS:
            await asyncio.sleep(POLLING_INTERVAL_SECONDS)  # Wait between checks

            result = await ssm_executor.get_command_result(
                command_id=command_id,
                instance_id=instance_id,
                region_name=region_name,
                use_change_credential=use_change_credential,
            )

            if result and result.get("Status") in [
                "Success",
                "Failed",
                "Cancelled",
                "TimedOut",
            ]:
                # Update execution with final status
                execution = (
                    db.query(ExecutionModel)
                    .filter(ExecutionModel.id == execution_id)
                    .first()
                )
                if execution:
                    execution.status = (
                        "completed" if result["Status"] == "Success" else "failed"
                    )
                    execution.result = (
                        result.get("StandardOutputContent", "")
                        if result["Status"] == "Success"
                        else result.get("StandardErrorContent", "")
                    )
                    execution.ssm_status = result["Status"]
                    execution.ssm_status_details = result.get("StatusDetails", "")
                    execution.execution_end_time = result.get("ExecutionEndDateTime")
                    execution.updated_at = datetime.utcnow()
                    db.commit()
                break

            attempt += 1

        if attempt >= POLLING_MAX_ATTEMPTS:
            # Command timed out
            execution = (
                db.query(ExecutionModel)
                .filter(ExecutionModel.id == execution_id)
                .first()
            )
            if execution:
                execution.status = "failed"
                execution.result = "Command monitoring timed out after 10 minutes"
                execution.ssm_status = "TimedOut"
                execution.updated_at = datetime.utcnow()
                db.commit()

    except Exception as e:
        execution = (
            db.query(ExecutionModel).filter(ExecutionModel.id == execution_id).first()
        )
        if execution:
            execution.status = "failed"
            execution.result = f"Error monitoring command: {str(e)}"
            execution.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def execute_script_task(
    execution_id: int,
    account_id: str,
    environment: str,
    use_change_credential: bool = False,
) -> None:
    """
    Background task to execute a script and update its status.
    This is a simplified version without hostname validation.
    """
    await execute_script_task_with_metadata(
        execution_id=execution_id,
        account_id=account_id,
        environment=environment,
        use_change_credential=use_change_credential,
        validate_hostname=False,
    )
