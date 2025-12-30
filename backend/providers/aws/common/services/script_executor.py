"""AWS Script Executor Service - Backend-only execution engine for controlled script operations"""

import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List

import boto3
from sqlalchemy.orm import Session

from backend.core.config import AWSEnvironment
from backend.db.models.execution import Execution
from backend.providers.aws.script_runner.services.ssm_executor import SSMExecutor

logger = logging.getLogger(__name__)

# Thread pool configuration to prevent resource exhaustion
MAX_CONCURRENT_EXECUTIONS = 10  # Limit concurrent batch executions
execution_thread_pool = ThreadPoolExecutor(
    max_workers=MAX_CONCURRENT_EXECUTIONS,
    thread_name_prefix="script-executor"
)

# Semaphore to track active executions (for monitoring/debugging)
active_executions_count = threading.Semaphore(MAX_CONCURRENT_EXECUTIONS)


def cleanup_thread_pool():
    """Cleanup function to gracefully shutdown the thread pool"""
    logger.info("Shutting down Script Executor thread pool...")
    execution_thread_pool.shutdown(wait=True, cancel_futures=False)
    logger.info("Thread pool shutdown complete")


# Register cleanup on module unload
import atexit

atexit.register(cleanup_thread_pool)


def poll_and_update_results(
    command_id: str,
    instance_ids: List[str],
    account_id: str,
    region: str,
    credentials: Any,
    execution_map: Dict[str, Any],
    db: Session,
    ssm_executor: Any,
    max_wait_time: int = 300,
    poll_interval: int = 5,
):
    """Poll SSM for command results and update execution records"""
    import time

    logger.info(
        f"[poll_and_update_results] Starting to poll command {command_id} for {len(instance_ids)} instances"
    )

    try:
        # Assume role to get SSM access
        base_creds = None
        if hasattr(credentials, "access_key") and hasattr(credentials, "secret_key"):
            base_creds = credentials

        assumed_creds = ssm_executor.account_manager.assume_role(
            account_id=account_id,
            region_name=region,
            credentials=base_creds,
        )

        if not assumed_creds:
            logger.error("[poll_and_update_results] Failed to assume role for polling")
            return

        # Create SSM client
        ssm = boto3.client(
            "ssm",
            region_name=region,
            aws_access_key_id=assumed_creds["AccessKeyId"],
            aws_secret_access_key=assumed_creds["SecretAccessKey"],
            aws_session_token=assumed_creds["SessionToken"],
        )

        start_time = time.time()
        terminal_states = ["Success", "Failed", "Cancelled", "TimedOut", "Cancelling"]

        while time.time() - start_time < max_wait_time:
            all_completed = True

            # Check status for each instance
            for instance_id in instance_ids:
                try:
                    # Get command invocation details for this instance
                    response = ssm.get_command_invocation(
                        CommandId=command_id, InstanceId=instance_id
                    )

                    status = response.get("Status", "Unknown")
                    logger.info(
                        f"[poll_and_update_results] Instance {instance_id}: status={status}"
                    )

                    # Update execution record
                    execution = execution_map.get(instance_id)
                    if execution:
                        if status in terminal_states:
                            # Command completed, update with final results
                            stdout_content = response.get("StandardOutputContent", "")
                            stderr_content = response.get("StandardErrorContent", "")

                            # Determine status based on:
                            # 1. If SSM status is "Success" -> completed
                            # 2. If we have stdout content (even with stderr) -> completed
                            # 3. Only mark as failed if no stdout AND (SSM failed OR only stderr)
                            if status == "Success" or (stdout_content and stdout_content.strip()):
                                execution.status = "completed"
                            else:
                                execution.status = "failed"

                            execution.output = stdout_content
                            execution.error = stderr_content
                            execution.end_time = datetime.utcnow()

                            # Store exit code in metadata
                            if execution.execution_metadata is None:
                                execution.execution_metadata = {}
                            execution.execution_metadata["exit_code"] = response.get(
                                "ResponseCode", -1
                            )
                            execution.execution_metadata["ssm_status"] = status

                            logger.info(
                                f"[poll_and_update_results] Instance {instance_id} completed with status {status}"
                            )
                        else:
                            # Still running
                            all_completed = False
                            execution.status = "running"

                        db.commit()

                    if status not in terminal_states:
                        all_completed = False

                except Exception as e:
                    logger.error(
                        f"[poll_and_update_results] Error checking status for instance {instance_id}: {e}"
                    )
                    # Mark as failed if we can't get status
                    execution = execution_map.get(instance_id)
                    if execution and execution.status == "running":
                        execution.status = "failed"
                        execution.error = f"Failed to get command status: {str(e)}"
                        execution.end_time = datetime.utcnow()
                        db.commit()

            if all_completed:
                logger.info(
                    f"[poll_and_update_results] All instances completed for command {command_id}"
                )
                break

            # Wait before next poll
            time.sleep(poll_interval)

        # If we hit the timeout, mark remaining running executions as timed out
        if time.time() - start_time >= max_wait_time:
            logger.warning(
                f"[poll_and_update_results] Timeout reached for command {command_id}"
            )
            for instance_id in instance_ids:
                execution = execution_map.get(instance_id)
                if execution and execution.status == "running":
                    execution.status = "failed"
                    execution.error = "Command execution timed out"
                    execution.end_time = datetime.utcnow()
            db.commit()

    except Exception as e:
        logger.error(f"[poll_and_update_results] Error polling for results: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")


def execute_batch(
    batch_id: str,
    script: Dict[str, Any],
    execution_ids: List[int],
    instances_by_env: Dict[str, List[Dict]],
    credential_manager,  # Shared credential manager instance
):
    """Background task to execute scripts.
    
    This function is designed to be run in a thread pool with proper resource management.
    It serves as the core execution engine for all specialized AWS script execution tools.
    """
    logger.info(f"[execute_batch] STARTED - batch_id={batch_id}")

    # Acquire semaphore to track active executions with timeout
    if not active_executions_count.acquire(timeout=60):
        logger.error(f"[execute_batch] Timeout waiting for execution slot for batch {batch_id}")
        # Mark all executions as failed in database
        from backend.db.session import SessionLocal
        db = SessionLocal()
        try:
            executions = db.query(Execution).filter(Execution.id.in_(execution_ids)).all()
            for execution in executions:
                execution.status = "failed"
                execution.error = "Execution queue timeout - too many concurrent executions"
                execution.end_time = datetime.utcnow()
            db.commit()
        finally:
            db.close()
        return

    # Create a new database session for the background task
    from backend.db.session import SessionLocal

    db = SessionLocal()

    try:
        logger.info(
            f"[execute_batch] Starting batch {batch_id} for {sum(len(v) for v in instances_by_env.values())} instance(s)"
        )
        logger.info(f"[execute_batch] Execution IDs: {execution_ids}")
        logger.info(
            f"[execute_batch] Instances by env: {list(instances_by_env.keys())}"
        )
        ssm_executor = SSMExecutor()

        # Fetch executions from database using IDs
        executions = db.query(Execution).filter(Execution.id.in_(execution_ids)).all()

        # Create a mapping for quick lookup
        execution_map = {e.instance_id: e for e in executions}

        for env, env_instances in instances_by_env.items():
            logger.info(
                f"[execute_batch] Processing {len(env_instances)} instances in {env} environment"
            )
            aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
            credentials = credential_manager.get_credentials(aws_env.value)

            if not credentials:
                # Mark all executions for this environment as failed
                logger.error(
                    f"[execute_batch] No credentials for {env.upper()} environment"
                )
                for instance in env_instances:
                    execution = execution_map.get(instance["instance_id"])
                    if execution:
                        execution.status = "failed"
                        execution.error = (
                            f"No credentials available for {env.upper()} environment"
                        )
                        execution.end_time = datetime.utcnow()
                        db.commit()
                logger.error(
                    f"No credentials for {env.upper()} environment - marking executions as failed"
                )
                continue

            logger.info(
                f"[execute_batch] Found credentials for {env.upper()} environment"
            )

            # Group instances by account+region for batch SSM commands
            instances_by_account_region = {}
            for instance in env_instances:
                key = (instance["account_id"], instance["region"])
                if key not in instances_by_account_region:
                    instances_by_account_region[key] = []
                instances_by_account_region[key].append(instance)

            logger.info(
                f"[execute_batch] Grouped instances into {len(instances_by_account_region)} account+region combinations"
            )

            # Execute one SSM command per account+region group
            for (
                account_id,
                region,
            ), group_instances in instances_by_account_region.items():
                instance_ids = [inst["instance_id"] for inst in group_instances]
                logger.info(
                    f"[execute_batch] Sending batch command to {len(instance_ids)} instances in account {account_id}, region {region}"
                )
                logger.info(f"[execute_batch] Instance IDs for batch: {instance_ids}")

                try:
                    # Execute script on all instances in this account+region as a batch
                    result = ssm_executor.execute_script_batch(
                        instance_ids=instance_ids,
                        script_content=script["content"],
                        interpreter=script["interpreter"],
                        account_id=account_id,
                        region=region,
                        credentials=credentials,
                    )

                    logger.info(
                        f"[execute_batch] SSM batch executor returned: {result}"
                    )
                    command_id = result.get("command_id")

                    # Update all executions with the same command_id and initial status
                    for instance in group_instances:
                        execution = execution_map.get(instance["instance_id"])
                        if execution:
                            execution.command_id = command_id
                            execution.status = "running" if command_id else "failed"
                            execution.output = ""
                            execution.error = (
                                result.get("error", "") if not command_id else ""
                            )
                            if not command_id:
                                execution.end_time = datetime.utcnow()
                            logger.info(
                                f"[execute_batch] Updated execution for {instance['instance_id']}: status={execution.status}, command_id={execution.command_id}"
                            )

                    db.commit()

                    # If command was sent successfully, poll for results
                    if command_id:
                        logger.info(
                            f"[execute_batch] Starting to poll for results for command {command_id}"
                        )
                        poll_and_update_results(
                            command_id=command_id,
                            instance_ids=instance_ids,
                            account_id=account_id,
                            region=region,
                            credentials=credentials,
                            execution_map=execution_map,
                            db=db,
                            ssm_executor=ssm_executor,
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to execute batch on account {account_id}, region {region}: {e}"
                    )
                    # Mark all executions in this group as failed
                    for instance in group_instances:
                        execution = execution_map.get(instance["instance_id"])
                        if execution:
                            execution.status = "failed"
                            execution.error = str(e)
                            execution.end_time = datetime.utcnow()
                    db.commit()

    except Exception as e:
        logger.error(f"Error in batch execution: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
        # Release semaphore and close database session
        active_executions_count.release()
        db.close()
        logger.info(f"[execute_batch] COMPLETED - batch_id={batch_id}")


def submit_execution(
    batch_id: str,
    script: Dict[str, Any],
    execution_ids: List[int],
    instances_by_env: Dict[str, List[Dict]],
    credential_manager,
) -> None:
    """Submit a script execution to the thread pool.
    
    This is the main entry point for specialized tools to execute scripts.
    
    Args:
        batch_id: Unique identifier for this batch
        script: Dictionary with script details (name, content, interpreter)
        execution_ids: List of Execution model IDs to update
        instances_by_env: Dictionary of instances grouped by environment
        credential_manager: Credential manager instance for AWS authentication
    """
    logger.info(f"Submitting batch {batch_id} to thread pool")

    # Submit to thread pool to prevent resource exhaustion
    future = execution_thread_pool.submit(
        execute_batch,
        batch_id,
        script,
        execution_ids,
        instances_by_env,
        credential_manager,
    )

    logger.info(f"Batch {batch_id} submitted to thread pool")
    return future
