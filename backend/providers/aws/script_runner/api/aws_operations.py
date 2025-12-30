"""
API endpoints for resilient AWS operations that can handle credential expiration
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from fastapi import APIRouter, BackgroundTasks, Body, HTTPException

from backend.providers.aws.common.services.account_manager import AWSAccountManager
from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.services.execution_state_manager import (
    AWSExecutionStateManager,
)
from backend.providers.aws.script_runner.services.org_visitor import OrgVisitor

# Initialize logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    tags=["aws-scans"],
    responses={
        404: {"description": "Not found"},
        401: {"description": "Unauthorized"},
        500: {"description": "Internal server error"},
    },
)

# Initialize services
credential_manager = CredentialManager()
account_manager = AWSAccountManager(credential_manager)
execution_state_manager = AWSExecutionStateManager(credential_manager)
org_visitor = OrgVisitor(credential_manager)


import aiobotocore.session

async def perform_account_scan_task(execution_id: str) -> None:
    """Background task for scanning AWS accounts

    Args:
        execution_id: ID of the execution
    """
    # Get execution details
    execution = execution_state_manager.get_execution(execution_id)
    if not execution:
        logger.error(f"Execution {execution_id} not found")
        return

    # Extract parameters
    environment = execution["environment"]
    account_ids = execution["params"].get("account_ids", [])
    regions = execution["params"].get("regions", [])
    role_name = execution["params"].get("role_name", "OrganizationAccountAccessRole")

    # Start the execution
    if not execution_state_manager.start_execution(execution_id):
        logger.error(f"Failed to start execution {execution_id}")
        return

    # Process accounts
    results = {}

    # Create aiobotocore session
    session = aiobotocore.session.get_session()

    for account_id in account_ids:
        # Check if credentials are still valid
        if not execution_state_manager.check_credentials(execution_id):
            logger.warning(f"Credentials expired during execution {execution_id}")
            return

        try:
            # Create result structure for this account
            account_results: Dict[str, Any] = {}
            region_results: Dict[str, Any] = {"regions": {}}

            # Process regions for this account
            for region in regions:
                # Check credentials again
                if not execution_state_manager.check_credentials(execution_id):
                    logger.warning(
                        f"Credentials expired during execution {execution_id}"
                    )
                    return

                try:
                    # Assume role in the account
                    assumed_role = await account_manager.assume_role(account_id, region)
                    if not assumed_role:
                        account_results["regions"][region] = {
                            "status": "error",
                            "error": "Failed to assume role",
                        }
                        continue

                    # Create EC2 client with assumed role credentials
                    async with session.create_client(
                        "ec2",
                        region_name=region,
                        aws_access_key_id=assumed_role["AccessKeyId"],
                        aws_secret_access_key=assumed_role["SecretAccessKey"],
                        aws_session_token=assumed_role["SessionToken"],
                    ) as ec2_client:

                        # Describe instances
                        response = await ec2_client.describe_instances()

                        # Process the instances
                        instances = []
                        for reservation in response.get("Reservations", []):
                            for instance in reservation.get("Instances", []):
                                instances.append(
                                    {
                                        "id": instance.get("InstanceId"),
                                        "state": instance.get("State", {}).get("Name"),
                                        "type": instance.get("InstanceType"),
                                        "private_ip": instance.get("PrivateIpAddress"),
                                        "public_ip": instance.get("PublicIpAddress"),
                                    }
                                )

                        # Store region results
                        account_results["regions"][region] = {
                            "status": "success",
                            "instance_count": len(instances),
                            "instances": instances,
                        }

                except Exception as e:
                    account_results["regions"][region] = {
                        "status": "error",
                        "error": str(e),
                    }
                    logger.error(
                        f"Error processing region {region} for account {account_id}: {str(e)}"
                    )

            # Store account results
            results[account_id] = account_results

            # Complete this step
            if not execution_state_manager.complete_step(
                execution_id, {"account_id": account_id, "result": account_results}
            ):
                break

        except Exception as e:
            logger.error(f"Error processing account {account_id}: {str(e)}")
            execution_state_manager.fail_step(
                execution_id, f"Error processing account {account_id}: {str(e)}"
            )
            return

    # Update final results
    execution_state_manager.complete_step(execution_id, {"final_results": results})


@router.post("/start", status_code=202)
async def start_account_scan(
    background_tasks: BackgroundTasks,
    environment: str = Body(..., description="AWS environment (com or gov)"),
    account_ids: List[str] = Body(..., description="List of AWS account IDs to scan"),
    regions: List[str] = Body(..., description="List of AWS regions to scan"),
    role_name: str = Body(
        "OrganizationAccountAccessRole",
        description="Role name to assume in target accounts",
    ),
) -> Dict[str, Any]:
    """
    Start a resilient scan of AWS accounts that can resume after credential refresh

    This operation scans EC2 instances in multiple AWS accounts and regions.
    If credentials expire during the operation, it can be resumed later.
    """
    # Validate environment
    if environment not in ["com", "gov"]:
        raise HTTPException(
            status_code=400, detail="Invalid environment, must be 'com' or 'gov'"
        )

    # Check if credentials are valid
    if not credential_manager.are_credentials_valid(environment):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials, please provide valid AWS credentials",
        )

    # Create execution
    try:
        execution_id = execution_state_manager.create_execution(
            execution_type="account_scan",
            environment=environment,
            params={
                "account_ids": account_ids,
                "regions": regions,
                "role_name": role_name,
            },
            steps=[{"name": f"scan_account_{account_id}"} for account_id in account_ids]
            + [{"name": "finalize_results"}],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Start background task
    background_tasks.add_task(perform_account_scan_task, execution_id)

    return {"message": "Account scan started", "scan_id": execution_id}


@router.get("/{scan_id}")
async def get_scan_status(scan_id: str) -> Dict[str, Any]:
    """
    Get the status of a long-running execution

    This endpoint returns the current status and results of an execution.
    """
    execution = execution_state_manager.get_execution(scan_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    return execution


@router.post("/{scan_id}/resume", status_code=202)
async def resume_scan(
    scan_id: str, background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Resume an execution after credentials have been refreshed

    This endpoint resumes an execution that was paused due to expired credentials.
    """
    execution = execution_state_manager.get_execution(scan_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check if execution is in the correct state
    if execution["status"] != "credentials_expired":
        raise HTTPException(status_code=400, detail="Scan is not in a resumable state")

    # Check if credentials are valid now
    if not credential_manager.are_credentials_valid(execution["environment"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials, please provide valid AWS credentials",
        )

    # Resume the execution
    if not execution_state_manager.resume_execution(scan_id):
        raise HTTPException(status_code=400, detail="Failed to resume scan")

    # Start background task to continue execution
    background_tasks.add_task(perform_account_scan_task, scan_id)

    return {"message": "Scan resumed", "scan_id": scan_id}


@router.get("/")
async def list_scans(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all scans with optional status filter

    This endpoint returns a list of all scans.
    """
    return execution_state_manager.list_executions(status)
