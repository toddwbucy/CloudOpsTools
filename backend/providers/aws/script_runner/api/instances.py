"""
API endpoints for EC2 instance operations.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, status

from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.services.ec2_manager import EC2Manager

# Create router
router = APIRouter(
    tags=["instances"],
    responses={
        404: {"description": "Not found"},
        401: {"description": "Unauthorized"},
        500: {"description": "Internal server error"},
    },
)

# Initialize services
credential_manager = CredentialManager()
logger = logging.getLogger(__name__)


@router.get("/", response_model=List[Dict[str, Any]])
async def list_instances(
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query(..., description="AWS Region"),
    x_aws_environment: Optional[str] = Header(
        None, description="AWS environment (com or gov)"
    ),
    x_aws_access_key: Optional[str] = Header(None, description="AWS Access Key ID"),
    x_aws_secret_key: Optional[str] = Header(None, description="AWS Secret Access Key"),
    x_aws_session_token: Optional[str] = Header(None, description="AWS Session Token"),
) -> List[Dict[str, Any]]:
    """
    List EC2 instances in a specific account and region.

    This endpoint returns a list of EC2 instances with their basic information
    including instance ID, type, state, and SSM management status.
    """

    # Determine environment from region if not provided
    if not x_aws_environment:
        x_aws_environment = "gov" if "gov" in region.lower() else "com"

    # Check for credentials in headers first
    if x_aws_access_key and x_aws_secret_key:
        # Store credentials for this request
        from backend.core.config import AWSCredentials, AWSEnvironment
        aws_credentials = AWSCredentials(
            access_key=x_aws_access_key,
            secret_key=x_aws_secret_key,
            session_token=x_aws_session_token,
            environment=AWSEnvironment(x_aws_environment)
        )
        credential_manager.store_credentials(aws_credentials)
    else:
        # Check if we have stored credentials
        if not credential_manager.are_credentials_valid(x_aws_environment):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"No valid credentials found for {x_aws_environment} environment. Please provide credentials.",
            )

    try:
        # Create EC2 manager
        ec2_manager = EC2Manager(credential_manager)

        # Get instances
        instances = await ec2_manager.describe_instances(
            account_id=account_id,
            region=region,
            environment=x_aws_environment
        )

        # Format response
        formatted_instances = []
        for instance in instances:
            # Check SSM status asynchronously
            is_managed = await ec2_manager.is_instance_managed_by_ssm(
                instance["InstanceId"], account_id, region, x_aws_environment
            )
            
            formatted_instance = {
                "id": instance["InstanceId"],
                "instance_id": instance["InstanceId"],
                "type": instance.get("InstanceType", "unknown"),
                "state": instance.get("State", {}).get("Name", "unknown"),
                "name": "",  # Will be populated from tags
                "private_ip": instance.get("PrivateIpAddress", ""),
                "public_ip": instance.get("PublicIpAddress", ""),
                "platform": ec2_manager.get_instance_platform(instance),
                "ssm_managed": is_managed,
                "account_id": account_id,
                "region": region,
            }

            # Extract name from tags
            for tag in instance.get("Tags", []):
                if tag.get("Key") == "Name":
                    formatted_instance["name"] = tag.get("Value", "")
                    break

            formatted_instances.append(formatted_instance)

        return formatted_instances

    except Exception as e:
        logger.error(f"Error listing instances in {account_id}/{region}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list instances: {str(e)}",
        )
