from typing import Any, Dict

import aiobotocore.session
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.providers.aws.common.schemas.account import (
    AWSCredentialsRequest,
)

# Create router
router = APIRouter()

# Environment configurations
ENV_CONFIGS = {
    "gov": {
        "region": "us-gov-west-1",
        "endpoint": "https://sts.us-gov-west-1.amazonaws.com",
    },
    "com": {
        "region": "us-east-1",
        "endpoint": "https://sts.us-east-1.amazonaws.com",
    },
}


def create_aio_session_from_credentials(
    credentials: AWSCredentialsRequest,
) -> aiobotocore.session.AioSession:
    """Create an aiobotocore session from provided credentials"""
    session = aiobotocore.session.get_session()
    session.set_credentials(
        credentials.access_key,
        credentials.secret_key,
        credentials.session_token
    )
    return session


@router.post("/", response_model=Dict[str, Any])
async def list_accounts(
    credentials: AWSCredentialsRequest, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    List all AWS accounts for a specific environment using provided credentials.

    This endpoint retrieves accounts from AWS Organizations API or
    from the current credentials if Organizations access is not available.
    Credentials must be provided in the request body.
    """
    try:
        # Create session with provided credentials
        session = create_aio_session_from_credentials(credentials)

        # Validate credentials by making a test call
        env_config = ENV_CONFIGS.get(credentials.environment)
        if not env_config:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid environment: {credentials.environment}",
            )

        async with session.create_client(
            "sts", region_name=env_config["region"], endpoint_url=env_config["endpoint"]
        ) as sts:
            # Test credentials
            caller_identity = await sts.get_caller_identity()
            account_id = caller_identity.get("Account")

        # Try to list accounts using Organizations (if available)
        try:
            async with session.create_client(
                "organizations", region_name=env_config["region"]
            ) as org_client:
                accounts_response = await org_client.list_accounts()
                accounts = [
                    {
                        "account_id": acc["Id"],
                        "name": acc["Name"],
                        "status": acc["Status"],
                        "email": acc["Email"],
                    }
                    for acc in accounts_response.get("Accounts", [])
                ]
        except ClientError:
            # Organizations not available, return current account
            accounts = [
                {
                    "account_id": account_id,
                    "name": f"Account {account_id}",
                    "status": "ACTIVE",
                    "email": "unknown",
                }
            ]

        return {
            "environment": credentials.environment,
            "accounts": accounts,
            "current_account": account_id,
        }

    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS credential validation failed: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing accounts: {str(e)}",
        )


@router.post("/{account_id}", response_model=Dict[str, Any])
async def get_account_details(
    account_id: str, credentials: AWSCredentialsRequest, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get detailed information for a specific AWS account using provided credentials.
    
    Returns account metadata, available regions, and basic account information.
    """
    try:
        # Create session with provided credentials
        session = create_aio_session_from_credentials(credentials)

        # Validate credentials and get account info
        env_config = ENV_CONFIGS.get(credentials.environment)
        if not env_config:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid environment: {credentials.environment}",
            )

        async with session.create_client(
            "sts", region_name=env_config["region"], endpoint_url=env_config["endpoint"]
        ) as sts:
            # Test credentials and get caller identity
            caller_identity = await sts.get_caller_identity()
            current_account_id = caller_identity.get("Account")

        # Verify the requested account matches the credentials
        if current_account_id != account_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account ID mismatch: credentials are for {current_account_id}, but {account_id} was requested",
            )

        # Get account details
        account_details = {
            "account_id": account_id,
            "arn": caller_identity.get("Arn"),
            "user_id": caller_identity.get("UserId"),
            "environment": credentials.environment,
        }

        # Try to get additional account info from Organizations (if available)
        try:
            async with session.create_client("organizations", region_name=env_config["region"]) as org_client:
                account_info = await org_client.describe_account(AccountId=account_id)
                account_details.update({
                    "name": account_info["Account"]["Name"],
                    "email": account_info["Account"]["Email"],
                    "status": account_info["Account"]["Status"],
                })
        except ClientError:
            # Organizations not available, use basic info
            account_details.update({
                "name": f"Account {account_id}",
                "email": "unknown",
                "status": "ACTIVE",
            })

        # Get available regions for this environment
        try:
            async with session.create_client("ec2", region_name=env_config["region"]) as ec2:
                regions_response = await ec2.describe_regions()
                available_regions = [region["RegionName"] for region in regions_response["Regions"]]
        except ClientError:
            # Fallback to common regions based on environment
            if credentials.environment == "gov":
                available_regions = ["us-gov-west-1", "us-gov-east-1"]
            else:
                available_regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1"]

        account_details["available_regions"] = available_regions

        return account_details

    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS credential validation failed: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting account details: {str(e)}",
        )


@router.post("/{account_id}/instances", response_model=Dict[str, Any])
async def list_instances(
    account_id: str,
    credentials: AWSCredentialsRequest,
    region: str = "us-east-1",
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    List EC2 instances in a specific account and region using provided credentials.
    
    Returns a list of instances with their basic information including
    instance ID, type, state, name, and SSM management status.
    """
    try:
        # Create session with provided credentials
        session = create_aio_session_from_credentials(credentials)

        # Validate credentials
        env_config = ENV_CONFIGS.get(credentials.environment)
        if not env_config:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid environment: {credentials.environment}",
            )

        async with session.create_client(
            "sts", region_name=env_config["region"], endpoint_url=env_config["endpoint"]
        ) as sts:
            # Test credentials and verify account
            caller_identity = await sts.get_caller_identity()
            current_account_id = caller_identity.get("Account")

        if current_account_id != account_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account ID mismatch: credentials are for {current_account_id}, but {account_id} was requested",
            )

        # Get EC2 instances
        async with session.create_client("ec2", region_name=region) as ec2:
            response = await ec2.describe_instances()

            instances = []
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    # Extract instance name from tags
                    name = ""
                    for tag in instance.get("Tags", []):
                        if tag.get("Key") == "Name":
                            name = tag.get("Value", "")
                            break

                    # Determine platform
                    platform = "windows" if instance.get("Platform") == "windows" else "linux"

                    instance_info = {
                        "instance_id": instance["InstanceId"],
                        "name": name,
                        "type": instance.get("InstanceType", "unknown"),
                        "state": instance.get("State", {}).get("Name", "unknown"),
                        "platform": platform,
                        "private_ip": instance.get("PrivateIpAddress", ""),
                        "public_ip": instance.get("PublicIpAddress", ""),
                        "launch_time": instance.get("LaunchTime"),
                        "account_id": account_id,
                        "region": region,
                    }
                    instances.append(instance_info)

        return {
            "account_id": account_id,
            "region": region,
            "environment": credentials.environment,
            "instances": instances,
            "total_count": len(instances),
        }

    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS API error: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing instances: {str(e)}",
        )


@router.post("/{account_id}/instances/{instance_id}/status", response_model=Dict[str, Any])
async def get_instance_status(
    account_id: str,
    instance_id: str,
    credentials: AWSCredentialsRequest,
    region: str = "us-east-1",
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get detailed status information for a specific EC2 instance using provided credentials.
    
    Returns instance state, health checks, and SSM connectivity status.
    """
    try:
        # Create session with provided credentials
        session = create_aio_session_from_credentials(credentials)

        # Validate credentials
        env_config = ENV_CONFIGS.get(credentials.environment)
        if not env_config:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid environment: {credentials.environment}",
            )

        async with session.create_client(
            "sts", region_name=env_config["region"], endpoint_url=env_config["endpoint"]
        ) as sts:
            # Test credentials and verify account
            caller_identity = await sts.get_caller_identity()
            current_account_id = caller_identity.get("Account")

        if current_account_id != account_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account ID mismatch: credentials are for {current_account_id}, but {account_id} was requested",
            )

        # Get instance details
        async with session.create_client("ec2", region_name=region) as ec2:
            try:
                response = await ec2.describe_instances(InstanceIds=[instance_id])
            except ClientError as e:
                if "InvalidInstanceID" in str(e):
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Instance {instance_id} not found",
                    )
                raise

            if not response["Reservations"]:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Instance {instance_id} not found",
                )

            instance = response["Reservations"][0]["Instances"][0]

            # Get instance status checks
            status_response = await ec2.describe_instance_status(InstanceIds=[instance_id])
            status_info = status_response.get("InstanceStatuses", [{}])[0] if status_response.get("InstanceStatuses") else {}

        # Check SSM connectivity
        ssm_managed = False
        ssm_ping_status = "unknown"
        try:
            async with session.create_client("ssm", region_name=region) as ssm:
                ping_response = await ssm.describe_instance_information(
                    InstanceInformationFilterList=[
                        {"key": "InstanceIds", "valueSet": [instance_id]}
                    ]
                )
                if ping_response.get("InstanceInformationList"):
                    ssm_managed = True
                    ssm_ping_status = ping_response["InstanceInformationList"][0].get("PingStatus", "unknown")
        except ClientError:
            # SSM not available or instance not managed
            pass

        # Extract instance name from tags
        name = ""
        for tag in instance.get("Tags", []):
            if tag.get("Key") == "Name":
                name = tag.get("Value", "")
                break

        instance_status = {
            "instance_id": instance_id,
            "name": name,
            "account_id": account_id,
            "region": region,
            "environment": credentials.environment,
            "state": instance.get("State", {}).get("Name", "unknown"),
            "instance_type": instance.get("InstanceType", "unknown"),
            "platform": "windows" if instance.get("Platform") == "windows" else "linux",
            "private_ip": instance.get("PrivateIpAddress", ""),
            "public_ip": instance.get("PublicIpAddress", ""),
            "launch_time": instance.get("LaunchTime"),
            "availability_zone": instance.get("Placement", {}).get("AvailabilityZone", ""),
            "system_status": status_info.get("SystemStatus", {}).get("Status", "unknown"),
            "instance_status": status_info.get("InstanceStatus", {}).get("Status", "unknown"),
            "ssm_managed": ssm_managed,
            "ssm_ping_status": ssm_ping_status,
        }

        return instance_status

    except ClientError as e:
        if "InvalidInstanceID" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Instance {instance_id} not found",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"AWS API error: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting instance status: {str(e)}",
        )
