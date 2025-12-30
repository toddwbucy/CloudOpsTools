"""
API endpoints for AWS organization traversal.
"""

import logging
from typing import Any, Dict, List, Optional

import aiobotocore.session
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.script_runner.services.org_visitor import OrgVisitor

# Create router
router = APIRouter()

# Create service instances
credential_manager = CredentialManager()
org_visitor = OrgVisitor(credential_manager)

# Configure logging
logger = logging.getLogger(__name__)


class OrgVisitRequest(BaseModel):
    """Request model for organization traversal"""

    environment: str = "com"
    role_name: str = "OrganizationAccountAccessRole"
    parent_id: Optional[str] = None
    visitor_type: str = "instances"  # Options: "instances", "buckets", "custom"
    custom_account_query: Optional[str] = None
    custom_region_query: Optional[str] = None


@router.post("/visit-organization", response_model=Dict[str, Any])
async def visit_organization(request: OrgVisitRequest) -> Dict[str, Any]:
    """
    Traverse an AWS organization structure and execute visitor functions.

    This endpoint traverses the AWS organization structure, assumes roles in each account,
    and executes visitor functions for each account and region. It returns results from
    all accounts and regions visited.

    The visitor_type parameter determines what visitors are used:
    - "instances": List EC2 instances in each account/region
    - "buckets": List S3 buckets in each account/region
    - "custom": Execute custom query provided in request
    """
    # Check if credentials are valid
    if not credential_manager.are_credentials_valid(request.environment):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No valid credentials found for {request.environment} environment",
        )

    # Define visitor functions based on request type
    if request.visitor_type == "instances":
        # List EC2 instances in each account/region
        async def account_visitor(session: aiobotocore.session.AioSession, account_id: str) -> Dict[str, Any]:
            async with session.create_client("sts") as sts:
                identity = await sts.get_caller_identity()
            return {"account_id": account_id, "caller_identity": identity}

        async def region_visitor(
            session: aiobotocore.session.AioSession, region: str, account_id: str
        ) -> Dict[str, Any]:
            instances = []
            try:
                async with session.create_client("ec2", region_name=region) as ec2:
                    paginator = ec2.get_paginator("describe_instances")
                    async for page in paginator.paginate():
                        for reservation in page["Reservations"]:
                            instances.extend(reservation["Instances"])
                return {
                    "count": len(instances),
                    "instances": [
                        {
                            "id": i["InstanceId"],
                            "type": i.get("InstanceType", "unknown"),
                        }
                        for i in instances
                    ],
                }
            except Exception as e:
                logger.error(
                    f"Error listing instances in {account_id}/{region}: {str(e)}"
                )
                raise

    elif request.visitor_type == "buckets":
        # List S3 buckets in each account/region
        async def account_visitor(session: aiobotocore.session.AioSession, account_id: str) -> Dict[str, Any]:
            async with session.create_client("sts") as sts:
                identity = await sts.get_caller_identity()
            
            try:
                async with session.create_client("s3") as s3:
                    buckets = await s3.list_buckets()
                return {
                    "account_id": account_id,
                    "bucket_count": len(buckets.get("Buckets", [])),
                    "caller_identity": identity,
                }
            except Exception as e:
                logger.error(f"Error listing buckets in {account_id}: {str(e)}")
                raise

        async def region_visitor(
            session: aiobotocore.session.AioSession, region: str, account_id: str
        ) -> Dict[str, Any]:
            # S3 buckets are global, but we can list the ones in this region
            # For this example, we'll just return a message as S3 is global
            return {"region": region, "message": "S3 buckets are global resources"}

    elif request.visitor_type == "custom":
        # Execute custom query
        if not request.custom_account_query or not request.custom_region_query:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom visitor type requires both custom_account_query and custom_region_query",
            )

        # Create dynamic visitors using provided queries
        # WARNING: This approach has significant security implications
        try:
            # Create account visitor function - MUST be async
            account_code = f"async def dynamic_account_visitor(session, account_id):\n    # Custom query must be awaitable if it uses session calls\n    # For now, we assume the user provides valid async code or synchronous logic\n    # But since we are inside an async function, we can use await\n    result = {request.custom_account_query}\n    return result"
            region_code = f"async def dynamic_region_visitor(session, region, account_id):\n    result = {request.custom_region_query}\n    return result"

            account_locals: Dict[str, Any] = {}
            region_locals: Dict[str, Any] = {}

            exec(account_code, globals(), account_locals)
            exec(region_code, globals(), region_locals)

            account_visitor = account_locals["dynamic_account_visitor"]
            region_visitor = region_locals["dynamic_region_visitor"]

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid custom query: {str(e)}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid visitor_type: {request.visitor_type}",
        )

    # Execute the organization traversal
    results = await org_visitor.visit_organization(
        environment=request.environment,
        account_visitor=account_visitor,
        region_visitor=region_visitor,
        role_name=request.role_name,
        parent_id=request.parent_id,
    )

    return results


@router.get("/organization-accounts", response_model=Dict[str, Any])
async def list_organization_accounts(
    environment: str = Query("com", description="AWS environment (gov or com)"),
    parent_id: Optional[str] = Query(
        None, description="Optional parent ID to list accounts under"
    ),
) -> Dict[str, Any]:
    """
    List accounts in an AWS organization.

    This endpoint lists accounts in an AWS organization, optionally filtered by parent ID.
    """
    # Check if credentials are valid
    if not credential_manager.are_credentials_valid(environment):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No valid credentials found for {environment} environment",
        )

    try:
        # Create session
        # We need to get credentials and create an aiobotocore session manually
        # as credential_manager.create_session returns a boto3 session
        creds = credential_manager._get_credentials(environment)
        if not creds:
             raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve credentials for {environment}",
            )
            
        session = aiobotocore.session.get_session()
        session.set_credentials(
            access_key=creds.access_key,
            secret_key=creds.secret_key,
            token=creds.session_token
        )

        # List accounts
        async with org_visitor.get_organization_client(session) as org_client:
            accounts = await org_visitor.get_accounts(org_client, parent_id)

            # Get detailed information for each account
            detailed_accounts = []
            for account_id in accounts:
                try:
                    # Get account details
                    response = await org_client.describe_account(AccountId=account_id)
                    detailed_accounts.append(response["Account"])
                except Exception as e:
                    logger.error(
                        f"Error getting details for account {account_id}: {str(e)}"
                    )
                    detailed_accounts.append(
                        {"Id": account_id, "Status": "UNKNOWN", "Error": str(e)}
                    )

            return {
                "status": "success",
                "account_count": len(detailed_accounts),
                "accounts": detailed_accounts,
            }

    except Exception as e:
        logger.error(f"Error listing organization accounts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing organization accounts: {str(e)}",
        )
