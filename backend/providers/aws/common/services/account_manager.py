import logging
from typing import Any, Dict, List, Optional
import traceback

import aiobotocore.session
from botocore.exceptions import ClientError, EndpointConnectionError

from backend.providers.aws.common.services.credential_manager import CredentialManager
from backend.providers.aws.common.schemas.account import AWSCredentials
from backend.providers.aws.script_runner.services.execution_state_manager import (
    AWSExecutionStateManager,
)

logger = logging.getLogger(__name__)


class AWSAccountManager:
    """Service for AWS account management operations (Async)"""

    def __init__(self, credential_manager: CredentialManager):
        self.credential_manager = credential_manager
        self.default_region = "us-east-1"
        self.retry_regions = {"gov": "us-gov-west-1", "com": "us-east-1"}
        # Initialize the execution state manager
        self.execution_state_manager = AWSExecutionStateManager(credential_manager)

    async def assume_role(
        self,
        account_id: str,
        region_name: str,
        credentials: Optional[AWSCredentials] = None,
    ) -> Optional[Dict[str, Any]]:
        """Assume role in specified account and region using provided credentials if given (Async)."""
        arn_prefix = "arn:aws-us-gov" if "us-gov" in region_name else "arn:aws"
        role_arn = f"{arn_prefix}:iam::{account_id}:role/OrganizationAccountAccessRole"

        try:
            # Create session
            session = aiobotocore.session.get_session()
            
            # Determine client configuration
            client_kwargs = {
                "service_name": "sts",
                "region_name": region_name,
            }

            if credentials:
                # Use explicitly supplied base credentials
                client_kwargs.update({
                    "aws_access_key_id": credentials.access_key,
                    "aws_secret_access_key": credentials.secret_key,
                    "aws_session_token": getattr(credentials, "session_token", None),
                })
                
                async with session.create_client(**client_kwargs) as sts_client:
                    # Assume the role
                    response = await sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="OrganizationAccessSession"
                    )
            else:
                # Use environment credentials from credential manager
                environment = "gov" if "us-gov" in region_name else "com"
                
                # Use credential manager's create_client which handles auth
                async with self.credential_manager.create_client(
                    "sts", environment, region_name
                ) as sts_client:
                    if not sts_client:
                        logger.error(
                            f"Failed to create STS client for {environment} in {region_name}"
                        )
                        return None
                        
                    # Assume the role
                    response = await sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="OrganizationAccessSession"
                    )

            # Convert to Dict[str, Any] to match the return type
            if "Credentials" in response:
                creds = response["Credentials"]
                return {
                    "AccessKeyId": creds["AccessKeyId"],
                    "SecretAccessKey": creds["SecretAccessKey"],
                    "SessionToken": creds["SessionToken"],
                    "Expiration": creds["Expiration"],
                }
            return None

        except Exception as e:
            logger.error(f"Error assuming role in account {account_id}: {str(e)}")
            logger.error(f"Traceback for assume_role: {traceback.format_exc()}")
            logger.error(f"Attempted to assume role: {role_arn}")
            return None

    async def list_available_regions(
        self, environment: str, service: str = "ec2"
    ) -> List[str]:
        """List available AWS regions for a service (Async)"""
        try:
            logger.debug(
                f"Listing available regions for service: {service} in {environment}"
            )
            regions: List[str] = []

            # Use environment-specific region for API calls
            region = self.retry_regions.get(environment.lower(), self.default_region)

            # Get client using credential manager
            async with self.credential_manager.create_client(service, environment, region) as client:
                if not client:
                    logger.error("Failed to create client for listing regions")
                    return []

                try:
                    response = await client.describe_regions()
                    if environment.lower() == "gov":
                        regions = [
                            r["RegionName"]
                            for r in response["Regions"]
                            if "gov" in r["RegionName"]
                        ]
                    else:
                        regions = [
                            r["RegionName"]
                            for r in response["Regions"]
                            if r["RegionName"].startswith("us-")
                            and "gov" not in r["RegionName"]
                        ]
                    logger.info(f"Retrieved {len(regions)} regions from {region}")
                except (ClientError, EndpointConnectionError) as e:
                    logger.warning(f"Failed to list regions from {region}: {str(e)}")

            if not regions:
                logger.error("Failed to retrieve regions from any endpoint")

            return regions

        except Exception as e:
            logger.error(f"Error listing available regions: {str(e)}")
            return []

    async def get_caller_identity(self, environment: str) -> Optional[Dict[str, Any]]:
        """Get identity information for the caller (Async)"""
        try:
            async with self.credential_manager.create_client("sts", environment) as client:
                if not client:
                    logger.error(f"Failed to create STS client for {environment}")
                    return None

                response = await client.get_caller_identity()
                logger.info(
                    f"Successfully retrieved caller identity: {response['Account']}"
                )
                # Explicitly cast the response to fix the Any return type
                return dict(response)
        except Exception as e:
            logger.error(f"Error getting caller identity: {str(e)}")
            return None

    async def list_accounts(self, environment: str) -> List[Dict[str, Any]]:
        """List AWS accounts accessible to the caller (Async)"""
        try:
            async with self.credential_manager.create_client("organizations", environment) as client:
                if not client:
                    logger.error(f"Failed to create Organizations client for {environment}")
                    return []

                # Try to list accounts in the organization
                accounts = []
                paginator = client.get_paginator("list_accounts")
                async for page in paginator.paginate():
                    accounts.extend(page["Accounts"])

                logger.info(f"Retrieved {len(accounts)} accounts from organizations API")
                return accounts
        except Exception as e:
            # If organizations API fails, just return the caller's account
            logger.warning(f"Failed to list accounts using organizations API: {str(e)}")

            identity = await self.get_caller_identity(environment)
            if identity:
                return [
                    {
                        "Id": identity["Account"],
                        "Name": f"Account {identity['Account']}",
                        "Status": "ACTIVE",
                    }
                ]
            return []

    async def describe_instances(
        self, account_id: str, region: str, environment: str
    ) -> List[Dict[str, Any]]:
        """Describe EC2 instances in specified account and region (Async)"""
        try:
            # NOTE: OrgVisitor usage removed for async migration simplification.
            # We are using direct access pattern which is cleaner for single account access.

            logger.info(
                f"Describing instances in account {account_id}, region {region} (Direct Access)"
            )

            # Try direct role assumption
            assumed_creds = await self.assume_role(account_id, region)
            
            if assumed_creds:
                logger.info(
                    f"Successfully assumed role directly in account {account_id}"
                )
                
                # Create session for assumed role
                session = aiobotocore.session.get_session()
                
                async with session.create_client(
                    "ec2",
                    region_name=region,
                    aws_access_key_id=assumed_creds["AccessKeyId"],
                    aws_secret_access_key=assumed_creds["SecretAccessKey"],
                    aws_session_token=assumed_creds["SessionToken"],
                ) as ec2:
                    return await self._fetch_instances(ec2, account_id, region)
            else:
                logger.warning(
                    f"Could not assume role in account {account_id}, falling back to environment credentials"
                )
                # Try to use environment credentials directly
                async with self.credential_manager.create_client("ec2", environment, region) as ec2:
                    if not ec2:
                        logger.error(
                            f"Failed to create EC2 client for {account_id} in {region}"
                        )
                        return []
                    logger.info(
                        f"Using environment credentials for {environment} to access account {account_id}"
                    )
                    return await self._fetch_instances(ec2, account_id, region)

        except Exception as e:
            logger.error(
                f"Error describing instances in account {account_id}, region {region}: {str(e)}"
            )
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []

    async def _fetch_instances(self, ec2_client, account_id, region):
        """Helper to fetch instances from an EC2 client"""
        instances = []
        paginator = ec2_client.get_paginator("describe_instances")
        async for page in paginator.paginate():
            for reservation in page["Reservations"]:
                instances.extend(reservation["Instances"])

        logger.info(
            f"Retrieved {len(instances)} instances from account {account_id} in region {region}"
        )
        return instances
