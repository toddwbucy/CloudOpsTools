"""
Organization traversal service for AWS accounts.
Based on proven pattern for role assumption across an organization.
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import (
    Any,
    Callable,
    Dict,
    AsyncIterator,
    List,
    Optional,
    Protocol,
)

import aiobotocore.session
from aiobotocore.session import AioSession
from botocore.config import Config
from botocore.exceptions import ClientError


# Type definition for OrganizationsClient
class OrganizationsClient(Protocol):
    async def describe_organization(self) -> Dict[str, Any]: ...
    async def list_accounts(self, **kwargs) -> Dict[str, Any]: ...
    async def list_accounts_for_parent(self, **kwargs) -> Dict[str, Any]: ...
    def get_paginator(self, operation_name: str) -> Any: ...
    async def describe_account(self, **kwargs) -> Dict[str, Any]: ...


from backend.providers.aws.common.services.credential_manager import CredentialManager

# Constants
AWS_PUBLIC = "aws"
AWS_GOVCLOUD = "aws-us-gov"

logger = logging.getLogger(__name__)


class OrgVisitor:
    """Service for traversing AWS organization and visiting accounts"""

    def __init__(self, credential_manager: CredentialManager):
        """Initialize the OrgVisitor

        Args:
            credential_manager: The credential manager to use for base credentials
        """
        self.credential_manager = credential_manager

    @asynccontextmanager
    async def switch_role(
        self,
        session: AioSession,
        account_id: str,
        role_name: str,
        partition: str,
        role_session_name: str = "API-Visitor-Session",
        region_name: Optional[str] = None,
    ) -> AsyncIterator[Optional[AioSession]]:
        """Switch to a role in another account

        Args:
            session: The aiobotocore session to use for assuming the role
            account_id: The account ID to assume the role in
            role_name: The name of the role to assume
            partition: The AWS partition (aws or aws-us-gov)
            role_session_name: The session name to use
            region_name: Optional region name override

        Yields:
            An assumed role session or None if assumption failed
        """
        try:
            arn_template = "arn:%s:iam::%s:role/%s"
            role_arn = arn_template % (partition, account_id, role_name)

            logger.debug(f"Assuming role: {role_arn}")
            
            # Use a temporary client to assume role
            # We need to get credentials from the session to create the client
            # But aiobotocore session.create_client handles this automatically if we pass the session
            
            # Note: session.create_client is an async context manager
            async with session.create_client("sts") as sts:
                resp = await sts.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)

            # Create a new session with the assumed credentials
            assumed_session = aiobotocore.session.get_session()
            
            # We need to manually set credentials on the new session or pass them when creating clients
            # A better approach with aiobotocore is to return the credentials dict or a helper
            # But to keep the API similar, we'll configure the session with credentials
            
            # Actually, aiobotocore sessions don't hold credentials directly like boto3 sessions in the same way
            # Instead, we can use set_credentials method if available, or just return a session that
            # has a credential provider configured.
            
            # Simpler approach: Return a session that is pre-configured with these credentials
            # However, aiobotocore doesn't make this easy.
            
            # Alternative: Return a helper object or just the credentials
            # But the caller expects a session.
            
            # Let's use the set_credentials method on the session's component
            assumed_session.set_credentials(
                access_key=resp["Credentials"]["AccessKeyId"],
                secret_key=resp["Credentials"]["SecretAccessKey"],
                token=resp["Credentials"]["SessionToken"],
            )
            
            # Set region
            if region_name:
                assumed_session.set_default_client_config(region_name=region_name)
            
            yield assumed_session
            
        except ClientError as err:
            logger.error(f"Error assuming role in account {account_id}: {str(err)}")
            yield None

    @asynccontextmanager
    async def get_organization_client(
        self, session: AioSession
    ) -> AsyncIterator[OrganizationsClient]:
        """Get a client for AWS Organizations

        Args:
            session: The aiobotocore session to use

        Yields:
            An AWS Organizations client
        """
        client = None
        try:
            logger.debug("Getting handle on client for AWS Organizations")
            async with session.create_client("organizations") as client:
                yield client
        except Exception as e:
            logger.error(f"Error getting organization client: {e}")
            raise

    async def get_accounts(
        self, org_client: OrganizationsClient, parent_id: Optional[str] = None
    ) -> List[str]:
        """Get a list of account IDs in the organization

        Args:
            org_client: The AWS Organizations client
            parent_id: Optional parent ID to list accounts for

        Returns:
            A list of account IDs
        """
        if parent_id is not None:
            paginator = org_client.get_paginator("list_accounts_for_parent")
            iterator = paginator.paginate(ParentId=parent_id)
        else:
            paginator = org_client.get_paginator("list_accounts")
            iterator = paginator.paginate()

        account_ids = []
        async for page in iterator:
            account_ids.extend([a["Id"] for a in page["Accounts"]])

        logger.debug(f"Found accounts: {account_ids}")
        return account_ids

    async def get_us_regions(self, session: AioSession, include_gov: bool = False) -> List[str]:
        """Get a list of US regions

        Args:
            session: The aiobotocore session to use
            include_gov: Whether to include GovCloud regions

        Returns:
            A list of region names
        """
        logger.debug("Getting US regions")
        async with session.create_client("ec2") as ec2_client:
            resp = await ec2_client.describe_regions()

        if include_gov:
            return [
                r["RegionName"]
                for r in resp["Regions"]
                if r["RegionName"].startswith("us-")
            ]
        else:
            return [
                r["RegionName"]
                for r in resp["Regions"]
                if r["RegionName"].startswith("us-") and "gov" not in r["RegionName"]
            ]

    async def walk_organization(
        self,
        session: AioSession,
        org_client: OrganizationsClient,
        role_name: str,
        account_visitor: Callable,
        region_visitor: Callable,
        partition: str,
        parent_id: Optional[str],
    ) -> Dict[str, Any]:
        """Walk the organization and visit accounts

        Args:
            session: The aiobotocore session to use
            org_client: The AWS Organizations client
            role_name: The name of the role to assume
            account_visitor: A callable to visit each account (must be async)
            region_visitor: A callable to visit each region in each account (must be async)
            partition: The AWS partition (aws or aws-us-gov)
            parent_id: Optional parent ID to start from

        Returns:
            A dictionary with visit results
        """
        logger.debug("Walking organization")
        include_gov = partition == AWS_GOVCLOUD
        regions = await self.get_us_regions(session, include_gov)
        results: Dict[str, Dict[str, Any]] = {"accounts": {}}

        account_ids = await self.get_accounts(org_client, parent_id)

        for account in account_ids:
            results["accounts"][account] = {"regions": {}}

            async with self.switch_role(
                session, account, role_name, partition
            ) as assumed_session:
                if assumed_session is None:
                    logger.warning(f"Failed to switch role for account {account}")
                    results["accounts"][account]["status"] = "error"
                    results["accounts"][account]["error"] = "Failed to assume role"
                    continue

                logger.info(f"Visiting account {account}")
                try:
                    # account_visitor must be async
                    account_result = await account_visitor(assumed_session, account)
                    results["accounts"][account]["result"] = account_result
                    results["accounts"][account]["status"] = "success"
                except Exception as e:
                    logger.error(f"Error in account visitor for {account}: {str(e)}")
                    results["accounts"][account]["status"] = "error"
                    results["accounts"][account]["error"] = str(e)

                for region in regions:
                    results["accounts"][account]["regions"][region] = {}
                    try:
                        logger.info(f"Visiting region {region} for account {account}")
                        # region_visitor must be async
                        region_result = await region_visitor(assumed_session, region, account)
                        results["accounts"][account]["regions"][region][
                            "result"
                        ] = region_result
                        results["accounts"][account]["regions"][region][
                            "status"
                        ] = "success"
                    except Exception as e:
                        logger.error(
                            f"Error in region visitor for {account}/{region}: {str(e)}"
                        )
                        results["accounts"][account]["regions"][region][
                            "status"
                        ] = "error"
                        results["accounts"][account]["regions"][region]["error"] = str(
                            e
                        )

        return results

    async def visit_organization(
        self,
        environment: str,
        account_visitor: Callable,
        region_visitor: Callable,
        role_name: str = "OrganizationAccountAccessRole",
        parent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Visit each account and region in an organization

        Args:
            environment: The AWS environment (gov or com)
            account_visitor: A callable to visit each account (must be async)
            region_visitor: A callable to visit each region in each account (must be async)
            role_name: The name of the role to assume
            parent_id: Optional parent ID to start from

        Returns:
            A dictionary with visit results
        """
        logger.info("Starting organization visit")
        start_time = time.time()
        results = {"status": "error", "time_elapsed": 0}

        try:
            # Get environment-specific values
            partition_name = (
                AWS_GOVCLOUD if environment.lower() == "gov" else AWS_PUBLIC
            )

            # Create a session from existing credentials
            # We need an async session here
            # CredentialManager returns a boto3.Session (sync) or we can create an aiobotocore session
            # and configure it with credentials from CredentialManager
            
            # Get credentials from manager
            # Note: This assumes we have valid credentials stored
            creds = self.credential_manager._get_credentials(environment)
            if not creds:
                 logger.error(f"No credentials found for {environment}")
                 results["error"] = f"No credentials found for {environment}"
                 return results
                 
            session = aiobotocore.session.get_session()
            session.set_credentials(
                access_key=creds.access_key,
                secret_key=creds.secret_key,
                token=creds.session_token
            )
            
            # Visit the organization
            async with self.get_organization_client(session) as org_client:
                visit_results = await self.walk_organization(
                    session,
                    org_client,
                    role_name,
                    account_visitor,
                    region_visitor,
                    partition_name,
                    parent_id,
                )

                results.update(visit_results)
                results["status"] = "success"

        except Exception as e:
            logger.error(f"Error visiting organization: {str(e)}")
            results["error"] = str(e)

        # Update elapsed time
        elapsed_time = time.time() - start_time
        results["time_elapsed"] = elapsed_time
        logger.info(f"Organization visit completed in {elapsed_time:.2f} seconds")

        return results
