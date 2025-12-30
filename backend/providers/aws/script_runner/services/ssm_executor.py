import logging
import time
import asyncio
from typing import Any, Dict, List, Optional

import aiobotocore.session
import boto3  # Keep for minimal fallback if needed

from backend.providers.aws.common.services.account_manager import AWSAccountManager
from backend.providers.aws.common.services.credential_manager import CredentialManager

logger = logging.getLogger(__name__)


class SSMExecutor:
    """Service for executing commands via AWS Systems Manager (SSM) (Async)"""

    def __init__(self, credential_manager: Optional[CredentialManager] = None):
        self.credential_manager = credential_manager or CredentialManager()
        self.account_manager = AWSAccountManager(self.credential_manager)
        self._last_error: Optional[str] = (
            None  # Store last error for better error reporting
        )

    async def send_command_to_multiple_instances(
        self,
        instance_ids: List[str],
        command: str,
        account_id: str,
        region: str,
        environment: str,
        comment: str = "",
        timeout_seconds: int = 3600,
        parameters: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[str]:
        """
        Send a command to multiple EC2 instances using SSM (Async).

        Args:
            instance_ids: List of EC2 instance IDs
            command: Command content to execute
            account_id: AWS account ID
            region: AWS region
            environment: AWS environment (gov or com)
            comment: Optional comment for the command
            timeout_seconds: Command timeout in seconds
            parameters: Optional parameters for the command

        Returns:
            Command ID if successful, None otherwise
        """
        # Use the same logic as send_command but with multiple instances
        return await self._send_command_internal(
            instance_ids=instance_ids,
            command=command,
            account_id=account_id,
            region=region,
            environment=environment,
            comment=comment,
            timeout_seconds=timeout_seconds,
            parameters=parameters,
        )

    async def send_command(
        self,
        instance_id: str,
        command: str,
        account_id: str,
        region: str,
        environment: str,
        comment: str = "",
        timeout_seconds: int = 3600,
        parameters: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[str]:
        """
        Send a command to an EC2 instance using SSM (Async).

        Args:
            instance_id: EC2 instance ID
            command: Command content to execute
            account_id: AWS account ID
            region: AWS region
            environment: AWS environment (gov or com)
            comment: Optional comment for the command
            timeout_seconds: Command timeout in seconds
            parameters: Optional parameters for the command

        Returns:
            Command ID if successful, None otherwise
        """
        # Call internal method with single instance in a list
        return await self._send_command_internal(
            instance_ids=[instance_id],
            command=command,
            account_id=account_id,
            region=region,
            environment=environment,
            comment=comment,
            timeout_seconds=timeout_seconds,
            parameters=parameters,
        )

    async def _send_command_internal(
        self,
        instance_ids: List[str],
        command: str,
        account_id: str,
        region: str,
        environment: str,
        comment: str = "",
        timeout_seconds: int = 3600,
        parameters: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[str]:
        """Internal method to send command to one or more instances (Async)."""
        try:
            # Try to assume role in target account for cross-account access
            logger.info(
                f"Attempting to assume role in target account {account_id} for region {region}"
            )

            try:
                assumed_credentials = await self.account_manager.assume_role(
                    account_id, region
                )
            except Exception as assume_error:
                logger.warning(
                    f"Role assumption failed for account {account_id}: {str(assume_error)}"
                )
                assumed_credentials = None

            # Prepare the client context manager
            client_cm = None
            
            if assumed_credentials:
                logger.info(f"Successfully assumed role in account {account_id}")
                # Create SSM client with assumed role credentials
                session = aiobotocore.session.get_session()
                client_cm = session.create_client(
                    "ssm",
                    region_name=region,
                    aws_access_key_id=assumed_credentials["AccessKeyId"],
                    aws_secret_access_key=assumed_credentials["SecretAccessKey"],
                    aws_session_token=assumed_credentials["SessionToken"],
                )
            else:
                logger.info(
                    f"Using environment credentials for account {account_id} in region {region}"
                )
                client_cm = self.credential_manager.create_client("ssm", environment, region)

            if not client_cm:
                logger.error(
                    f"Failed to create SSM client for {environment} in {region}"
                )
                return None

            async with client_cm as ssm:
                # Build command document - use different approach for GovCloud
                if environment == "gov":
                    # GovCloud has different SSM document names or may need custom documents
                    document_name = (
                        "AWS-RunShellScript"
                        if not command.startswith("powershell")
                        else "AWS-RunPowerShellScript"
                    )

                    # Try fallback documents if the primary ones don't exist
                    fallback_docs = (
                        ["SSM-RunCommand", "AWS-RunRemoteScript"]
                        if not command.startswith("powershell")
                        else ["AWS-RunPowerShellScript"]
                    )

                    available_doc = None
                    for doc in [document_name] + fallback_docs:
                        try:
                            await ssm.describe_document(Name=doc)
                            logger.info(f"Found available SSM document: {doc}")
                            available_doc = doc
                            break
                        except Exception as doc_error:
                            logger.debug(
                                f"SSM document {doc} not available: {str(doc_error)}"
                            )
                            continue

                    if not available_doc:
                        logger.error(
                            "No compatible SSM documents found in GovCloud environment"
                        )
                        raise Exception("No compatible SSM documents available in GovCloud")

                    document_name = available_doc
                else:
                    # Commercial AWS - standard document names
                    document_name = (
                        "AWS-RunShellScript"
                        if not command.startswith("powershell")
                        else "AWS-RunPowerShellScript"
                    )

                    # Check if document exists
                    try:
                        await ssm.describe_document(Name=document_name)
                        logger.debug(f"Document {document_name} is available")
                    except Exception as e:
                        logger.error(
                            f"Required SSM document {document_name} is not available in this environment"
                        )
                        raise Exception(f"SSM document {document_name} is not available") from e

                cmd_parameters = parameters or {}

                # If no custom parameters provided, set the default commands parameter
                if "commands" not in cmd_parameters:
                    cmd_parameters["commands"] = [command]

                logger.info(
                    f"Sending command to {len(instance_ids)} instance(s) in account {account_id}, region {region}"
                )
                
                # Send the command
                response = await ssm.send_command(
                    InstanceIds=instance_ids,
                    DocumentName=document_name,
                    Comment=comment,
                    TimeoutSeconds=timeout_seconds,
                    Parameters=cmd_parameters,
                    CloudWatchOutputConfig={"CloudWatchOutputEnabled": True},
                )

                # Extract command ID
                command_id = str(response["Command"]["CommandId"])
                logger.info(f"Successfully sent command. Command ID: {command_id}")
                return command_id

        except Exception as e:
            error_msg = str(e)
            self._last_error = error_msg  # Store for error reporting
            logger.error(
                f"Error sending command to instances {instance_ids}: {error_msg}"
            )

            # Check if the error response contains a command ID (partial success case)
            if hasattr(e, "response") and isinstance(e.response, dict):
                # Sometimes AWS returns an error but still creates the command
                if "Command" in e.response and "CommandId" in e.response["Command"]:
                    command_id = str(e.response["Command"]["CommandId"])
                    logger.warning(
                        f"Command {command_id} was created despite error: {error_msg}"
                    )
                    return command_id

            # Provide specific guidance for common SSM issues
            if "InvalidInstanceId" in error_msg:
                if "not in a valid state" in error_msg:
                    logger.error(
                        f"Instances {instance_ids} are not ready for SSM commands. Please check:"
                    )
                    logger.error(
                        "1. Instance Region - Verify the instance exists in the selected region"
                    )
                    logger.error(f"   - You selected region: {region}")
                    logger.error(
                        "   - GovCloud instances should use us-gov-west-1 or us-gov-east-1"
                    )
                    logger.error(
                        "   - Commercial instances use standard AWS regions (us-east-1, us-west-2, etc.)"
                    )
                    logger.error(
                        "2. Instance State - Instance must be running (not stopped/terminated)"
                    )
                    logger.error(
                        "3. Instance ID - Verify the instance ID is correct (no typos)"
                    )
                    logger.error(
                        "4. SSM Agent - Must be installed and running on the instance"
                    )
                    logger.error(
                        "5. IAM Role - Instance must have an IAM role with SSM permissions"
                    )
                    logger.error(
                        "6. SSM Registration - Instance must be registered with SSM service"
                    )
                    logger.error(
                        f"Check instance status in AWS console for {instance_ids} in region {region}"
                    )

                    logger.info("Command sending failed - unable to recover command ID")

                else:
                    logger.error(
                        f"Instances {instance_ids} not found or not accessible. Please verify:"
                    )
                    logger.error(f"1. Instance IDs are correct: {instance_ids}")
                    logger.error(f"2. Instance exists in region: {region}")
                    logger.error("3. You have permissions to access this instance")
            elif "AccessDenied" in error_msg:
                logger.error(
                    f"Insufficient permissions to send commands to {instance_ids}"
                )
                logger.error("Check IAM policies for SSM SendCommand permissions")
            elif "ThrottlingException" in error_msg:
                logger.error(f"Rate limiting encountered for instances {instance_ids}")
                logger.error("Too many concurrent SSM commands, try again later")

            return None

    async def get_command_status(
        self,
        command_id: str,
        instance_id: str,
        account_id: str,
        region: str,
        environment: str,
    ) -> Dict[str, Any]:
        """
        Get the status of a specific command execution (Async).

        Args:
            command_id: The ID of the command
            instance_id: The ID of the instance
            account_id: The AWS account ID
            region: The AWS region
            environment: The AWS environment

        Returns:
            Dictionary containing status information
        """
        try:
            # Try to assume role in target account
            try:
                assumed_credentials = await self.account_manager.assume_role(
                    account_id, region
                )
            except Exception:
                assumed_credentials = None

            # Prepare client context manager
            client_cm = None
            
            if assumed_credentials:
                session = aiobotocore.session.get_session()
                client_cm = session.create_client(
                    "ssm",
                    region_name=region,
                    aws_access_key_id=assumed_credentials["AccessKeyId"],
                    aws_secret_access_key=assumed_credentials["SecretAccessKey"],
                    aws_session_token=assumed_credentials["SessionToken"],
                )
            else:
                client_cm = self.credential_manager.create_client("ssm", environment, region)

            if not client_cm:
                return {"Status": "Failed", "ResponseCode": -1, "Output": "Failed to create SSM client"}

            async with client_cm as ssm:
                response = await ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )

                return {
                    "Status": response.get("Status", "Unknown"),
                    "ResponseCode": response.get("ResponseCode", -1),
                    "Output": response.get("StandardOutputContent", ""),
                    "Error": response.get("StandardErrorContent", ""),
                    "StatusDetails": response.get("StatusDetails", ""),
                }

        except Exception as e:
            logger.error(f"Error getting command status: {str(e)}")
            return {
                "Status": "Error",
                "ResponseCode": -1,
                "Output": "",
                "Error": str(e),
            }

    async def wait_for_command_completion(
        self,
        command_id: str,
        instance_id: str,
        account_id: str,
        region: str,
        environment: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 2,
    ) -> Dict[str, Any]:
        """
        Wait for a command to complete execution (Async).

        Args:
            command_id: The ID of the command
            instance_id: The ID of the instance
            account_id: The AWS account ID
            region: The AWS region
            environment: The AWS environment
            timeout_seconds: Maximum time to wait
            poll_interval_seconds: Time between status checks

        Returns:
            Final status dictionary
        """
        start_time = time.time()
        terminal_states = ["Success", "Cancelled", "Failed", "TimedOut", "Cancelling"]

        while time.time() - start_time < timeout_seconds:
            status = await self.get_command_status(
                command_id, instance_id, account_id, region, environment
            )

            if status["Status"] in terminal_states:
                logger.info(
                    f"Command {command_id} completed with status: {status['Status']}"
                )
                return status

            logger.debug(
                f"Command {command_id} still running. Status: {status['Status']}"
            )
            await asyncio.sleep(poll_interval_seconds)

        logger.warning(f"Timeout waiting for command {command_id} to complete")
        return {
            "CommandId": command_id,
            "InstanceId": instance_id,
            "Status": "TimedOut",
            "StatusDetails": "Timed out waiting for command completion",
            "Output": "",
            "Error": "Command execution timed out",
            "ExitCode": -1,
        }

    async def execute_script(
        self,
        instance_id: str,
        script_name: str,
        account_id: str,
        region: str,
        environment: str,
        parameters: Optional[Dict[str, List[str]]] = None,
        timeout_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Execute a script on an instance (Async).

        Args:
            instance_id: EC2 instance ID
            script_name: Name of the script to execute
            account_id: AWS account ID
            region: AWS region
            environment: AWS environment
            parameters: Script parameters
            timeout_seconds: Timeout in seconds

        Returns:
            Execution result dictionary
        """
        try:
            # Get script content
            script_content = self._get_script_content(script_name)
            if not script_content:
                return {
                    "Status": "Failed",
                    "Error": f"Script {script_name} not found",
                    "ResponseCode": -1,
                }

            # Send command
            command_id = await self.send_command(
                instance_id=instance_id,
                command=script_content,
                account_id=account_id,
                region=region,
                environment=environment,
                comment=f"Executing script {script_name}",
                timeout_seconds=timeout_seconds,
                parameters=parameters,
            )

            if not command_id:
                return {
                    "Status": "Failed",
                    "Error": "Failed to send command",
                    "ResponseCode": -1,
                }

            # Wait for completion
            return await self.wait_for_command_completion(
                command_id=command_id,
                instance_id=instance_id,
                account_id=account_id,
                region=region,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )

        except Exception as e:
            logger.error(f"Error executing script {script_name}: {str(e)}")
            return {
                "Status": "Error",
                "Error": str(e),
                "ResponseCode": -1,
            }

    async def execute_script_batch(
        self,
        instance_ids: List[str],
        script_name: str,
        account_id: str,
        region: str,
        environment: str,
        parameters: Optional[Dict[str, List[str]]] = None,
        timeout_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Execute a script on multiple instances (Async).

        Args:
            instance_ids: List of EC2 instance IDs
            script_name: Name of the script to execute
            account_id: AWS account ID
            region: AWS region
            environment: AWS environment
            parameters: Script parameters
            timeout_seconds: Timeout in seconds

        Returns:
            Execution result dictionary
        """
        try:
            # Get script content
            script_content = self._get_script_content(script_name)
            if not script_content:
                return {
                    "Status": "Failed",
                    "Error": f"Script {script_name} not found",
                    "ResponseCode": -1,
                }

            # Clean the script content
            clean_script_content = script_content.replace("\r\n", "\n").replace("\r", "")
            
            # Determine document name based on extension (simplified)
            document_name = "AWS-RunShellScript"
            if script_name.endswith(".ps1"):
                document_name = "AWS-RunPowerShellScript"
            
            # Wrap if shell script
            if document_name == "AWS-RunShellScript":
                wrapped_script = f"""#!/bin/bash
set -e  # Exit on error

# Switch to root if not already (SSM runs as ssm-user by default)
if [ "$EUID" -ne 0 ]; then
    sudo -s bash << 'SUDO_EOF'
{clean_script_content}
SUDO_EOF
else
    # Already root, execute directly
{clean_script_content}
fi
"""
                command_to_send = wrapped_script
            else:
                command_to_send = script_content

            # Send command
            command_id = await self.send_command_to_multiple_instances(
                instance_ids=instance_ids,
                command=command_to_send,
                account_id=account_id,
                region=region,
                environment=environment,
                comment=f"Executing script {script_name}",
                timeout_seconds=timeout_seconds,
                parameters=parameters,
            )

            if not command_id:
                return {
                    "Status": "Failed",
                    "Error": "Failed to send command",
                    "ResponseCode": -1,
                }

            # Wait a bit for command to start
            await asyncio.sleep(2)

            # Get initial status for the first instance
            status_result = await self.get_command_status(
                command_id=command_id,
                instance_id=instance_ids[0],
                account_id=account_id,
                region=region,
                environment=environment
            )

            return {
                "command_id": command_id,
                "status": status_result.get("Status", "InProgress"),
                "output": status_result.get("Output", ""),
                "error": status_result.get("Error", ""),
            }

        except Exception as e:
            logger.error(f"Error executing script {script_name}: {str(e)}")
            return {
                "Status": "Error",
                "Error": str(e),
                "ResponseCode": -1,
            }

    async def execute_script(
        self,
        instance_id: str,
        script_content: str,
        interpreter: str,
        account_id: str,
        region: str,
        credentials: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute a script on an instance (simplified interface for web routes) (Async).

        Args:
            instance_id: EC2 instance ID
            script_content: Script content to execute
            interpreter: Script interpreter (bash, python3, powershell)
            account_id: AWS account ID (where the instance lives)
            region: AWS region
            credentials: AWS credentials dict (management account credentials)

        Returns:
            Dictionary with execution result
        """
        try:
            # First, we need to assume a role into the target account
            logger.info(
                f"Assuming role into account {account_id} for instance {instance_id}"
            )

            # Use the account manager to assume role
            # Pass through base credentials (management account) when available to enable
            # proper assume-role chaining into the target account
            base_creds = None
            try:
                # Support both pydantic models and simple objects
                if hasattr(credentials, "access_key") and hasattr(
                    credentials, "secret_key"
                ):
                    # Convert to AWSCredentials if needed
                    import time

                    from backend.providers.aws.common.schemas.account import (
                        AWSCredentials as AMCredentials,
                    )

                    # Determine environment from region
                    environment = "gov" if "gov" in region else "com"

                    base_creds = AMCredentials(
                        access_key=credentials.access_key,
                        secret_key=credentials.secret_key,
                        session_token=getattr(credentials, "session_token", "") or "",
                        expiration=getattr(
                            credentials, "expiration", time.time() + 3600
                        ),
                        environment=environment,
                    )
            except Exception:
                base_creds = None

            assumed_creds = await self.account_manager.assume_role(
                account_id=account_id,
                region_name=region,
                credentials=base_creds,
            )

            if not assumed_creds:
                logger.error(f"Failed to assume role into account {account_id}")
                return {
                    "command_id": None,
                    "status": "failed",
                    "output": "",
                    "error": f"Failed to assume role into account {account_id}. Check that OrganizationAccountAccessRole exists and is accessible.",
                }

            logger.info(f"Successfully assumed role into account {account_id}")

            # Create SSM client with the assumed role credentials
            session = aiobotocore.session.get_session()
            client_kwargs = {
                "service_name": "ssm",
                "region_name": region,
                "aws_access_key_id": assumed_creds["AccessKeyId"],
                "aws_secret_access_key": assumed_creds["SecretAccessKey"],
                "aws_session_token": assumed_creds["SessionToken"],
            }

            # For GOV regions, endpoints are partition-specific but the standard
            # boto3 client with region is sufficient; only set explicit endpoint if provided
            if "gov" in region:
                client_kwargs.setdefault(
                    "endpoint_url", f"https://ssm.{region}.amazonaws.com"
                )

            async with session.create_client(**client_kwargs) as ssm:

                # Determine document name based on interpreter
                known_interpreters = ["bash", "sh", "python", "python3", "powershell"]
                if interpreter == "powershell":
                    document_name = "AWS-RunPowerShellScript"
                else:
                    if interpreter and interpreter not in known_interpreters:
                        logger.warning(
                            f"Unknown interpreter '{interpreter}' requested. Defaulting to shell script."
                        )
                    document_name = "AWS-RunShellScript"

                # Clean the script content - remove Windows line endings that can break shell scripts
                # Convert CRLF (\r\n) to LF (\n) and remove any trailing \r
                clean_script_content = script_content.replace("\r\n", "\n").replace(
                    "\r", ""
                )

                # Log the command being sent
                logger.info(
                    f"Sending SSM command to {instance_id} in {region} (account: {account_id})"
                )
                logger.info(
                    f"Document: {document_name}, Script length: {len(clean_script_content)}"
                )

                # For shell scripts, wrap the content to ensure proper execution context
                if document_name == "AWS-RunShellScript":
                    # Create a proper bash context to preserve variables and formatting
                    # Run as root user to match manual execution context
                    wrapped_script = f"""#!/bin/bash
set -e  # Exit on error

# Switch to root if not already (SSM runs as ssm-user by default)
if [ "$EUID" -ne 0 ]; then
    sudo -s bash << 'SUDO_EOF'
{clean_script_content}
SUDO_EOF
else
    # Already root, execute directly
{clean_script_content}
fi
"""
                    commands_to_send = [wrapped_script]
                else:
                    # For PowerShell, send as-is
                    commands_to_send = [script_content]

                # Send command
                response = await ssm.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=document_name,
                    Parameters={"commands": commands_to_send},
                    TimeoutSeconds=3600,
                )

                command_id = response["Command"]["CommandId"]
                logger.info(f"SSM command sent successfully. Command ID: {command_id}")

                # Wait a bit for command to start
                await asyncio.sleep(2)

                # Get initial status
                status_response = await ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )

                status = status_response.get("Status", "InProgress")
                logger.info(f"Command {command_id} status: {status}")

                return {
                    "command_id": command_id,
                    "status": status,
                    "output": status_response.get("StandardOutputContent", ""),
                    "error": status_response.get("StandardErrorContent", ""),
                }

        except Exception as e:
            logger.error(f"Error executing script on {instance_id}: {str(e)}")
            return {
                "command_id": None,
                "status": "failed",
                "output": "",
                "error": str(e),
            }
