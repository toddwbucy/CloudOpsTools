"""AWS Linux QC Patching Prep Tool - Web Interface"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import Integer, desc, func
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.templates import templates
from backend.core.utils.encryption import decrypt_session_credentials
from backend.db.models.change import Change, ChangeInstance
from backend.db.models.execution import Execution
from backend.db.models.script import Script
from backend.db.session import get_db
from backend.core.config import AWSEnvironment

# Import the shared script executor service
from backend.providers.aws.common.services.script_executor import (
    submit_execution,
)

# Import the shared credential manager from auth module
from backend.web.aws.auth import credential_manager

logger = logging.getLogger(__name__)

# Thread pool management is now handled by the shared script_executor service

# Compiled regex for ANSI escape code removal (performance optimization)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

router = APIRouter()


# Helper functions for session management
def get_current_change(request: Request) -> Optional[Dict]:
    """Get the current change from session"""
    current_change = request.session.get("current_change")
    session_keys = list(request.session.keys())
    logger.info(f"get_current_change: Retrieved change {current_change.get('change_number') if current_change else 'None'}")
    logger.info(f"get_current_change: Session keys: {session_keys}")
    return current_change


def set_current_change(request: Request, change_data: Dict) -> None:
    """Set the current change in session"""
    import json
    
    # Clear any potentially conflicting session data
    logger.info(f"set_current_change: BEFORE - Session keys: {list(request.session.keys())}")
    
    try:
        # Validate that the data is JSON serializable BEFORE storing in session
        json_test = json.dumps(change_data)
        data_size = len(json_test)
        logger.info(f"set_current_change: Change data is JSON serializable, size: {data_size} bytes")
        
        # If data is too large, log a warning
        if data_size > 50000:  # 50KB warning threshold
            logger.warning(f"set_current_change: Large session data detected: {data_size} bytes")
            
    except (TypeError, ValueError) as e:
        logger.error(f"set_current_change: Change data is NOT JSON serializable: {e}")
        logger.error(f"set_current_change: Problematic data: {change_data}")
        raise ValueError(f"Change data contains non-serializable objects: {e}")
    
    # Store in session
    request.session["current_change"] = change_data
    
    # In Starlette/FastAPI, session changes are automatically detected
    # No need to manually set modified flag
    
    logger.info(f"set_current_change: Set change {change_data.get('change_number')} to session")
    logger.info(f"set_current_change: AFTER - Session keys: {list(request.session.keys())}")
    
    # Verify the data was actually stored and is still serializable
    try:
        verification = request.session.get("current_change")
        if verification:
            # Test that we can still serialize the retrieved data
            json.dumps(verification)
            logger.info(f"set_current_change: VERIFIED - Change {verification.get('change_number')} stored and retrievable")
        else:
            logger.error("set_current_change: FAILED - Change not found in session after setting!")
    except (TypeError, ValueError) as e:
        logger.error(f"set_current_change: CORRUPTION DETECTED - Retrieved data is not serializable: {e}")
        # Clear the corrupted data
        request.session.pop("current_change", None)
        raise ValueError(f"Session corruption detected after storage: {e}")


# Pre-defined scripts for the three-step QC process
QC_SCRIPTS = {
    "step1_initial_qc": {
        "name": "Step 1: Initial QC and Report Generation",
        "description": "Downloads latest patcher and runs initial QC with report generation",
        "content": """CHANGE_NUMBER="{change_number}"
# Remove the old LinuxPatcher directory if it exists
rm -rf /root/LinuxPatcher
# Download the latest version of the patcher
wget -O /root/LinuxPatcher.sh https://pcm-ops-tools.s3.us-gov-west-1.amazonaws.com/linux_patcher/Linux_Patcher_v258-b.sh
# Run the patcher with the change number, silent mode, and QC enabled
bash /root/LinuxPatcher.sh -c $CHANGE_NUMBER -q -s
# Display the QC report
cat /root/$CHANGE_NUMBER/qc_report.txt""",
        "interpreter": "bash",
    },
    "step2_kernel_staging": {
        "name": "Step 2: Stage Kernel Version",
        "description": "Sets the specific kernel version for selected instances",
        "content": """CHANGE_NUMBER="{change_number}"
KERNEL_VERSION="{kernel_version}"
# Run the patcher with the specific kernel version
bash /root/LinuxPatcher.sh -c $CHANGE_NUMBER -k $KERNEL_VERSION -q""",
        "interpreter": "bash",
    },
    "step3_final_report": {
        "name": "Step 3: Final QC Report",
        "description": "Retrieves the final QC report and patch script",
        "content": """CHANGE_NUMBER="{change_number}"
echo "=== QC Report ==="
cat /root/$CHANGE_NUMBER/qc_report.txt
echo ""
echo "=== Patch Script ==="
cat /root/$CHANGE_NUMBER/patchme.sh""",
        "interpreter": "bash",
    },
}


@router.get("/", response_class=HTMLResponse)
async def linux_qc_patching_prep_page(request: Request, db: Session = Depends(get_db)):
    """Linux QC Patching Prep Tool main page"""
    # Get current change if loaded
    current_change = get_current_change(request)

    # If no current change in session, try to restore the most recent change with Step 1 results
    # But only if the change wasn't manually cleared by the user
    if not current_change and not request.session.get("change_manually_cleared", False):
        # Look for the most recent change that has Step 1 execution results

        recent_step1_execution = (
            db.query(Execution)
            .filter(
                func.json_extract(Execution.execution_metadata, '$.qc_step') == "step1_initial_qc",
                Execution.status == "completed"
            )
            .order_by(desc(Execution.end_time))
            .first()
        )

        if recent_step1_execution:
            # Get the change_id from execution metadata
            change_id = recent_step1_execution.execution_metadata.get("change_id")
            if change_id:
                # Load this change into session
                change = db.query(Change).filter(Change.id == change_id).first()
                if change:
                    # Build instances list just like in load_change endpoint
                    instances = []
                    for ci in change.instances:
                        instances.append({
                            "instance_id": ci.instance_id,
                            "name": ci.instance_metadata.get("name", "") if ci.instance_metadata else "",
                            "account_id": ci.account_id,
                            "region": ci.region,
                            "platform": ci.platform,
                            "environment": "gov" if "gov" in ci.region else "com",
                        })

                    # Store in session
                    change_data = {
                        "id": change.id,
                        "change_number": change.change_number,
                        "instances": instances,
                        "selected_instances": [inst["instance_id"] for inst in instances],
                    }
                    set_current_change(request, change_data)
                    current_change = change_data
                    logger.info(f"Auto-restored change {change.change_number} with Step 1 results to session")

    # Get list of available changes
    changes = db.query(Change).order_by(Change.created_at.desc()).limit(10).all()

    # Check credential status from session
    com_credentials = request.session.get("aws_com_credentials", False)
    gov_credentials = request.session.get("aws_gov_credentials", False)

    return templates.TemplateResponse(
        "aws/linux_qc_patching_prep.html",
        {
            "request": request,
            "current_change": current_change,
            "changes": changes,
            "qc_scripts": QC_SCRIPTS,
            "settings": settings,
            "com_credentials": com_credentials,
            "gov_credentials": gov_credentials,
        },
    )


def _restore_credentials_from_session(request: Request, env: str, aws_env) -> Optional[Any]:
    """Restore credentials from session storage if available.
    
    Args:
        request: FastAPI request object
        env: Environment string ('com' or 'gov')
        aws_env: AWS environment enum
        
    Returns:
        Restored credentials or None if not found
    """
    logger.warning(
        f"No credentials found in credential_manager for {env} environment"
    )

    session_creds_key = f"aws_{env}_credential_data"
    encrypted_creds = request.session.get(session_creds_key)
    session_creds = None
    if encrypted_creds:
        session_creds = decrypt_session_credentials(encrypted_creds)

    # Also check the boolean flag
    session_flag_key = f"aws_{env}_credentials"
    has_flag = request.session.get(session_flag_key, False)
    logger.info(
        f"Session check for {env}: flag={has_flag}, has_data={bool(session_creds)}"
    )

    if session_creds:
        logger.info(
            f"Found {env} credentials in session, restoring to credential manager"
        )
        # Restore credentials from session to credential manager
        from backend.core.config import AWSCredentials

        restored_creds = AWSCredentials(
            access_key=session_creds["access_key"],
            secret_key=session_creds["secret_key"],
            session_token=session_creds.get("session_token"),
            environment=aws_env,
        )
        credential_manager.store_credentials(restored_creds)
        return credential_manager.get_credentials(aws_env.value)

    return None


def _prepare_credentials_for_assume_role(credentials, env: str):
    """Convert credentials to the format expected by account manager.
    
    Args:
        credentials: Raw credentials from credential manager
        env: Environment string ('com' or 'gov')
        
    Returns:
        AMCredentials object for account manager
    """
    import time

    from backend.providers.aws.common.schemas.account import (
        AWSCredentials as AMCredentials,
    )

    if hasattr(credentials, "access_key"):
        # It's a CredentialSchema object
        return AMCredentials(
            access_key=credentials.access_key,
            secret_key=credentials.secret_key,
            session_token=credentials.session_token or "",
            expiration=getattr(credentials, "expiration", time.time() + 3600),
            environment=env,
        )
    else:
        # It's already a dict, convert to AMCredentials
        return AMCredentials(
            access_key=credentials["access_key"],
            secret_key=credentials["secret_key"],
            session_token=credentials.get("session_token", ""),
            expiration=credentials.get("expiration", time.time() + 3600),
            environment=env,
        )


async def _assume_role_for_account(account_id: str, region: str, credentials, env: str):
    """Handle role assumption for target account.
    
    Args:
        account_id: AWS account ID
        region: AWS region
        credentials: AWS credentials
        env: Environment string ('com' or 'gov')
        
    Returns:
        tuple: (ssm_client, success_bool)
    """
    import aiobotocore.session

    from backend.providers.aws.common.services.account_manager import (
        AWSAccountManager,
    )

    account_manager = AWSAccountManager(credential_manager)
    am_creds = _prepare_credentials_for_assume_role(credentials, env)

    # Assume role into the target account
    logger.info(
        f"Attempting to assume role into account {account_id} for SSM connectivity check"
    )
    assumed_creds = await account_manager.assume_role(
        account_id=account_id, region_name=region, credentials=am_creds
    )

    if not assumed_creds:
        logger.warning(
            f"Failed to assume role into account {account_id}, using direct credentials"
        )
        # Fallback to direct credentials (for same-account access)
        session = aiobotocore.session.get_session()
        if hasattr(credentials, "access_key"):
            ssm_client = await session.create_client(
                "ssm",
                region_name=region,
                aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key,
                aws_session_token=credentials.session_token,
            ).__aenter__()
        else:
            ssm_client = await session.create_client(
                "ssm",
                region_name=region,
                aws_access_key_id=credentials["access_key"],
                aws_secret_access_key=credentials["secret_key"],
                aws_session_token=credentials.get("session_token"),
            ).__aenter__()
        return ssm_client, False
    else:
        logger.info(
            f"Successfully assumed role into account {account_id}"
        )
        # Create SSM client with assumed role credentials
        session = aiobotocore.session.get_session()
        ssm_client = await session.create_client(
            "ssm",
            region_name=region,
            aws_access_key_id=assumed_creds["AccessKeyId"],
            aws_secret_access_key=assumed_creds["SecretAccessKey"],
            aws_session_token=assumed_creds["SessionToken"],
        ).__aenter__()
        return ssm_client, True


async def _check_ssm_connectivity(ssm_client, region_instances, account_id: str, region: str):
    """Check SSM connectivity for instances using describe_instance_information.
    
    Args:
        ssm_client: aiobotocore SSM client
        region_instances: List of instances to check
        account_id: AWS account ID (for logging)
        region: AWS region (for logging)
        
    Returns:
        List of connectivity results
    """
    instance_ids_to_check = [
        inst["instance_id"] for inst in region_instances
    ]

    # Get all SSM-managed instances in this region
    logger.info(
        f"Checking SSM status for {len(instance_ids_to_check)} instances in account {account_id}, region {region}"
    )
    response = await ssm_client.describe_instance_information(MaxResults=50)

    # Handle pagination if needed
    all_ssm_instances = response.get("InstanceInformationList", [])
    while "NextToken" in response:
        response = await ssm_client.describe_instance_information(
            MaxResults=50, NextToken=response["NextToken"]
        )
        all_ssm_instances.extend(
            response.get("InstanceInformationList", [])
        )

    logger.info(
        f"Found {len(all_ssm_instances)} total SSM-managed instances in account {account_id}, region {region}"
    )

    # Filter to just our instances and get their status
    online_instances = {}
    for info in all_ssm_instances:
        if info["InstanceId"] in instance_ids_to_check:
            online_instances[info["InstanceId"]] = (
                info["PingStatus"] == "Online"
            )
            logger.debug(
                f"Instance {info['InstanceId']}: PingStatus={info['PingStatus']}"
            )

    logger.info(
        f"Matched {len(online_instances)} of our instances in SSM"
    )

    # Record results
    results = []
    for instance in region_instances:
        instance_id = instance["instance_id"]
        if instance_id in online_instances:
            results.append(
                {
                    "instance_id": instance_id,
                    "accessible": online_instances[instance_id],
                    "error": (
                        None
                        if online_instances[instance_id]
                        else "Instance offline"
                    ),
                }
            )
        else:
            results.append(
                {
                    "instance_id": instance_id,
                    "accessible": False,
                    "error": "Not registered with SSM",
                }
            )

    return results


def _handle_ssm_errors(error, region_instances):
    """Handle SSM ClientError exceptions and generate appropriate error results.
    
    Args:
        error: ClientError exception
        region_instances: List of instances that failed
        
    Returns:
        List of error results
    """
    from botocore.exceptions import ClientError

    if isinstance(error, ClientError):
        error_code = error.response["Error"]["Code"]
        error_msg = error.response["Error"]["Message"]

        # Handle specific errors
        if error_code == "InvalidInstanceId.NotFound":
            return [
                {
                    "instance_id": instance["instance_id"],
                    "accessible": False,
                    "error": "Instance not found",
                }
                for instance in region_instances
            ]
        else:
            return [
                {
                    "instance_id": instance["instance_id"],
                    "accessible": False,
                    "error": f"AWS Error: {error_msg}",
                }
                for instance in region_instances
            ]
    else:
        # General error
        return [
            {
                "instance_id": instance["instance_id"],
                "accessible": False,
                "error": str(error),
            }
            for instance in region_instances
        ]


@router.post("/test-connectivity")
async def test_connectivity(request: Request, db: Session = Depends(get_db)):
    """Test connectivity to instances using SSM"""
    from botocore.exceptions import ClientError

    try:
        data = await request.json()
        instance_ids = data.get("instance_ids", [])

        if not instance_ids:
            raise HTTPException(status_code=400, detail="No instances provided")

        # Get current change for instance details
        current_change = get_current_change(request)
        if not current_change:
            raise HTTPException(status_code=400, detail="No change loaded")

        results = []

        # Group instances by environment (GOV/COM)
        instances_by_env = {}
        for instance in current_change.get("instances", []):
            if instance["instance_id"] in instance_ids:
                env = instance.get("environment", "com")
                if env not in instances_by_env:
                    instances_by_env[env] = []
                instances_by_env[env].append(instance)

        # Test connectivity for each environment
        for env, env_instances in instances_by_env.items():
            # Get credentials for this environment
            aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
            logger.info(
                f"Checking credentials for {env} environment (key: {aws_env.value})"
            )

            # First try to get from credential manager
            credentials = credential_manager.get_credentials(aws_env.value)

            # If not in credential manager, check if we have them in session (after server restart)
            if not credentials:
                credentials = _restore_credentials_from_session(request, env, aws_env)

                if not credentials:
                    # No credentials for this environment
                    for instance in env_instances:
                        results.append(
                            {
                                "instance_id": instance["instance_id"],
                                "accessible": False,
                                "error": f"No {env.upper()} credentials configured",
                            }
                        )
                    continue

            # Group by account and region for batch efficiency
            by_account_region = {}
            for instance in env_instances:
                account_id = instance.get("account_id", "")
                region = instance["region"]
                key = f"{account_id}:{region}"
                if key not in by_account_region:
                    by_account_region[key] = []
                by_account_region[key].append(instance)

            # Test each account/region combination (batch check for efficiency)
            for account_region_key, region_instances in by_account_region.items():
                account_id, region = account_region_key.split(":")

                try:
                    # Assume role and create SSM client
                    ssm_client, role_assumed = await _assume_role_for_account(
                        account_id, region, credentials, env
                    )

                    # Check SSM connectivity
                    connectivity_results = await _check_ssm_connectivity(
                        ssm_client, region_instances, account_id, region
                    )
                    results.extend(connectivity_results)

                except ClientError as e:
                    error_results = _handle_ssm_errors(e, region_instances)
                    results.extend(error_results)

                except Exception as e:
                    # General error for this account/region
                    logger.error(
                        f"Error checking SSM for account {account_id}, region {region}: {str(e)}"
                    )
                    error_results = _handle_ssm_errors(e, region_instances)
                    results.extend(error_results)

        return JSONResponse({"status": "success", "results": results})

    except Exception as e:
        logger.error(f"Error testing connectivity: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/execute-qc-step")
async def execute_qc_step(request: Request, db: Session = Depends(get_db)):
    """Execute a specific QC step on all instances in the current change"""

    try:
        data = await request.json()
        step = data.get(
            "step"
        )  # step1_initial_qc, step2_kernel_staging, step3_final_report
        kernel_version = data.get("kernel_version", "")  # For step 2

        # Get current change
        current_change = get_current_change(request)
        if not current_change:
            raise HTTPException(status_code=400, detail="No change loaded")

        change_number = current_change.get(
            "change_number", ""
        )  # Changed from "number" to "change_number"
        change_id = current_change.get("id")

        if not step or step not in QC_SCRIPTS:
            raise HTTPException(status_code=400, detail="Invalid QC step")

        # Use all instances from the current change
        instance_ids = current_change.get("selected_instances", [])
        if not instance_ids:
            raise HTTPException(
                status_code=400, detail="No instances in current change"
            )

        # Get the script template for this step
        script_template = QC_SCRIPTS[step]

        # Build the actual script content with variables filled in
        script_content = script_template["content"].format(
            change_number=change_number, kernel_version=kernel_version
        )

        # Get instances from database
        change_obj = db.query(Change).filter(Change.id == change_id).first()
        if not change_obj:
            raise HTTPException(status_code=404, detail="Change not found")

        # Build instance details
        all_instances = []
        for ci in change_obj.instances:
            if ci.instance_id in instance_ids:
                all_instances.append(
                    {
                        "instance_id": ci.instance_id,
                        "account_id": ci.account_id,
                        "region": ci.region,
                        "platform": ci.platform,
                        "environment": "gov" if "gov" in ci.region else "com",
                        "name": (
                            ci.instance_metadata.get("name", "")
                            if ci.instance_metadata
                            else ""
                        ),
                    }
                )

        if not all_instances:
            raise HTTPException(status_code=400, detail="No valid instances found")

        # Group instances by environment
        instances_by_env = {}
        for instance in all_instances:
            env = instance.get("environment", "com")
            if env not in instances_by_env:
                instances_by_env[env] = []
            instances_by_env[env].append(instance)

        # Validate credentials
        missing_creds = []
        for env in instances_by_env.keys():
            aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
            credentials = credential_manager.get_credentials(aws_env.value)

            # If not in credential manager, check if we have them in session (after server restart)
            if not credentials:

                session_creds_key = f"aws_{env}_credential_data"
                encrypted_creds = request.session.get(session_creds_key)
                session_creds = None
                if encrypted_creds:
                    session_creds = decrypt_session_credentials(encrypted_creds)

                if session_creds:
                    logger.info(
                        f"Restoring {env} credentials from session to credential manager"
                    )
                    from backend.core.config import AWSCredentials

                    restored_creds = AWSCredentials(
                        access_key=session_creds["access_key"],
                        secret_key=session_creds["secret_key"],
                        session_token=session_creds.get("session_token"),
                        environment=aws_env,
                    )
                    credential_manager.store_credentials(restored_creds)
                    credentials = credential_manager.get_credentials(aws_env.value)

            if not credentials:
                missing_creds.append(env.upper())

        if missing_creds:
            raise HTTPException(
                status_code=400,
                detail=f"Missing credentials for {', '.join(missing_creds)} environment(s)",
            )

        # Create or get script in database
        script_name = f"Linux QC - {script_template['name']}"
        db_script = (
            db.query(Script)
            .filter(Script.name == script_name, Script.content == script_content)
            .first()
        )

        if not db_script:
            db_script = Script(
                name=script_name,
                content=script_content,
                script_type="bash",
                interpreter="bash",
                description=script_template["description"],
                change_id=change_id,  # Add the change_id
                tool_id=None,  # Explicitly set tool_id to None
            )
            db.add(db_script)
            db.flush()

        # Create execution records
        batch_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        executions = []

        for env, env_instances in instances_by_env.items():
            for instance in env_instances:
                execution = Execution(
                    script_id=db_script.id,
                    instance_id=instance["instance_id"],
                    account_id=instance["account_id"],
                    region=instance["region"],
                    status="pending",
                    batch_id=batch_id,
                    change_number=change_number,
                    execution_metadata={
                        "script_name": script_name,
                        "qc_step": step,
                        "kernel_version": (
                            kernel_version if step == "step2_kernel_staging" else None
                        ),
                        "environment": env,
                        "instance_name": instance.get("name", ""),
                        "change_id": change_id,
                    },
                )
                db.add(execution)
                executions.append(execution)

        db.commit()

        # Start execution in background
        execution_ids = [e.id for e in executions]
        script_dict = {
            "id": db_script.id,
            "name": db_script.name,
            "content": db_script.content,
            "interpreter": "bash",
        }

        logger.info(f"Starting Linux QC step {step} for batch {batch_id}")
        # Submit to shared executor service
        future = submit_execution(
            batch_id,
            script_dict,
            execution_ids,
            instances_by_env,
            credential_manager,
        )
        logger.info(f"Submitted batch {batch_id} to executor service")

        # Store batch info in session
        jobs = request.session.get("background_jobs", [])
        jobs.append(
            {
                "id": batch_id,
                "name": script_name,
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "total": len(executions),
                "completed": 0,
                "qc_step": step,
            }
        )
        request.session["background_jobs"] = jobs

        return JSONResponse(
            {
                "status": "success",
                "batch_id": batch_id,
                "execution_count": len(executions),
                "step": step,
            }
        )

    except Exception as e:
        logger.error(f"Error executing QC step: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


def parse_qc_output(output: str) -> dict:
    """Parse QC report output to extract system information"""

    info = {
        "hostname": "",
        "current_kernel": "",
        "crowdstrike_running": False,
        "crowdstrike_version": "",
        "available_kernels": [],
        "distro": "",
        "test_passed": False,
        "disk_space_passed": False,
        "uptime": "",
        "qc_passed": False,  # Both tests must pass
    }

    # Remove all ANSI escape codes from the output
    clean_output = ANSI_ESCAPE_PATTERN.sub("", output)

    lines = clean_output.split("\n")
    for i, line in enumerate(lines):
        line = line.strip()

        # Extract hostname from header
        if "===== QC report for" in line:
            hostname_match = line.split("QC report for")[1].split("=====")[0].strip()
            info["hostname"] = hostname_match

        # Extract current kernel
        elif "(Current running kernel version):" in line:
            kernel = line.split(":", 1)[1].strip() if ":" in line else ""
            info["current_kernel"] = kernel
            # Detect distro from kernel version with more precise patterns
            if ".el9" in kernel:
                info["distro"] = "RHEL9"
            elif ".el8_10" in kernel:
                info["distro"] = "RHEL8.10"
            elif ".el8_9" in kernel:
                info["distro"] = "RHEL8.9"
            elif ".el8_8" in kernel:
                info["distro"] = "RHEL8.8"
            elif ".el8" in kernel:
                info["distro"] = "RHEL8"
            elif ".el7" in kernel:
                info["distro"] = "RHEL7"
            elif ".amzn2023" in kernel:
                info["distro"] = "Amazon Linux 2023"
            elif ".amzn2" in kernel:
                info["distro"] = "Amazon Linux 2"
            elif ".ubuntu" in kernel:
                info["distro"] = "Ubuntu"
            elif "generic" in kernel and "ubuntu" in kernel.lower():
                info["distro"] = "Ubuntu"

        # Extract CrowdStrike info
        elif "(Is Crowdstrike running):" in line:
            info["crowdstrike_running"] = "Yes" in line or "yes" in line.lower()
        elif "(Current Crowdstrike Version):" in line:
            # Parse: (Current Crowdstrike Version): version = 7.23.17607.0
            if "version" in line and "=" in line:
                version_part = line.split("=", 1)[1].strip() if "=" in line else ""
                info["crowdstrike_version"] = version_part
            elif ":" in line:
                info["crowdstrike_version"] = line.split(":", 1)[1].strip()

        # Extract available kernels
        elif "(Available Kernel Updates):" in line:
            # Read the next lines for kernel updates
            j = i + 1
            while j < len(lines):
                kernel_line = lines[j].strip()
                # Stop if we hit another section marker or empty line after kernels
                if kernel_line.startswith("(") or (
                    not kernel_line and info["available_kernels"]
                ):
                    break
                if kernel_line.startswith("kernel"):
                    # Parse: kernel.x86_64 4.18.0-553.45.1.el8_10 rhel-8-baseos-rhui-rpms
                    parts = kernel_line.split()
                    if len(parts) >= 2:
                        info["available_kernels"].append(parts[1])
                j += 1

        # Extract test results
        elif "(Test Repositories Result):" in line:
            info["test_passed"] = "PASSED" in line.upper()
        elif "(Disk Space Check Result):" in line:
            info["disk_space_passed"] = "PASSED" in line.upper()
        elif "(Server running since):" in line:
            info["uptime"] = line.split(":", 1)[1].strip() if ":" in line else ""

    # Set overall QC passed flag - all three checks must pass:
    # 1. Repository test must pass
    # 2. Disk space check must pass
    # 3. CrowdStrike must be running
    info["qc_passed"] = (
        info["test_passed"]
        and info["disk_space_passed"]
        and info["crowdstrike_running"]
    )

    return info


@router.get("/latest-step1-results")
async def get_latest_step1_results(request: Request, db: Session = Depends(get_db)):
    """Get the latest Step 1 results for the current change"""
    current_change = request.session.get("current_change")
    if not current_change:
        # Add no-cache headers to prevent stale responses
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        return JSONResponse({"status": "no_change", "kernel_groups": {}}, headers=headers)

    change_number = current_change.get("change_number")
    change_id = current_change.get("id")

    # Query for the most recent Step 1 execution for this change
    # The metadata has 'qc_step' and 'change_id' fields
    latest_execution = (
        db.query(Execution)
        .filter(
            func.json_extract(Execution.execution_metadata, '$.qc_step')
            == "step1_initial_qc",
            func.cast(func.json_extract(Execution.execution_metadata, '$.change_id'), Integer)
            == change_id,
            Execution.status == "completed",
        )
        .order_by(desc(Execution.end_time))
        .first()
    )

    if not latest_execution or not latest_execution.batch_id:
        return JSONResponse({"status": "no_results", "kernel_groups": {}})

    # Get all executions from this batch
    batch_executions = (
        db.query(Execution)
        .filter(Execution.batch_id == latest_execution.batch_id)
        .all()
    )

    # Process results to extract kernel groups
    kernel_groups = {}
    for execution in batch_executions:
        if execution.status == "completed" and execution.output:
            # Parse the output to extract kernel info
            parsed_info = parse_qc_output(execution.output)
            if parsed_info and parsed_info.get(
                "qc_passed"
            ):  # Changed from "tests_passed" to "qc_passed"
                # Group by distro and kernel
                base_kernel = parsed_info["current_kernel"].split(".")[:3]
                base_kernel = (
                    ".".join(base_kernel)
                    if len(base_kernel) >= 3
                    else parsed_info["current_kernel"]
                )
                group_key = f"{parsed_info['distro']} - Kernel {base_kernel}"

                if group_key not in kernel_groups:
                    kernel_groups[group_key] = {
                        "distro": parsed_info["distro"],
                        "base_kernel": base_kernel,
                        "instances": [],
                        "available_kernels": [],
                    }

                kernel_groups[group_key]["instances"].append(
                    {
                        "instance_id": execution.instance_id,
                        "hostname": parsed_info.get("hostname", execution.instance_id),
                        "tests_passed": parsed_info.get(
                            "qc_passed", False
                        ),  # Use qc_passed field
                    }
                )

                # Merge available kernels
                existing_kernels = set(
                    kernel_groups[group_key].get("available_kernels", [])
                )
                new_kernels = set(parsed_info.get("available_kernels", []))
                kernel_groups[group_key]["available_kernels"] = sorted(
                    existing_kernels | new_kernels
                )

    # Add no-cache headers to prevent stale responses
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    return JSONResponse(
        {
            "status": "success",
            "kernel_groups": kernel_groups,
            "batch_id": latest_execution.batch_id if latest_execution else None,
        },
        headers=headers
    )


@router.get("/qc-results/{batch_id}")
async def get_qc_results(batch_id: str, db: Session = Depends(get_db)):
    """Get QC results for a specific batch"""

    # Check if this is a master batch ID (for Step 2 multi-kernel)
    # Master batch IDs are used for Step 2 when multiple kernels are staged
    executions = db.query(Execution).filter(Execution.batch_id == batch_id).all()

    # If no direct matches, check if it's a master batch ID
    if not executions:
        # Look for executions with this as their master_batch_id in metadata
        executions = (
            db.query(Execution)
            .filter(
                func.json_extract(Execution.execution_metadata, '$.master_batch_id') == batch_id
            )
            .all()
        )

    if not executions:
        return JSONResponse({"status": "not_found", "results": []})

    results = []
    kernel_groups = {}  # Group by distro and current kernel (only for passed instances)
    failed_instances = []  # Track instances that didn't pass QC

    for execution in executions:
        output = execution.output or ""

        # Parse QC output if this is step 1
        parsed_info = {}
        if (
            "qc_step" in (execution.execution_metadata or {})
            and execution.execution_metadata["qc_step"] == "step1_initial_qc"
        ):
            parsed_info = parse_qc_output(output)

            # Only group instances that passed BOTH tests
            if parsed_info["qc_passed"]:
                # Create grouping key using distro and base kernel version (without minor version)
                if parsed_info["current_kernel"] and parsed_info["distro"]:
                    # Extract base kernel version for grouping - use same logic as other endpoints
                    base_kernel = parsed_info["current_kernel"].split(".")[:3]
                    base_kernel = (
                        ".".join(base_kernel)
                        if len(base_kernel) >= 3
                        else parsed_info["current_kernel"]
                    )

                    group_key = f"{parsed_info['distro']} - Kernel {base_kernel}"

                    if group_key not in kernel_groups:
                        kernel_groups[group_key] = {
                            "distro": parsed_info["distro"],
                            "base_kernel": base_kernel,
                            "available_kernels": parsed_info["available_kernels"],
                            "instances": [],
                            "selected_kernel": None,  # Will be set by user in Step 2
                        }

                    # Merge available kernels from all instances in the group
                    existing_kernels = set(
                        kernel_groups[group_key]["available_kernels"]
                    )
                    new_kernels = set(parsed_info["available_kernels"])
                    kernel_groups[group_key]["available_kernels"] = sorted(
                        existing_kernels | new_kernels
                    )

                    kernel_groups[group_key]["instances"].append(
                        {
                            "instance_id": execution.instance_id,
                            "account_id": execution.account_id,
                            "region": execution.region,
                            "hostname": parsed_info["hostname"],
                            "current_kernel": parsed_info["current_kernel"],
                            "crowdstrike": parsed_info["crowdstrike_running"],
                            "crowdstrike_version": parsed_info["crowdstrike_version"],
                            "instance_name": (
                                execution.execution_metadata.get("instance_name", "")
                                if execution.execution_metadata
                                else ""
                            ),
                        }
                    )
            else:
                # Track failed instances
                failed_instances.append(
                    {
                        "instance_id": execution.instance_id,
                        "account_id": execution.account_id,
                        "region": execution.region,
                        "hostname": parsed_info.get("hostname", ""),
                        "test_passed": parsed_info.get("test_passed", False),
                        "disk_space_passed": parsed_info.get(
                            "disk_space_passed", False
                        ),
                        "crowdstrike_running": parsed_info.get(
                            "crowdstrike_running", False
                        ),
                        "error_reason": _get_qc_failure_reason(parsed_info),
                        "instance_name": (
                            execution.execution_metadata.get("instance_name", "")
                            if execution.execution_metadata
                            else ""
                        ),
                    }
                )

        results.append(
            {
                "instance_id": execution.instance_id,
                "account_id": execution.account_id,
                "region": execution.region,
                "status": execution.status,
                "output": output,
                "error": execution.error,
                "parsed_info": parsed_info,
                "instance_name": (
                    execution.execution_metadata.get("instance_name", "")
                    if execution.execution_metadata
                    else ""
                ),
            }
        )

    # Sort kernel groups by distro and kernel version
    sorted_groups = dict(sorted(kernel_groups.items()))

    return JSONResponse(
        {
            "status": "success",
            "results": results,
            "kernel_groups": sorted_groups,
            "failed_instances": failed_instances,
            "total": len(results),
            "completed": sum(
                1 for r in results if r["status"] in ["completed", "failed"]
            ),
            "passed_count": sum(len(g["instances"]) for g in kernel_groups.values()),
            "failed_count": len(failed_instances),
        }
    )


def _get_qc_failure_reason(parsed_info: dict) -> str:
    """Get a human-readable reason for QC failure"""
    reasons = []
    if not parsed_info.get("test_passed", False):
        reasons.append("Repository test failed")
    if not parsed_info.get("disk_space_passed", False):
        reasons.append("Insufficient disk space")
    if not parsed_info.get("crowdstrike_running", False):
        reasons.append("CrowdStrike not running")
    return ", ".join(reasons) if reasons else "Unknown failure"


@router.post("/load-change/{change_id}")
async def load_change(change_id: int, request: Request, db: Session = Depends(get_db)):
    """Load a change and its instances"""
    logger.info(f"load_change: Loading change ID {change_id}")
    
    try:
        change = db.query(Change).filter(Change.id == change_id).first()
        if not change:
            logger.error(f"load_change: Change ID {change_id} not found")
            raise HTTPException(status_code=404, detail="Change not found")

        logger.info(f"load_change: Found change {change.change_number}")

        # Build instances list - ensure all data is basic Python types
        instances = []
        for ci in change.instances:
            # Safely extract metadata with explicit type conversion
            name = ""
            if ci.instance_metadata and isinstance(ci.instance_metadata, dict):
                name = str(ci.instance_metadata.get("name", ""))
            
            instance_data = {
                "instance_id": str(ci.instance_id),  # Ensure string
                "name": name,
                "account_id": str(ci.account_id),  # Ensure string
                "region": str(ci.region),  # Ensure string
                "platform": str(ci.platform),  # Ensure string
                "environment": "gov" if "gov" in str(ci.region) else "com",
            }
            instances.append(instance_data)
            logger.info(f"load_change: Built instance data: {instance_data}")

        # Store in session - ensure all data is basic Python types
        change_data = {
            "id": int(change.id),  # Ensure int
            "change_number": str(change.change_number),  # Ensure string
            "instances": instances,
            "selected_instances": [str(inst["instance_id"]) for inst in instances],  # Ensure strings
        }
        
        logger.info(f"load_change: Built change_data with {len(instances)} instances")
        logger.info(f"load_change: Change data keys: {list(change_data.keys())}")
        
        set_current_change(request, change_data)
        # Clear manually cleared flag since user is now loading a change
        request.session.pop("change_manually_cleared", None)

        return JSONResponse(
            {
                "status": "success",
                "change": change_data,
                "instance_count": len(instances),
            }
        )
        
    except ValueError as e:
        logger.error(f"load_change: Session serialization error: {e}")
        raise HTTPException(status_code=500, detail=f"Session error: {str(e)}")
    except Exception as e:
        logger.error(f"load_change: Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Load error: {str(e)}")


@router.get("/list-changes")
async def list_changes(request: Request, db: Session = Depends(get_db)):
    """List available changes"""
    try:
        changes = db.query(Change).order_by(Change.created_at.desc()).limit(50).all()
        
        # Add no-cache headers to ensure fresh data
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        
        return JSONResponse(
            [
                {
                    "id": change.id,
                    "change_number": change.change_number,  # Changed from "number" to "change_number"
                    "instance_count": len(change.instances),
                    "created_at": (
                        change.created_at.isoformat() if change.created_at else None
                    ),
                }
                for change in changes
            ],
            headers=headers
        )
    except Exception as e:
        logger.error(f"Error listing changes: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/execute-step2-kernel-staging")
async def execute_step2_kernel_staging(request: Request, db: Session = Depends(get_db)):
    """Execute Step 2: Stage kernel versions for each group of instances"""

    try:
        data = await request.json()
        kernel_selections = data.get(
            "kernel_selections", {}
        )  # Dict of group_key -> kernel_version
        batch_id = data.get("batch_id")  # Original batch_id from step 1

        if not kernel_selections:
            raise HTTPException(status_code=400, detail="No kernel selections provided")

        if not batch_id:
            raise HTTPException(status_code=400, detail="No batch ID provided")

        # Get current change
        current_change = get_current_change(request)
        if not current_change:
            raise HTTPException(status_code=400, detail="No change loaded")

        change_number = current_change.get("change_number", "")
        change_id = current_change.get("id")

        # Get the step 1 results to identify which instances belong to which group
        step1_executions = (
            db.query(Execution).filter(Execution.batch_id == batch_id).all()
        )

        # Build instance groups based on kernel selections
        instances_to_execute = []
        for execution in step1_executions:
            if execution.output:
                parsed_info = parse_qc_output(execution.output)

                # Only process instances that passed QC
                if parsed_info["qc_passed"]:
                    # Determine which group this instance belongs to
                    # Use same logic as in latest-step1-results endpoint
                    base_kernel = parsed_info["current_kernel"].split(".")[:3]
                    base_kernel = (
                        ".".join(base_kernel)
                        if len(base_kernel) >= 3
                        else parsed_info["current_kernel"]
                    )
                    group_key = f"{parsed_info['distro']} - Kernel {base_kernel}"

                    # Check if we have a kernel selection for this group
                    if group_key in kernel_selections:
                        selected_kernel = kernel_selections[group_key]

                        # Get instance details from the change
                        change_obj = (
                            db.query(Change).filter(Change.id == change_id).first()
                        )
                        for ci in change_obj.instances:
                            if ci.instance_id == execution.instance_id:
                                instances_to_execute.append(
                                    {
                                        "instance_id": ci.instance_id,
                                        "account_id": ci.account_id,
                                        "region": ci.region,
                                        "platform": ci.platform,
                                        "environment": (
                                            "gov" if "gov" in ci.region else "com"
                                        ),
                                        "kernel_version": selected_kernel,
                                        "group_key": group_key,
                                        "name": (
                                            ci.instance_metadata.get("name", "")
                                            if ci.instance_metadata
                                            else ""
                                        ),
                                    }
                                )
                                break

        if not instances_to_execute:
            raise HTTPException(
                status_code=400, detail="No instances to execute Step 2 on"
            )

        # Create execution records for Step 2
        batch_id_step2 = datetime.now().strftime("%Y%m%d_%H%M%S")
        executions = []

        # Group instances by environment for credential validation
        instances_by_env = {}
        for instance in instances_to_execute:
            env = instance.get("environment", "com")
            if env not in instances_by_env:
                instances_by_env[env] = []
            instances_by_env[env].append(instance)

        # Validate credentials
        missing_creds = []
        for env in instances_by_env.keys():
            aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
            credentials = credential_manager.get_credentials(aws_env.value)

            if not credentials:
                # Try to restore from session

                session_creds_key = f"aws_{env}_credential_data"
                encrypted_creds = request.session.get(session_creds_key)
                session_creds = None
                if encrypted_creds:
                    session_creds = decrypt_session_credentials(encrypted_creds)

                if session_creds:
                    from backend.core.config import AWSCredentials

                    restored_creds = AWSCredentials(
                        access_key=session_creds["access_key"],
                        secret_key=session_creds["secret_key"],
                        session_token=session_creds.get("session_token"),
                        environment=aws_env,
                    )
                    credential_manager.store_credentials(restored_creds)
                    credentials = credential_manager.get_credentials(aws_env.value)

            if not credentials:
                missing_creds.append(env.upper())

        if missing_creds:
            raise HTTPException(
                status_code=400,
                detail=f"Missing credentials for {', '.join(missing_creds)} environment(s)",
            )

        # Create script and execution records for each instance
        script_template = QC_SCRIPTS["step2_kernel_staging"]

        for instance in instances_to_execute:
            # Build script content with the specific kernel version
            script_content = script_template["content"].format(
                change_number=change_number, kernel_version=instance["kernel_version"]
            )

            # Create or get script in database
            script_name = f"Linux QC - Step 2 - {instance['group_key']}"
            db_script = (
                db.query(Script)
                .filter(Script.name == script_name, Script.content == script_content)
                .first()
            )

            if not db_script:
                db_script = Script(
                    name=script_name,
                    content=script_content,
                    script_type="bash",
                    interpreter="bash",
                    description=f"Stage kernel {instance['kernel_version']} for {instance['group_key']}",
                    change_id=change_id,  # Add the change_id
                    tool_id=None,  # Explicitly set tool_id to None
                )
                db.add(db_script)
                db.flush()

            # Create execution record
            execution = Execution(
                script_id=db_script.id,
                instance_id=instance["instance_id"],
                account_id=instance["account_id"],
                region=instance["region"],
                status="pending",
                batch_id=batch_id_step2,
                change_number=change_number,
                execution_metadata={
                    "script_name": script_name,
                    "qc_step": "step2_kernel_staging",
                    "kernel_version": instance["kernel_version"],
                    "environment": instance["environment"],
                    "instance_name": instance.get("name", ""),
                    "change_id": change_id,
                    "group_key": instance["group_key"],
                },
            )
            db.add(execution)
            executions.append(execution)

        db.commit()

        # Start execution in background
        logger.info(f"Starting Linux QC Step 2 for batch {batch_id_step2}")

        # Group execution records by script_id for batch submission
        scripts_to_execute = {}
        for execution in executions:
            script_id = execution.script_id
            if script_id not in scripts_to_execute:
                db_script = db.query(Script).filter(Script.id == script_id).first()
                if not db_script:
                    logger.error(f"Script {script_id} not found in database")
                    continue

                scripts_to_execute[script_id] = {
                    'script': {
                        'id': db_script.id,
                        'name': db_script.name,
                        'content': db_script.content,
                        'interpreter': db_script.interpreter or 'bash'
                    },
                    'execution_ids': [],
                    'instances_by_env': {}
                }

            scripts_to_execute[script_id]['execution_ids'].append(execution.id)

            # Group instances by environment
            env = execution.execution_metadata.get('environment', 'com')
            if env not in scripts_to_execute[script_id]['instances_by_env']:
                scripts_to_execute[script_id]['instances_by_env'][env] = []

            scripts_to_execute[script_id]['instances_by_env'][env].append({
                'instance_id': execution.instance_id,
                'account_id': execution.account_id,
                'region': execution.region,
                'platform': 'linux',
                'environment': env,
                'name': execution.execution_metadata.get('instance_name', '')
            })

        # Submit each script group for execution
        for script_data in scripts_to_execute.values():
            logger.info(f"Submitting Step 2 script {script_data['script']['name']} for {len(script_data['execution_ids'])} instances")
            submit_execution(
                batch_id_step2,
                script_data['script'],
                script_data['execution_ids'],
                script_data['instances_by_env'],
                credential_manager
            )

        logger.info(f"Submitted Step 2 kernel staging batch {batch_id_step2} to executor service")

        # Store batch info in session
        jobs = request.session.get("background_jobs", [])
        jobs.append(
            {
                "id": batch_id_step2,
                "name": "Linux QC - Step 2: Kernel Staging",
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "total": len(executions),
                "completed": 0,
                "qc_step": "step2_kernel_staging",
            }
        )
        request.session["background_jobs"] = jobs

        return JSONResponse(
            {
                "status": "success",
                "batch_id": batch_id_step2,
                "execution_count": len(executions),
                "step": "step2_kernel_staging",
                "kernel_selections": kernel_selections,
            }
        )

    except Exception as e:
        logger.error(f"Error executing Step 2 kernel staging: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e

@router.post("/clear-change")
async def clear_change(request: Request):
    """Clear current change"""
    logger.info("clear_change: Clearing session data")
    logger.info(f"clear_change: BEFORE - Session keys: {list(request.session.keys())}")
    
    request.session.pop("current_change", None)
    request.session.pop("instances", None)
    request.session.pop("selected_instances", None)
    # Set flag to prevent auto-restore on next page load
    request.session["change_manually_cleared"] = True
    
    # In Starlette/FastAPI, session changes are automatically detected
    # No need to manually set modified flag
    
    logger.info(f"clear_change: AFTER - Session keys: {list(request.session.keys())}")
    return JSONResponse({"status": "success"})


@router.get("/debug-session")
@router.post("/debug-session") 
async def debug_session(request: Request):
    """Debug session state - useful for troubleshooting"""
    session_data = dict(request.session)
    logger.info(f"debug_session: Full session contents: {session_data}")
    
    return JSONResponse({
        "session_keys": list(request.session.keys()),
        "current_change": request.session.get("current_change"),
        "session_size": len(dict(request.session)),
        "change_manually_cleared": request.session.get("change_manually_cleared", False)
    })


@router.post("/save-change-with-instances")
async def save_change_with_instances(request: Request, db: Session = Depends(get_db)):
    """Save a change with instances from manual entry"""
    try:

        # Get form data
        form = await request.form()
        change_number = form.get("change_number")
        description = form.get("description", "")
        instances_json = form.get("instances", "[]")

        if not change_number:
            raise ValueError("Change number is required")

        # Parse instances
        import json

        instances = json.loads(instances_json)

        if not instances:
            raise ValueError("At least one instance is required")

        # Check if change already exists
        existing_change = (
            db.query(Change).filter(Change.change_number == change_number).first()
        )

        if existing_change:
            # Update existing change
            change = existing_change
            # Clear existing instances
            db.query(ChangeInstance).filter(
                ChangeInstance.change_id == change.id
            ).delete()
        else:
            # Create new change
            change = Change(change_number=change_number, description=description)
            db.add(change)
            db.flush()

        # Add instances
        for inst_data in instances:
            instance = ChangeInstance(
                change_id=change.id,
                instance_id=inst_data.get("instance_id"),
                account_id=inst_data.get("account_id"),
                region=inst_data.get("region"),
                platform=inst_data.get("platform", "linux"),
                instance_metadata={"name": inst_data.get("name", "")},
            )
            db.add(instance)

        db.commit()

        # Store in session
        change_data = {
            "id": change.id,
            "change_number": change.change_number,  # Changed from "number" to "change_number"
            "instances": instances,
            "selected_instances": [inst["instance_id"] for inst in instances],
        }
        set_current_change(request, change_data)
        # Clear manually cleared flag since user just created/saved a change
        request.session.pop("change_manually_cleared", None)

        return JSONResponse(
            {
                "status": "success",
                "change_id": change.id,
                "change_number": change_number,
                "instance_count": len(instances),
            }
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error saving change: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/upload-change-csv")
async def upload_change_csv(request: Request, db: Session = Depends(get_db)):
    """Upload CSV with change and instance data"""
    try:
        import csv
        import io

        # Get the file from the form
        form = await request.form()
        file_data = form.get("file")

        if not file_data:
            raise ValueError("No file uploaded")

        # Read CSV content
        content = await file_data.read()
        csv_text = content.decode("utf-8-sig")  # utf-8-sig automatically handles BOM
        reader = csv.DictReader(io.StringIO(csv_text))

        # Process rows
        rows = list(reader)
        if not rows:
            raise ValueError("CSV file is empty")
            
        # Debug: Log CSV structure
        if rows:
            logger.error(f"DEBUG CSV Headers: {list(rows[0].keys())}")
            logger.error(f"DEBUG First row: {rows[0]}")

        # Get change number from first row
        change_number = None
        instances = []

        for row in rows:
            # Try different column name variations
            cn = (
                row.get("change_number")
                or row.get("Change_number")
                or row.get("ChangeNumber")
                or row.get("Change Number")
            )
            if cn and not change_number:
                change_number = cn

            # Extract instance data
            instance_id = (
                row.get("instance_id")
                or row.get("InstanceID")
                or row.get("Instance ID")
                or row.get("instance_id")
            )
            account_id = (
                row.get("account_id") 
                or row.get("AccountID") 
                or row.get("Account ID")
                or row.get("account_id")
            )
            region = row.get("region") or row.get("Region") or row.get("region")
            platform = row.get("platform") or row.get("Platform") or "linux"

            if instance_id and account_id and region:
                instances.append(
                    {
                        "instance_id": instance_id,
                        "account_id": account_id,
                        "region": region,
                        "platform": platform.lower(),
                        "environment": "gov" if "gov" in region.lower() else "com",
                        "name": row.get("name", ""),
                    }
                )

        if not change_number:
            raise ValueError("Change number not found in CSV")

        if not instances:
            raise ValueError("No valid instances found in CSV")

        # Check if change exists
        existing_change = (
            db.query(Change).filter(Change.change_number == change_number).first()
        )

        if existing_change:
            change = existing_change
            # Clear existing instances
            db.query(ChangeInstance).filter(
                ChangeInstance.change_id == change.id
            ).delete()
        else:
            # Create new change
            change = Change(
                change_number=change_number,
                description=f"Uploaded from CSV on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            )
            db.add(change)
            db.flush()

        # Add instances
        for inst_data in instances:
            instance = ChangeInstance(
                change_id=change.id,
                instance_id=inst_data["instance_id"],
                account_id=inst_data["account_id"],
                region=inst_data["region"],
                platform=inst_data["platform"],
                instance_metadata={"name": inst_data.get("name", "")},
            )
            db.add(instance)

        db.commit()

        # Store in session
        change_data = {
            "id": change.id,
            "change_number": change.change_number,  # Changed from "number" to "change_number"
            "instances": instances,
            "selected_instances": [inst["instance_id"] for inst in instances],
        }
        set_current_change(request, change_data)
        # Clear manually cleared flag since user is now loading a change via CSV
        request.session.pop("change_manually_cleared", None)

        return JSONResponse(
            {
                "status": "success",
                "change_id": change.id,
                "change_number": change_number,
                "instance_count": len(instances),
            }
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error uploading CSV: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/execute-step2-multi-kernel")
async def execute_step2_multi_kernel(request: Request, db: Session = Depends(get_db)):
    """Execute Step 2 kernel staging for multiple kernel groups

    This endpoint handles the complexity of executing Step 2 with different kernels
    for different groups of instances. It groups instances by account/region/kernel
    to optimize SSM command execution.
    """
    import time

    try:
        data = await request.json()
        kernel_groups = data.get("kernel_groups", [])

        if not kernel_groups:
            raise HTTPException(status_code=400, detail="No kernel groups provided")

        # Get current change
        current_change = get_current_change(request)
        if not current_change:
            raise HTTPException(status_code=400, detail="No change loaded")

        change_number = current_change.get("change_number", "")
        change_id = current_change.get("id")

        # Get the script template for Step 2
        script_template = QC_SCRIPTS["step2_kernel_staging"]

        # Get instances from database
        change_obj = db.query(Change).filter(Change.id == change_id).first()
        if not change_obj:
            raise HTTPException(status_code=404, detail="Change not found")

        # Build a map of instance_id to instance details
        instance_map = {}
        for ci in change_obj.instances:
            instance_map[ci.instance_id] = {
                "instance_id": ci.instance_id,
                "account_id": ci.account_id,
                "region": ci.region,
                "platform": ci.platform,
                "environment": "gov" if "gov" in ci.region else "com",
                "name": (
                    ci.instance_metadata.get("name", "") if ci.instance_metadata else ""
                ),
            }

        # Group instances by account/region/kernel for efficient execution
        execution_groups = {}
        for group in kernel_groups:
            kernel_version = group["kernel"]
            instances = group.get("instances", [])

            for inst_id in instances:
                if inst_id not in instance_map:
                    continue

                inst_detail = instance_map[inst_id]
                # Create key: env_account_region_kernel
                group_key = f"{inst_detail['environment']}_{inst_detail['account_id']}_{inst_detail['region']}_{kernel_version}"

                if group_key not in execution_groups:
                    execution_groups[group_key] = {
                        "environment": inst_detail["environment"],
                        "account_id": inst_detail["account_id"],
                        "region": inst_detail["region"],
                        "kernel_version": kernel_version,
                        "instances": [],
                    }

                execution_groups[group_key]["instances"].append(inst_detail)

        if not execution_groups:
            raise HTTPException(status_code=400, detail="No valid instances to execute")

        # Validate credentials for all environments
        environments_needed = set(g["environment"] for g in execution_groups.values())
        missing_creds = []

        for env in environments_needed:
            aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
            credentials = credential_manager.get_credentials(aws_env.value)

            # Try to restore from session if not in manager
            if not credentials:

                session_creds_key = f"aws_{env}_credential_data"
                encrypted_creds = request.session.get(session_creds_key)
                session_creds = None
                if encrypted_creds:
                    session_creds = decrypt_session_credentials(encrypted_creds)

                if session_creds:
                    from backend.core.config import AWSCredentials

                    restored_creds = AWSCredentials(
                        access_key=session_creds["access_key"],
                        secret_key=session_creds["secret_key"],
                        session_token=session_creds.get("session_token"),
                        environment=aws_env,
                    )
                    credential_manager.store_credentials(restored_creds)
                    credentials = credential_manager.get_credentials(aws_env.value)

            if not credentials:
                missing_creds.append(env.upper())

        if missing_creds:
            raise HTTPException(
                status_code=400,
                detail=f"Missing credentials for {', '.join(missing_creds)} environment(s)",
            )

        # Create a master batch ID for tracking all executions
        master_batch_id = datetime.now().strftime("%Y%m%d_%H%M%S_multi")
        all_executions = []

        # Process each execution group
        for group_key, group_data in execution_groups.items():
            kernel_version = group_data["kernel_version"]
            group_instances = group_data["instances"]

            # Build the script content with the specific kernel version
            script_content = script_template["content"].format(
                change_number=change_number, kernel_version=kernel_version
            )

            # Create or get the script
            script_name = f"Linux_QC_Step2_{kernel_version}_{int(time.time())}"
            db_script = db.query(Script).filter(Script.name == script_name).first()

            if not db_script:
                db_script = Script(
                    name=script_name,
                    content=script_content,
                    script_type="bash",
                    interpreter="bash",
                    description=f"Linux QC Patching Prep Step 2 - Kernel {kernel_version}",
                    change_id=change_id,  # Add the change_id
                    tool_id=None,  # Explicitly set tool_id to None
                )
                db.add(db_script)
                db.flush()

            # Create a batch ID for this group
            batch_id = f"{master_batch_id}_{group_data['account_id']}_{group_data['region']}_{kernel_version.replace('.', '_')}"

            # Create executions for this group
            for instance in group_instances:
                execution = Execution(
                    script_id=db_script.id,
                    instance_id=instance["instance_id"],
                    account_id=instance["account_id"],
                    region=instance["region"],
                    status="pending",
                    batch_id=batch_id,
                    change_number=change_number,
                    execution_metadata={
                        "script_name": script_name,
                        "qc_step": "step2_kernel_staging",
                        "kernel_version": kernel_version,
                        "environment": instance["environment"],
                        "platform": instance["platform"],  # Store platform in metadata
                        "instance_name": instance.get("name", ""),
                        "change_id": change_id,
                        "master_batch_id": master_batch_id,
                        "execution_group": group_key,
                    },
                )
                db.add(execution)
                all_executions.append(execution)

        db.commit()

        # Now execute each group
        for group_key, group_data in execution_groups.items():
            group_executions = [
                e
                for e in all_executions
                if e.execution_metadata.get("execution_group") == group_key
            ]

            if not group_executions:
                continue

            # Get the script for this group
            script_id = group_executions[0].script_id
            db_script = db.query(Script).filter(Script.id == script_id).first()

            script_dict = {
                "id": db_script.id,
                "name": db_script.name,
                "content": db_script.content,
                "interpreter": "bash",
            }

            # Group instances by environment for this execution group
            instances_by_env = {}
            for instance in group_data["instances"]:
                env = instance["environment"]
                if env not in instances_by_env:
                    instances_by_env[env] = []
                instances_by_env[env].append(instance)

            execution_ids = [e.id for e in group_executions]
            batch_id = group_executions[0].batch_id

            logger.info(
                f"Starting Step 2 kernel staging for group {group_key} with batch {batch_id}"
            )

            # Start execution in background thread using shared executor
            future = submit_execution(
                batch_id,
                script_dict,
                execution_ids,
                instances_by_env,
                credential_manager,
            )
            logger.info(f"Submitted multi-kernel batch {batch_id} to executor service")

        # Store batch info in session
        jobs = request.session.get("background_jobs", [])
        jobs.append(
            {
                "id": master_batch_id,
                "name": f"Step2_Multi_Kernel_{master_batch_id}",
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "total": len(all_executions),
                "completed": 0,
                "qc_step": "step2_kernel_staging",
                "execution_groups": len(execution_groups),
            }
        )
        request.session["background_jobs"] = jobs

        return JSONResponse(
            {
                "status": "success",
                "master_batch_id": master_batch_id,
                "execution_count": len(all_executions),
                "execution_groups": len(execution_groups),
                "groups": [
                    {
                        "key": k,
                        "kernel": v["kernel_version"],
                        "instances": len(v["instances"]),
                        "account": v["account_id"],
                        "region": v["region"],
                    }
                    for k, v in execution_groups.items()
                ],
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing Step 2 multi-kernel: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/download-reports")
async def download_reports(request: Request, db: Session = Depends(get_db)):
    """Download QC execution results as markdown file"""
    from fastapi.responses import Response

    # Get current change info
    current_change = request.session.get("current_change", {})
    if not current_change:
        return Response(
            content="No active change found. Please load a change first.",
            media_type="text/plain",
        )

    change_number = current_change.get("change_number", "Unknown")
    change_id = current_change.get("id")

    if not change_id:
        return Response(
            content="No valid change loaded", media_type="text/plain"
        )

    # Query all executions for this change that have QC metadata
    executions = (
        db.query(Execution)
        .filter(
            Execution.change_number == change_number,
            func.json_extract(Execution.execution_metadata, '$.qc_step').is_not(None),
        )
        .order_by(desc(Execution.created_at))
        .all()
    )

    if not executions:
        return Response(
            content=f"No QC execution results found for change {change_number}",
            media_type="text/plain",
        )

    # Build markdown content
    markdown_lines = [
        f"# Linux QC Patching Results - {change_number}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Total Executions:** {len(executions)}",
        "",
        "---",
        "",
    ]

    # Group executions by QC step
    executions_by_step = {}
    for execution in executions:
        qc_step = execution.execution_metadata.get("qc_step", "unknown") if execution.execution_metadata else "unknown"
        if qc_step not in executions_by_step:
            executions_by_step[qc_step] = []
        executions_by_step[qc_step].append(execution)

    # Process each step
    step_order = ["step1_initial_qc", "step2_kernel_staging", "step3_final_report"]
    for step in step_order:
        if step not in executions_by_step:
            continue

        step_executions = executions_by_step[step]

        # Step header
        step_name = {
            "step1_initial_qc": "Step 1: Initial QC and Report Generation",
            "step2_kernel_staging": "Step 2: Kernel Staging",
            "step3_final_report": "Step 3: Final QC Report"
        }.get(step, step)

        markdown_lines.append(f"## {step_name}")
        markdown_lines.append("")

        # Sort executions by instance ID for consistent ordering
        step_executions.sort(key=lambda x: x.instance_id)

        for execution in step_executions:
            # Instance header
            markdown_lines.append(f"### Instance: {execution.instance_id}")
            markdown_lines.append(f"**Account:** {execution.account_id}")
            markdown_lines.append(f"**Region:** {execution.region}")

            # Add instance name if available
            if execution.execution_metadata and execution.execution_metadata.get("instance_name"):
                markdown_lines.append(f"**Instance Name:** {execution.execution_metadata['instance_name']}")

            markdown_lines.append(f"**Status:** {execution.status}")

            # Add timestamps
            if execution.start_time:
                markdown_lines.append(f"**Start Time:** {execution.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if execution.end_time:
                markdown_lines.append(f"**End Time:** {execution.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

            # Add step-specific metadata
            if execution.execution_metadata:
                if step == "step2_kernel_staging" and execution.execution_metadata.get("kernel_version"):
                    markdown_lines.append(f"**Target Kernel:** {execution.execution_metadata['kernel_version']}")

                batch_id = execution.batch_id
                if batch_id:
                    markdown_lines.append(f"**Batch ID:** {batch_id}")

            markdown_lines.append("")

            # Output section
            markdown_lines.append("#### Output:")
            if execution.output and execution.output.strip():
                markdown_lines.append("```bash")
                markdown_lines.append(execution.output.strip())
                markdown_lines.append("```")
            else:
                markdown_lines.append("*No output available*")

            markdown_lines.append("")
            markdown_lines.append("---")
            markdown_lines.append("")

    # Join all lines
    markdown_content = "\n".join(markdown_lines)

    # Create filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"qc_results_{change_number}_{timestamp}.md"

    # Return as downloadable file
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/download-final-report")
async def download_final_report(request: Request, db: Session = Depends(get_db)):
    """Download abbreviated QC final report (Step 3 only) as markdown file"""
    from fastapi.responses import Response

    # Get current change info
    current_change = request.session.get("current_change", {})
    if not current_change:
        return Response(
            content="No active change found. Please load a change first.",
            media_type="text/plain",
        )

    change_number = current_change.get("change_number", "Unknown")
    change_id = current_change.get("id")

    if not change_id:
        return Response(
            content="No valid change loaded", media_type="text/plain"
        )

    # Query only Step 3 executions for this change
    executions = (
        db.query(Execution)
        .filter(
            Execution.change_number == change_number,
            func.json_extract(Execution.execution_metadata, '$.qc_step') == "step3_final_report",
        )
        .order_by(desc(Execution.created_at))
        .all()
    )

    if not executions:
        return Response(
            content=f"No Step 3 QC execution results found for change {change_number}. Please run Step 3 first.",
            media_type="text/plain",
        )

    # Build markdown content - abbreviated version
    markdown_lines = [
        f"# Linux QC Final Report - {change_number}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Total Instances:** {len(executions)}",
        "",
        "This report contains the final QC results and patch scripts generated after completing all QC steps.",
        "",
        "---",
        "",
    ]

    # Sort executions by instance ID for consistent ordering
    executions = sorted(executions, key=lambda x: x.instance_id or "")

    for execution in executions:
        # Instance header
        markdown_lines.append(f"## Instance: {execution.instance_id}")
        markdown_lines.append(f"**Account:** {execution.account_id}")
        markdown_lines.append(f"**Region:** {execution.region}")
        markdown_lines.append(f"**Status:** {execution.status}")

        # Add timestamps
        if execution.end_time:
            markdown_lines.append(f"**Report Generated:** {execution.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Add batch ID if available
        if execution.batch_id:
            markdown_lines.append(f"**Batch ID:** {execution.batch_id}")

        markdown_lines.append("")

        # Parse and format the Step 3 output more cleanly
        if execution.output and execution.output.strip():
            output = execution.output.strip()

            # Split the output into QC Report and Patch Script sections
            if "=== QC Report ===" in output and "=== Patch Script ===" in output:
                # Extract the clean portions
                qc_report_start = output.find("=== QC Report ===")
                patch_script_start = output.find("=== Patch Script ===")

                if qc_report_start != -1 and patch_script_start != -1:
                    # Extract QC report section
                    qc_section = output[qc_report_start:patch_script_start].strip()
                    patch_section = output[patch_script_start:].strip()

                    markdown_lines.append("### QC Summary")
                    # Clean up ANSI color codes for better readability
                    clean_qc = qc_section.replace("[33m", "").replace("[0m", "").replace("=== QC Report ===", "")
                    clean_qc = clean_qc.replace("===== QC report for ", "**Server:** ").replace(" =====", "")
                    clean_qc = clean_qc.replace("========================================", "")
                    markdown_lines.append("```")
                    markdown_lines.append(clean_qc.strip())
                    markdown_lines.append("```")
                    markdown_lines.append("")

                    markdown_lines.append("### Patch Script")
                    # Extract just the script content
                    patch_content = patch_section.replace("=== Patch Script ===", "").strip()
                    markdown_lines.append("```bash")
                    markdown_lines.append(patch_content)
                    markdown_lines.append("```")
                else:
                    # Fallback - show raw output if parsing fails
                    markdown_lines.append("### Output")
                    markdown_lines.append("```bash")
                    markdown_lines.append(output)
                    markdown_lines.append("```")
            else:
                # Fallback - show raw output if expected sections not found
                markdown_lines.append("### Output")
                markdown_lines.append("```bash")
                markdown_lines.append(output)
                markdown_lines.append("```")
        else:
            markdown_lines.append("### Output")
            markdown_lines.append("*No output available*")

        markdown_lines.append("")
        markdown_lines.append("---")
        markdown_lines.append("")

    # Join all lines
    markdown_content = "\n".join(markdown_lines)

    # Create filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"qc_final_report_{change_number}_{timestamp}.md"

    # Return as downloadable file
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
