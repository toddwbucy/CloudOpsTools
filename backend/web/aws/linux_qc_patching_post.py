"""AWS Linux QC Patching Post Tool - Web Interface"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
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
def get_current_change(request: Request, db: Session = None) -> Optional[Dict]:
    """Get the current change from session.

    Only stores the change ID in session to avoid cookie size limits.
    Loads full change data from database when retrieved.
    """
    change_id = request.session.get("current_change_id")
    if not change_id:
        return None

    # If no db session provided, can't load full data
    if db is None:
        return {"id": change_id}

    # Load full change data from database
    change = db.query(Change).filter(Change.id == change_id).first()
    if not change:
        # Change was deleted, clear session
        request.session.pop("current_change_id", None)
        return None

    # Build instances list
    instances = []
    for ci in change.instances:
        instances.append(
            {
                "instance_id": ci.instance_id,
                "name": (
                    ci.instance_metadata.get("name", "") if ci.instance_metadata else ""
                ),
                "account_id": ci.account_id,
                "region": ci.region,
                "platform": ci.platform,
                "environment": "gov" if "gov" in ci.region else "com",
            }
        )

    return {
        "id": change.id,
        "change_number": change.change_number,
        "instances": instances,
        "selected_instances": [inst["instance_id"] for inst in instances],
    }


def set_current_change(request: Request, change_data: Dict) -> None:
    """Set the current change in session.

    Only stores the change ID to avoid cookie size limits.
    """
    request.session["current_change_id"] = change_data["id"]


def generate_post_patch_script(change_number: str) -> str:
    """Generate the enhanced post-patch validation script
    
    Comprehensive validation script that checks:
    - Kernel version validation
    - Critical services (SFTD, CrowdStrike, EnCase, BigFix)
    - Disk space and LVM health
    - System health status
    - Package management history
    """
    # Sanitize change_number to prevent command injection
    import shlex
    safe_change_number = shlex.quote(change_number)

    script_content = f"""#!/bin/bash
CHANGE={safe_change_number}

echo "=== BASIC SYSTEM INFO ==="
hostname
date
uptime
who -b  # System boot time

echo ""
echo "=== KERNEL VALIDATION ==="
if [[ ! -f "/root/$CHANGE/patchme.sh" ]]; then
    echo "ERROR: /root/$CHANGE/patchme.sh not found"
    echo "This server may not have been prepped for patching"
    exit 1
fi

k_target=$(grep -Eo 'kernel-[0-9]+\\.[0-9]+\\.[0-9]+-[^ ]+' /root/$CHANGE/patchme.sh | sed 's/^kernel-//' | head -1)
current_kernel=$(uname -r)

if [[ -z "$k_target" ]]; then
    echo "WARNING: Could not extract target kernel from patchme.sh"
    echo "Contents of patchme.sh (first 20 lines):"
    cat /root/$CHANGE/patchme.sh | head -20
    kernel_pass=false
elif [[ "$current_kernel" == "$k_target"* ]]; then
    echo "✓ PASS: Kernel matches target"
    echo "  Current: $current_kernel"
    echo "  Target:  $k_target"
    kernel_pass=true
else
    echo "✗ FAIL: Kernel mismatch"
    echo "  Current: $current_kernel"
    echo "  Target:  $k_target"
    kernel_pass=false
fi

echo ""
echo "=== PACKAGE MANAGEMENT ==="
# Check for both yum and apt history
if command -v yum >/dev/null 2>&1; then
    yum history | grep $(date +%F) || echo "No yum activity today"
elif command -v apt >/dev/null 2>&1; then
    grep " $(date +%Y-%m-%d)" /var/log/apt/history.log 2>/dev/null || echo "No apt activity today"
else
    echo "No recognized package manager found"
fi

echo ""
echo "=== CRITICAL SERVICES ==="

# SFTD service check
if systemctl is-active sftd >/dev/null 2>&1; then
    echo "✓ SFTD: Running"
elif systemctl status sftd >/dev/null 2>&1; then
    echo "✗ SFTD: Not Running (service exists but stopped)"
else
    echo "- SFTD: Service not installed"
fi

# CrowdStrike check
crowdstrike_running=false
if systemctl is-active falcon-sensor >/dev/null 2>&1; then
    echo "✓ CrowdStrike: Running"
    /opt/CrowdStrike/falconctl -g --version 2>/dev/null | grep version || echo "  Version check failed"
    crowdstrike_running=true
elif [ -f /opt/CrowdStrike/falconctl ]; then
    echo "✗ CrowdStrike: NOT RUNNING - Critical Issue!"
    echo "  Falcon sensor installed but not active"
else
    echo "- CrowdStrike: Not installed"
fi

# EnCase check
if pgrep -x "enlinuxpc" >/dev/null 2>&1; then
    echo "✓ EnCase: Running"
    # Check for EnCase version if available
    if [ -f /usr/local/bin/enlinuxpc ]; then
        echo "  EnCase binary found at /usr/local/bin/enlinuxpc"
    elif [ -f /opt/encase/enlinuxpc ]; then
        echo "  EnCase binary found at /opt/encase/enlinuxpc"
    fi
elif [ -f /usr/local/bin/enlinuxpc ] || [ -f /opt/encase/enlinuxpc ]; then
    echo "✗ EnCase: Installed but NOT RUNNING"
else
    echo "- EnCase: Not installed"
fi

# BigFix (BES Client) check
bigfix_running=false
if systemctl is-active besclient >/dev/null 2>&1; then
    echo "✓ BigFix: Running"
    # Try to get BigFix version
    if [ -f /opt/BESClient/bin/BESClient ]; then
        /opt/BESClient/bin/BESClient -version 2>/dev/null | head -1 || echo "  Version check failed"
    fi
    bigfix_running=true
elif systemctl status besclient >/dev/null 2>&1; then
    echo "✗ BigFix: NOT RUNNING - Critical Issue!"
    echo "  BES Client installed but not active"
elif [ -f /etc/init.d/besclient ]; then
    # Check for older init.d style service
    if /etc/init.d/besclient status >/dev/null 2>&1; then
        echo "✓ BigFix: Running (init.d)"
        bigfix_running=true
    else
        echo "✗ BigFix: NOT RUNNING (init.d service)"
    fi
else
    echo "- BigFix: Not installed"
fi

echo ""
echo "=== DISK AND STORAGE ==="

# Basic disk usage
echo "Filesystem Usage:"
df -h / 2>/dev/null | tail -1 | awk '{{print "  Root: "$5" used ("$4" available)"}}'
if df -h /boot 2>/dev/null | tail -1 >/dev/null 2>&1; then
    df -h /boot 2>/dev/null | tail -1 | awk '{{print "  Boot: "$5" used ("$4" available)"}}'
fi

# LVM checks if LVM is present
if command -v vgs >/dev/null 2>&1; then
    echo ""
    echo "LVM Status:"
    
    # Check volume groups
    vg_count=$(vgs --noheadings 2>/dev/null | wc -l)
    if [ $vg_count -gt 0 ]; then
        echo "  Volume Groups: $vg_count found"
        
        # Check for any VG issues - simplified to avoid complex while loop in SSM
        vgs_output=$(vgs --noheadings -o vg_name,vg_attr 2>/dev/null)
        if echo "$vgs_output" | grep -q "r"; then
            echo "  ✓ Volume groups appear healthy"
        else
            echo "  ✗ Check volume group status:"
            echo "$vgs_output" | head -3
        fi
        
        # Check logical volumes
        lv_count=$(lvs --noheadings 2>/dev/null | wc -l)
        echo "  Logical Volumes: $lv_count found"
        
        # Check for inactive LVs
        inactive_lvs=$(lvs --noheadings -o lv_attr 2>/dev/null | grep -c "^.*-" 2>/dev/null || echo "0")
        if [ "$inactive_lvs" -gt 0 ]; then
            echo "  ✗ Warning: $inactive_lvs inactive logical volumes detected"
            lvs --noheadings -o lv_name,vg_name,lv_attr 2>/dev/null | grep "^.*-" | head -3
        else
            echo "  ✓ All logical volumes active"
        fi
        
        # Check PV status
        pv_count=$(pvs --noheadings 2>/dev/null | wc -l)
        echo "  Physical Volumes: $pv_count found"
        
        # Check for missing PVs
        if pvs 2>&1 | grep -q "missing"; then
            echo "  ✗ Warning: Missing physical volumes detected!"
        fi
    else
        echo "  No LVM volume groups found"
    fi
else
    echo "- LVM: Not configured"
fi

echo ""
echo "=== SYSTEM HEALTH ==="

# Memory status
echo "Memory Status:"
free -h | grep "^Mem:" | awk '{{print "  Total: "$2", Used: "$3", Free: "$4}}'
free -h | grep "^Swap:" | awk '{{print "  Swap Total: "$2", Used: "$3}}'

# Failed services
failed_count=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
if [ $failed_count -eq 0 ]; then
    echo "✓ No failed services"
else
    echo "✗ $failed_count failed services detected:"
    systemctl --failed --no-legend 2>/dev/null | head -5
fi

# Check for kernel panic or critical errors in last boot
echo ""
echo "Boot Messages:"
if dmesg 2>/dev/null | grep -iE "kernel panic|critical|emergency" | head -1 >/dev/null 2>&1; then
    echo "✗ Critical messages found in boot log:"
    dmesg 2>/dev/null | grep -iE "kernel panic|critical|emergency" | head -3
else
    echo "✓ No critical boot messages detected"
fi

echo ""
echo "=== FINAL STATUS ==="

# Determine overall pass/fail
validation_passed=true
validation_issues=""

if [ "$kernel_pass" != "true" ]; then
    validation_passed=false
    validation_issues="$validation_issues\\n  - Kernel version validation failed"
fi

if [ "$crowdstrike_running" != "true" ] && [ -f /opt/CrowdStrike/falconctl ]; then
    validation_passed=false
    validation_issues="$validation_issues\\n  - CrowdStrike installed but not running"
fi

if [ "$bigfix_running" != "true" ] && ([ -f /opt/BESClient/bin/BESClient ] || [ -f /etc/init.d/besclient ]); then
    validation_passed=false
    validation_issues="$validation_issues\\n  - BigFix installed but not running"
fi

if [ "$validation_passed" = "true" ]; then
    echo "✓ POST-PATCH VALIDATION: PASSED"
    echo "  System successfully patched and rebooted"
    echo "  All critical services verified"
else
    echo "✗ POST-PATCH VALIDATION: FAILED"
    echo "  Issues detected:"
    echo -e "$validation_issues"
fi

# Record validation timestamp
echo ""
echo "Validation completed at: $(date)"
"""
    return script_content


# Pre-defined script for post-patch validation
POST_PATCH_SCRIPT = {
    "name": "Enhanced Post-Patch Validation",
    "description": "Comprehensive validation including kernel checks, critical services (SFTD, CrowdStrike, EnCase, BigFix), disk/LVM health, and system status",
    "interpreter": "bash",
}


@router.get("/", response_class=HTMLResponse)
async def linux_qc_patching_post_page(request: Request, db: Session = Depends(get_db)):
    """Linux QC Patching Post Tool main page"""
    # Get current change if loaded
    current_change = get_current_change(request, db)

    # Get list of available changes
    changes = db.query(Change).order_by(Change.created_at.desc()).limit(10).all()

    # Check credential status from session
    com_credentials = request.session.get("aws_com_credentials", False)
    gov_credentials = request.session.get("aws_gov_credentials", False)

    return templates.TemplateResponse(
        "aws/linux_qc_patching_post.html",
        {
            "request": request,
            "current_change": current_change,
            "changes": changes,
            "settings": settings,
            "com_credentials": com_credentials,
            "gov_credentials": gov_credentials,
        },
    )


def _restore_credentials_from_session_post(request: Request, env: str, aws_env) -> Optional[Any]:
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


def _prepare_credentials_for_assume_role_post(credentials, env: str):
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


async def _assume_role_for_account_post(account_id: str, region: str, credentials, env: str):
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
    am_creds = _prepare_credentials_for_assume_role_post(credentials, env)

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



async def _check_ssm_connectivity_post(ssm_client, region_instances, account_id: str, region: str):
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


def _handle_ssm_errors_post(error, region_instances):
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
                credentials = _restore_credentials_from_session_post(request, env, aws_env)

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
                    ssm_client, role_assumed = await _assume_role_for_account_post(
                        account_id, region, credentials, env
                    )

                    # Check SSM connectivity
                    connectivity_results = await _check_ssm_connectivity_post(
                        ssm_client, region_instances, account_id, region
                    )
                    results.extend(connectivity_results)

                except ClientError as e:
                    error_results = _handle_ssm_errors_post(e, region_instances)
                    results.extend(error_results)

                except Exception as e:
                    # General error for this account/region
                    logger.error(
                        f"Error checking SSM for account {account_id}, region {region}: {str(e)}"
                    )
                    error_results = _handle_ssm_errors_post(e, region_instances)
                    results.extend(error_results)

        return JSONResponse({"status": "success", "results": results})

    except Exception as e:
        logger.error(f"Error testing connectivity: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/execute-post-validation")
async def execute_post_validation(request: Request, db: Session = Depends(get_db)):
    """Execute post-patch validation on selected instances"""

    try:
        data = await request.json()
        instance_ids = data.get("instance_ids", [])

        # Get current change
        current_change = get_current_change(request)
        if not current_change:
            raise HTTPException(status_code=400, detail="No change loaded")

        change_number = current_change.get("change_number", "")
        change_id = current_change.get("id")

        if not instance_ids:
            raise HTTPException(status_code=400, detail="No instances selected")

        # Generate the script content
        script_content = generate_post_patch_script(change_number)

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
        script_name = f"Linux QC Post - {POST_PATCH_SCRIPT['name']}"
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
                description=POST_PATCH_SCRIPT["description"],
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
                        "tool": "linux_qc_post",
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

        logger.info(f"Starting Linux QC Post validation for batch {batch_id}")
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
                "tool": "linux_qc_post",
            }
        )
        request.session["background_jobs"] = jobs

        return JSONResponse(
            {
                "status": "success",
                "batch_id": batch_id,
                "execution_count": len(executions),
            }
        )

    except Exception as e:
        logger.error(f"Error executing post validation: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


def parse_post_validation_output(output: str) -> dict:
    """Parse post-patch validation output to extract system information"""

    info = {
        "hostname": "",
        "date": "",
        "uptime": "",
        "kernel_match": False,
        "current_kernel": "",
        "expected_kernel": "",
        "yum_history": [],
        "validation_passed": False,
    }

    # Remove all ANSI escape codes from the output
    clean_output = ANSI_ESCAPE_PATTERN.sub("", output)

    lines = clean_output.split("\n")
    in_basic_info_section = False
    basic_info_line_count = 0
    
    for line in lines:
        line = line.strip()

        # Track sections based on headers
        if "=== BASIC SYSTEM INFO ===" in line:
            in_basic_info_section = True
            basic_info_line_count = 0
            continue

        # Extract hostname and date when in BASIC SYSTEM INFO section
        if in_basic_info_section and line and not line.startswith("==="):
            if basic_info_line_count == 0:
                info["hostname"] = line
            elif basic_info_line_count == 1:
                info["date"] = line
            basic_info_line_count += 1
            
            # Exit basic info section after processing a few lines
            if basic_info_line_count >= 4:
                in_basic_info_section = False

        # Extract uptime
        elif "load average:" in line:
            info["uptime"] = line

        # Check kernel match - look for PASS or FAIL
        elif "PASS: Kernel matches" in line:
            info["kernel_match"] = True
        elif "FAIL: Kernel mismatch" in line:
            info["kernel_match"] = False

        # Extract current and target kernel versions
        elif "Current:" in line:
            info["current_kernel"] = line.split("Current:", 1)[1].strip()
        elif "Target:" in line:
            info["expected_kernel"] = line.split("Target:", 1)[1].strip()

        # Extract yum history entries
        elif line and (line[0].isdigit() or line.startswith("ID")):
            # This could be a yum history line
            info["yum_history"].append(line)

    # Set overall validation passed flag
    info["validation_passed"] = info["kernel_match"] and len(info["yum_history"]) > 1

    return info


@router.get("/validation-results/{batch_id}")
async def get_validation_results(batch_id: str, db: Session = Depends(get_db)):
    """Get post-patch validation results for a specific batch"""

    executions = db.query(Execution).filter(Execution.batch_id == batch_id).all()

    if not executions:
        return JSONResponse({"status": "not_found", "results": []})

    results = []
    passed_instances = []
    failed_instances = []

    for execution in executions:
        output = execution.output or ""

        # Parse validation output
        parsed_info = parse_post_validation_output(output)

        # Categorize instances
        if parsed_info["validation_passed"]:
            passed_instances.append(
                {
                    "instance_id": execution.instance_id,
                    "account_id": execution.account_id,
                    "region": execution.region,
                    "hostname": parsed_info["hostname"],
                    "current_kernel": parsed_info["current_kernel"],
                    "date": parsed_info["date"],
                    "instance_name": (
                        execution.execution_metadata.get("instance_name", "")
                        if execution.execution_metadata
                        else ""
                    ),
                }
            )
        else:
            failed_instances.append(
                {
                    "instance_id": execution.instance_id,
                    "account_id": execution.account_id,
                    "region": execution.region,
                    "hostname": parsed_info.get("hostname", ""),
                    "kernel_match": parsed_info.get("kernel_match", False),
                    "current_kernel": parsed_info.get("current_kernel", ""),
                    "expected_kernel": parsed_info.get("expected_kernel", ""),
                    "error_reason": _get_validation_failure_reason(parsed_info),
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

    return JSONResponse(
        {
            "status": "success",
            "results": results,
            "passed_instances": passed_instances,
            "failed_instances": failed_instances,
            "total": len(results),
            "completed": sum(
                1 for r in results if r["status"] in ["completed", "failed"]
            ),
            "passed_count": len(passed_instances),
            "failed_count": len(failed_instances),
        }
    )


def _get_validation_failure_reason(parsed_info: dict) -> str:
    """Get a human-readable reason for validation failure"""
    reasons = []
    if not parsed_info.get("kernel_match", False):
        current = parsed_info.get('current_kernel', 'unknown')
        expected = parsed_info.get('expected_kernel', 'unknown')
        if current != 'unknown' or expected != 'unknown':
            reasons.append(
                f"Kernel mismatch: running {current}, expected {expected}"
            )
        else:
            reasons.append("Kernel mismatch detected")
    if (
        not parsed_info.get("yum_history")
        or len(parsed_info.get("yum_history", [])) <= 1
    ):
        reasons.append("No recent yum history found")
    return ", ".join(reasons) if reasons else "Unknown failure"


@router.post("/load-change/{change_id}")
async def load_change(change_id: int, request: Request, db: Session = Depends(get_db)):
    """Load a change and its instances"""

    change = db.query(Change).filter(Change.id == change_id).first()
    if not change:
        raise HTTPException(status_code=404, detail="Change not found")

    # Build instances list
    instances = []
    for ci in change.instances:
        instances.append(
            {
                "instance_id": ci.instance_id,
                "name": (
                    ci.instance_metadata.get("name", "") if ci.instance_metadata else ""
                ),
                "account_id": ci.account_id,
                "region": ci.region,
                "platform": ci.platform,
                "environment": "gov" if "gov" in ci.region else "com",
            }
        )

    # Store in session
    change_data = {
        "id": change.id,
        "change_number": change.change_number,
        "instances": instances,
        "selected_instances": [inst["instance_id"] for inst in instances],
    }
    set_current_change(request, change_data)

    return JSONResponse(
        {
            "status": "success",
            "change": change_data,
            "instance_count": len(instances),
        }
    )


@router.get("/list-changes")
async def list_changes(request: Request, db: Session = Depends(get_db)):
    """List available changes"""
    try:
        changes = db.query(Change).order_by(Change.created_at.desc()).limit(50).all()
        return JSONResponse(
            [
                {
                    "id": change.id,
                    "change_number": change.change_number,
                    "instance_count": len(change.instances),
                    "created_at": (
                        change.created_at.isoformat() if change.created_at else None
                    ),
                }
                for change in changes
            ]
        )
    except Exception as e:
        logger.error(f"Error listing changes: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/clear-change")
async def clear_change(request: Request):
    """Clear current change"""
    request.session.pop("current_change_id", None)
    # Also clear old keys for backwards compatibility
    request.session.pop("current_change", None)
    request.session.pop("instances", None)
    request.session.pop("selected_instances", None)
    return JSONResponse({"status": "success"})


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
            "change_number": change.change_number,
            "instances": instances,
            "selected_instances": [inst["instance_id"] for inst in instances],
        }
        set_current_change(request, change_data)

        return JSONResponse(
            {
                "status": "success",
                "change_id": change.id,
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
        csv_text = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(csv_text))

        # Process rows
        rows = list(reader)
        if not rows:
            raise ValueError("CSV file is empty")

        # Get change number from first row
        change_number = None
        instances = []

        for row in rows:
            # Try different column name variations
            cn = (
                row.get("change_number")
                or row.get("Change_number")
                or row.get("ChangeNumber")
            )
            if cn and not change_number:
                change_number = cn

            # Extract instance data
            instance_id = (
                row.get("instance_id")
                or row.get("InstanceID")
                or row.get("instance_id")
            )
            account_id = (
                row.get("account_id") or row.get("AccountID") or row.get("account_id")
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
            "change_number": change.change_number,
            "instances": instances,
            "selected_instances": [inst["instance_id"] for inst in instances],
        }
        set_current_change(request, change_data)

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
