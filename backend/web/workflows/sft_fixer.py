"""Provider-agnostic SFT (System Fix Tool) fixer workflow.

This module handles SFT (System Fix Tool) workflows using the provider abstraction
layer. It manages instance validation, script execution, and system remediation
operations across any cloud provider.

The workflow provides:
- Instance validation (connectivity, agent status)
- Arbitrary script execution for fixes/remediation
- Batch operations across multiple instances
- Predefined fix scripts for common issues

Example usage:
    # In FastAPI app setup
    from backend.web.workflows.sft_fixer import router
    app.include_router(router, prefix="/sft-fixer", tags=["sft-fixer"])

    # Client POST /sft-fixer/execute-script
    # Body: {"instance_id": "i-xxx", "script_content": "...", ...}
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.providers.base import ProviderBase
from backend.web.utils import get_authenticated_provider

router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================


class ValidateInstanceRequest(BaseModel):
    """Request model for instance validation.

    Attributes:
        instance_id: Target instance identifier.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        timeout: Maximum validation time in seconds.
    """

    instance_id: str = Field(..., description="Target instance identifier")
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    timeout: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Maximum validation time in seconds (10-300)",
    )


class ValidateInstanceResponse(BaseModel):
    """Response model for instance validation.

    Attributes:
        valid: Whether the instance is valid and reachable.
        instance_id: Target instance identifier.
        status: Validation status (reachable, unreachable, unknown).
        agent_status: Management agent status if applicable.
        message: Human-readable validation result.
    """

    valid: bool
    instance_id: str
    status: str
    agent_status: Optional[str] = None
    message: str


class BatchValidateRequest(BaseModel):
    """Request model for batch instance validation.

    Attributes:
        instance_ids: List of target instance identifiers.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        timeout: Maximum validation time per instance in seconds.
    """

    instance_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Target instance identifiers (max 50)",
    )
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    timeout: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Maximum validation time per instance in seconds (10-300)",
    )


class BatchValidateResponse(BaseModel):
    """Response model for batch instance validation.

    Attributes:
        overall_status: Aggregate status (all_valid, partial, all_invalid).
        valid_count: Number of valid instances.
        invalid_count: Number of invalid instances.
        results: Per-instance validation results.
        message: Human-readable summary message.
    """

    overall_status: str
    valid_count: int
    invalid_count: int
    results: List[Dict[str, Any]]
    message: str


class ExecuteScriptRequest(BaseModel):
    """Request model for script execution on an instance.

    Attributes:
        instance_id: Target instance identifier.
        script_content: Script content to execute.
        interpreter: Script interpreter (bash, python, powershell).
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        timeout: Maximum execution time in seconds.
    """

    instance_id: str = Field(..., description="Target instance identifier")
    script_content: str = Field(
        ...,
        min_length=1,
        description="Script content to execute",
    )
    interpreter: str = Field(
        default="bash",
        description="Script interpreter (bash, python, powershell)",
    )
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum execution time in seconds (30-3600)",
    )


class ExecuteScriptResponse(BaseModel):
    """Response model for script execution.

    Attributes:
        success: Whether the script executed successfully.
        instance_id: Target instance identifier.
        status: Execution status (success, failed, timeout).
        output: Standard output from the script execution.
        error: Error output if any.
        exit_code: Script exit code.
        message: Human-readable result message.
    """

    success: bool
    instance_id: str
    status: str
    output: Optional[str] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    message: str


class BatchExecuteScriptRequest(BaseModel):
    """Request model for batch script execution.

    Attributes:
        instance_ids: List of target instance identifiers.
        script_content: Script content to execute.
        interpreter: Script interpreter (bash, python, powershell).
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        timeout: Maximum execution time in seconds.
    """

    instance_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Target instance identifiers (max 50)",
    )
    script_content: str = Field(
        ...,
        min_length=1,
        description="Script content to execute",
    )
    interpreter: str = Field(
        default="bash",
        description="Script interpreter (bash, python, powershell)",
    )
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum execution time in seconds (30-3600)",
    )


class BatchExecuteScriptResponse(BaseModel):
    """Response model for batch script execution.

    Attributes:
        overall_status: Aggregate status (success, partial, failed).
        success_count: Number of successful executions.
        failure_count: Number of failed executions.
        results: Per-instance execution results.
        message: Human-readable summary message.
    """

    overall_status: str
    success_count: int
    failure_count: int
    results: List[Dict[str, Any]]
    message: str


class ExecuteFixRequest(BaseModel):
    """Request model for executing a predefined fix script.

    Attributes:
        instance_id: Target instance identifier.
        fix_name: Name of the predefined fix to execute.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        parameters: Optional fix-specific parameters.
        timeout: Maximum execution time in seconds.
    """

    instance_id: str = Field(..., description="Target instance identifier")
    fix_name: str = Field(..., description="Name of the predefined fix to execute")
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional fix-specific parameters",
    )
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum execution time in seconds (30-3600)",
    )


# =============================================================================
# Predefined Fix Scripts
# =============================================================================


# Available fix scripts with their content
# These are generic Linux/Windows scripts that work across providers
FIX_SCRIPTS: Dict[str, Dict[str, str]] = {
    "restart_agent": {
        "description": "Restart the management agent (SSM Agent, Azure Agent, etc.)",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Restarting Management Agent ==="

# Detect and restart appropriate agent
if command -v amazon-ssm-agent &> /dev/null; then
    echo "Restarting SSM Agent..."
    systemctl restart amazon-ssm-agent
    sleep 5
    if systemctl is-active --quiet amazon-ssm-agent; then
        echo "PASS: SSM Agent restarted successfully"
    else
        echo "FAIL: SSM Agent failed to restart"
        exit 1
    fi
elif command -v waagent &> /dev/null; then
    echo "Restarting Azure Linux Agent..."
    if systemctl restart walinuxagent 2>/dev/null; then
        sleep 5
        echo "PASS: Azure Linux Agent restarted"
    elif systemctl restart waagent 2>/dev/null; then
        sleep 5
        echo "PASS: Azure Agent restarted"
    else
        echo "FAIL: Failed to restart Azure Agent"
        exit 1
    fi
else
    echo "WARN: No recognized management agent found"
fi

echo "=== Agent Restart Complete ==="
""",
    },
    "clear_package_locks": {
        "description": "Clear stale package manager lock files",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Clearing Package Manager Locks ==="

# Clear YUM/DNF locks
if [ -f /var/run/yum.pid ]; then
    PID=$(cat /var/run/yum.pid 2>/dev/null || echo "")
    if [ -n "$PID" ] && ! ps -p "$PID" > /dev/null 2>&1; then
        echo "Removing stale yum.pid..."
        rm -f /var/run/yum.pid
        echo "PASS: Removed stale yum lock"
    else
        echo "WARN: YUM process still running or lock not stale"
    fi
else
    echo "INFO: No YUM lock file found"
fi

# Clear APT locks
if [ -f /var/lib/dpkg/lock-frontend ]; then
    if ! fuser /var/lib/dpkg/lock-frontend 2>/dev/null; then
        echo "Removing stale dpkg lock..."
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
        echo "PASS: Removed stale APT locks"
    else
        echo "WARN: DPKG lock is held by active process"
    fi
else
    echo "INFO: No APT lock file found"
fi

echo "=== Package Lock Cleanup Complete ==="
""",
    },
    "clear_tmp_space": {
        "description": "Clear temporary files to free up disk space",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Clearing Temporary Files ==="

# Show initial disk usage
echo "--- Initial Disk Usage ---"
df -h / /tmp /var/tmp 2>/dev/null || df -h /

# Clear /tmp files older than 7 days
echo "Cleaning /tmp..."
find /tmp -type f -atime +7 -delete 2>/dev/null || true
find /tmp -type d -empty -delete 2>/dev/null || true

# Clear /var/tmp files older than 7 days
echo "Cleaning /var/tmp..."
find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
find /var/tmp -type d -empty -delete 2>/dev/null || true

# Clear old log files
echo "Cleaning old logs..."
find /var/log -type f -name "*.gz" -mtime +30 -delete 2>/dev/null || true
find /var/log -type f -name "*.old" -mtime +30 -delete 2>/dev/null || true
find /var/log -type f -name "*.[0-9]" -mtime +30 -delete 2>/dev/null || true

# Clear package manager cache
echo "Cleaning package cache..."
if command -v yum &> /dev/null; then
    yum clean all 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    dnf clean all 2>/dev/null || true
elif command -v apt-get &> /dev/null; then
    apt-get clean 2>/dev/null || true
fi

# Show final disk usage
echo "--- Final Disk Usage ---"
df -h / /tmp /var/tmp 2>/dev/null || df -h /

echo "=== Temporary File Cleanup Complete ==="
""",
    },
    "repair_network": {
        "description": "Attempt to repair network connectivity issues",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Network Repair ==="

# Flush DNS cache
echo "Flushing DNS cache..."
if command -v systemd-resolve &> /dev/null; then
    systemd-resolve --flush-caches 2>/dev/null || true
    echo "PASS: Flushed systemd-resolved cache"
elif [ -f /etc/init.d/nscd ]; then
    /etc/init.d/nscd restart 2>/dev/null || true
    echo "PASS: Restarted nscd"
fi

# Restart network services
echo "Restarting network services..."
if systemctl is-active --quiet NetworkManager; then
    systemctl restart NetworkManager
    echo "PASS: Restarted NetworkManager"
elif systemctl is-active --quiet network; then
    systemctl restart network
    echo "PASS: Restarted network service"
elif systemctl is-active --quiet systemd-networkd; then
    systemctl restart systemd-networkd
    echo "PASS: Restarted systemd-networkd"
fi

# Wait for network to come up
sleep 5

# Test connectivity
echo "--- Connectivity Test ---"
if ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
    echo "PASS: External connectivity OK (8.8.8.8)"
else
    echo "WARN: External connectivity test failed"
fi

# Check default gateway
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
if [ -n "$GATEWAY" ]; then
    if ping -c 1 -W 5 "$GATEWAY" &>/dev/null; then
        echo "PASS: Gateway reachable ($GATEWAY)"
    else
        echo "FAIL: Gateway unreachable ($GATEWAY)"
    fi
else
    echo "WARN: No default gateway configured"
fi

echo "=== Network Repair Complete ==="
""",
    },
    "restart_services": {
        "description": "Restart common system services",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Restarting System Services ==="

# List of common services to restart
SERVICES=("sshd" "crond" "cron" "rsyslog" "syslog")

for service in "${SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo "Restarting $service..."
        systemctl restart "$service" 2>/dev/null && echo "PASS: $service restarted" || echo "WARN: Failed to restart $service"
    fi
done

# Check for any failed units
echo "--- Failed Units Check ---"
FAILED=$(systemctl --failed --no-pager --no-legend 2>/dev/null | wc -l || echo "0")
if [ "$FAILED" -gt 0 ]; then
    echo "WARN: $FAILED failed systemd units"
    systemctl --failed --no-pager 2>/dev/null | head -5
else
    echo "PASS: No failed systemd units"
fi

echo "=== Service Restart Complete ==="
""",
    },
    "check_and_fix_time": {
        "description": "Check and synchronize system time with NTP",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Time Synchronization Check ==="

# Current time
echo "Current system time: $(date)"

# Check NTP sync status
echo "--- NTP Status ---"
if command -v timedatectl &> /dev/null; then
    timedatectl status 2>/dev/null || true

    # Check if NTP is synchronized
    if timedatectl status 2>/dev/null | grep -q "NTP synchronized: yes"; then
        echo "PASS: NTP is synchronized"
    else
        echo "Attempting to enable NTP..."
        timedatectl set-ntp true 2>/dev/null || true
        systemctl restart chronyd 2>/dev/null || systemctl restart ntpd 2>/dev/null || systemctl restart systemd-timesyncd 2>/dev/null || true
        sleep 5
        if timedatectl status 2>/dev/null | grep -q "NTP synchronized: yes"; then
            echo "PASS: NTP now synchronized"
        else
            echo "WARN: NTP synchronization may still be in progress"
        fi
    fi
elif command -v ntpstat &> /dev/null; then
    ntpstat 2>/dev/null && echo "PASS: NTP synchronized" || echo "WARN: NTP not synchronized"
fi

# Show final time
echo "Final system time: $(date)"

echo "=== Time Synchronization Complete ==="
""",
    },
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_fix_script(fix_name: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Get the script content for a predefined fix.

    Args:
        fix_name: Fix script identifier.
        parameters: Optional parameters to customize the script.

    Returns:
        Dictionary with 'script' and 'interpreter' keys.

    Raises:
        HTTPException: 400 if fix is not found.
    """
    if fix_name not in FIX_SCRIPTS:
        available_fixes = list(FIX_SCRIPTS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unknown fix: '{fix_name}'. Available fixes: {available_fixes}",
        )

    fix_config = FIX_SCRIPTS[fix_name]
    script_content = fix_config["script"]

    # Apply any parameter substitutions if provided
    if parameters:
        for key, value in parameters.items():
            placeholder = f"${{{key}}}"
            script_content = script_content.replace(placeholder, str(value))

    return {
        "script": script_content,
        "interpreter": fix_config["interpreter"],
    }


# Validation script to check instance reachability
VALIDATION_SCRIPT = """#!/bin/bash
echo "=== Instance Validation ==="

# Check basic system info
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
echo "Kernel: $(uname -r)"

# Check agent status
if command -v amazon-ssm-agent &> /dev/null; then
    if systemctl is-active --quiet amazon-ssm-agent; then
        echo "Agent: SSM Agent (running)"
    else
        echo "Agent: SSM Agent (not running)"
    fi
elif command -v waagent &> /dev/null; then
    if systemctl is-active --quiet walinuxagent 2>/dev/null || systemctl is-active --quiet waagent 2>/dev/null; then
        echo "Agent: Azure Linux Agent (running)"
    else
        echo "Agent: Azure Linux Agent (not running)"
    fi
else
    echo "Agent: None detected"
fi

echo "=== Instance Validation Complete ==="
"""


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("/fixes")
async def list_fixes() -> Dict[str, Any]:
    """List available predefined fix scripts.

    Returns a list of all available fix scripts with their descriptions.
    These fixes can be executed on instances for common remediation tasks.

    Returns:
        Dictionary with available fixes and their descriptions.
    """
    fixes = {
        fix_name: {
            "description": fix_config["description"],
            "interpreter": fix_config["interpreter"],
        }
        for fix_name, fix_config in FIX_SCRIPTS.items()
    }

    return {
        "fixes": fixes,
        "count": len(fixes),
    }


@router.post("/validate-instance", response_model=ValidateInstanceResponse)
async def validate_instance(
    request: Request,
    validation_request: ValidateInstanceRequest,
) -> ValidateInstanceResponse:
    """Validate a single instance for connectivity and readiness.

    Checks if the instance is reachable and has a responsive management agent.
    This is a prerequisite check before running fix operations.

    Args:
        request: FastAPI request object for session access.
        validation_request: Instance validation request details.

    Returns:
        ValidateInstanceResponse with validation results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if validation fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    try:
        result = await provider.execute_script(
            instance_id=validation_request.instance_id,
            script_content=VALIDATION_SCRIPT,
            interpreter="bash",
            account_id=validation_request.account_id,
            region=validation_request.region,
            timeout=validation_request.timeout,
        )

        valid = result.get("status") == "success" and result.get("exit_code", 1) == 0
        output = result.get("output", "")

        # Parse agent status from output
        agent_status = "unknown"
        if "running" in output.lower():
            agent_status = "running"
        elif "not running" in output.lower():
            agent_status = "not_running"
        elif "none detected" in output.lower():
            agent_status = "none"

        return ValidateInstanceResponse(
            valid=valid,
            instance_id=validation_request.instance_id,
            status="reachable" if valid else "unreachable",
            agent_status=agent_status,
            message=f"Instance {validation_request.instance_id} is {'valid and reachable' if valid else 'not reachable'}",
        )

    except NotImplementedError as e:
        return ValidateInstanceResponse(
            valid=False,
            instance_id=validation_request.instance_id,
            status="not_implemented",
            agent_status=None,
            message=f"Instance validation not yet implemented for this provider: {e!s}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to validate instance: {e!s}",
        )


@router.post("/validate-batch", response_model=BatchValidateResponse)
async def validate_instances_batch(
    request: Request,
    batch_request: BatchValidateRequest,
) -> BatchValidateResponse:
    """Validate multiple instances for connectivity and readiness.

    Checks if instances are reachable and have responsive management agents.
    Uses batch execution for efficiency.

    Args:
        request: FastAPI request object for session access.
        batch_request: Batch validation request details.

    Returns:
        BatchValidateResponse with aggregated validation results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if validation fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    try:
        result = await provider.execute_script_batch(
            instance_ids=batch_request.instance_ids,
            script_content=VALIDATION_SCRIPT,
            interpreter="bash",
            account_id=batch_request.account_id,
            region=batch_request.region,
            timeout=batch_request.timeout,
        )

        valid_count = 0
        invalid_count = 0
        results = []

        for instance_result in result.get("results", []):
            instance_id = instance_result.get("instance_id")
            valid = (
                instance_result.get("status") == "success"
                and instance_result.get("exit_code", 1) == 0
            )

            if valid:
                valid_count += 1
            else:
                invalid_count += 1

            results.append({
                "instance_id": instance_id,
                "valid": valid,
                "status": "reachable" if valid else "unreachable",
                "error": instance_result.get("error") if not valid else None,
            })

        # Determine overall status
        if valid_count == len(batch_request.instance_ids):
            overall_status = "all_valid"
        elif invalid_count == len(batch_request.instance_ids):
            overall_status = "all_invalid"
        else:
            overall_status = "partial"

        return BatchValidateResponse(
            overall_status=overall_status,
            valid_count=valid_count,
            invalid_count=invalid_count,
            results=results,
            message=f"Validated {len(batch_request.instance_ids)} instances: "
            f"{valid_count} valid, {invalid_count} invalid",
        )

    except NotImplementedError as e:
        return BatchValidateResponse(
            overall_status="not_implemented",
            valid_count=0,
            invalid_count=len(batch_request.instance_ids),
            results=[
                {"instance_id": iid, "valid": False, "status": "not_implemented", "error": str(e)}
                for iid in batch_request.instance_ids
            ],
            message="Batch instance validation not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to validate instances: {e!s}",
        )


@router.post("/execute-script", response_model=ExecuteScriptResponse)
async def execute_script(
    request: Request,
    script_request: ExecuteScriptRequest,
) -> ExecuteScriptResponse:
    """Execute a custom script on a single instance.

    Executes the provided script content on the target instance using
    the provider's script execution capability (SSM, Run Command, etc.).

    Args:
        request: FastAPI request object for session access.
        script_request: Script execution request details.

    Returns:
        ExecuteScriptResponse with execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    try:
        result = await provider.execute_script(
            instance_id=script_request.instance_id,
            script_content=script_request.script_content,
            interpreter=script_request.interpreter,
            account_id=script_request.account_id,
            region=script_request.region,
            timeout=script_request.timeout,
        )

        success = result.get("status") == "success" and result.get("exit_code", 1) == 0

        return ExecuteScriptResponse(
            success=success,
            instance_id=script_request.instance_id,
            status=result.get("status", "unknown"),
            output=result.get("output"),
            error=result.get("error"),
            exit_code=result.get("exit_code"),
            message=f"Script execution {'completed successfully' if success else 'failed'}",
        )

    except NotImplementedError as e:
        return ExecuteScriptResponse(
            success=False,
            instance_id=script_request.instance_id,
            status="not_implemented",
            output=None,
            error=str(e),
            exit_code=None,
            message="Script execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute script: {e!s}",
        )


@router.post("/execute-script-batch", response_model=BatchExecuteScriptResponse)
async def execute_script_batch(
    request: Request,
    batch_request: BatchExecuteScriptRequest,
) -> BatchExecuteScriptResponse:
    """Execute a custom script on multiple instances.

    Executes the provided script content on all target instances using
    the provider's batch execution capability for efficiency.

    Args:
        request: FastAPI request object for session access.
        batch_request: Batch script execution request details.

    Returns:
        BatchExecuteScriptResponse with aggregated execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    try:
        result = await provider.execute_script_batch(
            instance_ids=batch_request.instance_ids,
            script_content=batch_request.script_content,
            interpreter=batch_request.interpreter,
            account_id=batch_request.account_id,
            region=batch_request.region,
            timeout=batch_request.timeout,
        )

        overall_status = result.get("overall_status", "unknown")
        success_count = result.get("success_count", 0)
        failure_count = result.get("failure_count", 0)
        results = result.get("results", [])

        return BatchExecuteScriptResponse(
            overall_status=overall_status,
            success_count=success_count,
            failure_count=failure_count,
            results=results,
            message=f"Script executed on {len(batch_request.instance_ids)} instances: "
            f"{success_count} succeeded, {failure_count} failed",
        )

    except NotImplementedError as e:
        return BatchExecuteScriptResponse(
            overall_status="not_implemented",
            success_count=0,
            failure_count=len(batch_request.instance_ids),
            results=[
                {"instance_id": iid, "status": "not_implemented", "error": str(e)}
                for iid in batch_request.instance_ids
            ],
            message="Batch script execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute batch script: {e!s}",
        )


@router.post("/execute-fix", response_model=ExecuteScriptResponse)
async def execute_fix(
    request: Request,
    fix_request: ExecuteFixRequest,
) -> ExecuteScriptResponse:
    """Execute a predefined fix script on a single instance.

    Executes the specified predefined fix script on the target instance.
    Use /fixes endpoint to list available fix scripts.

    Args:
        request: FastAPI request object for session access.
        fix_request: Fix execution request details.

    Returns:
        ExecuteScriptResponse with execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if fix is invalid.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Get the fix script
    fix_config = get_fix_script(fix_request.fix_name, fix_request.parameters)

    try:
        result = await provider.execute_script(
            instance_id=fix_request.instance_id,
            script_content=fix_config["script"],
            interpreter=fix_config["interpreter"],
            account_id=fix_request.account_id,
            region=fix_request.region,
            timeout=fix_request.timeout,
        )

        success = result.get("status") == "success" and result.get("exit_code", 1) == 0

        return ExecuteScriptResponse(
            success=success,
            instance_id=fix_request.instance_id,
            status=result.get("status", "unknown"),
            output=result.get("output"),
            error=result.get("error"),
            exit_code=result.get("exit_code"),
            message=f"Fix '{fix_request.fix_name}' {'completed successfully' if success else 'failed'}",
        )

    except NotImplementedError as e:
        return ExecuteScriptResponse(
            success=False,
            instance_id=fix_request.instance_id,
            status="not_implemented",
            output=None,
            error=str(e),
            exit_code=None,
            message="Fix execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute fix: {e!s}",
        )
