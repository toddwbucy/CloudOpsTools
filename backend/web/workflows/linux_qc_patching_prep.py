"""Provider-agnostic Linux QC patching preparation workflow.

This module handles Linux QC (Quality Control) patching preparation workflows
using the provider abstraction layer. It manages pre-patching validation,
instance readiness checks, and QC step execution across any cloud provider.

The workflow validates instances before patching to ensure:
- SSM/equivalent agent is responsive
- Required disk space is available
- No blocking processes are running
- System state is suitable for patching

Example usage:
    # In FastAPI app setup
    from backend.web.workflows.linux_qc_patching_prep import router
    app.include_router(router, prefix="/linux-qc-prep", tags=["linux-qc-prep"])

    # Client POST /linux-qc-prep/execute-step
    # Body: {"instance_id": "i-xxx", "step": "check_disk_space", ...}
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


class ExecuteQCStepRequest(BaseModel):
    """Request model for executing a QC preparation step.

    Attributes:
        instance_id: Target instance identifier.
        step: QC step to execute (e.g., "check_disk_space", "verify_agent").
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        parameters: Optional step-specific parameters.
        timeout: Maximum execution time in seconds.
    """

    instance_id: str = Field(..., description="Target instance identifier")
    step: str = Field(..., description="QC step to execute")
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional step-specific parameters",
    )
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum execution time in seconds (30-3600)",
    )


class ExecuteQCStepResponse(BaseModel):
    """Response model for QC step execution.

    Attributes:
        success: Whether the step executed successfully.
        instance_id: Target instance identifier.
        step: QC step that was executed.
        status: Execution status (success, failed, timeout).
        output: Standard output from the step execution.
        error: Error output if any.
        exit_code: Script exit code.
        message: Human-readable result message.
    """

    success: bool
    instance_id: str
    step: str
    status: str
    output: Optional[str] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    message: str


class BatchExecuteRequest(BaseModel):
    """Request model for batch QC step execution.

    Attributes:
        instance_ids: List of target instance identifiers.
        step: QC step to execute on all instances.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
        parameters: Optional step-specific parameters.
        timeout: Maximum execution time in seconds.
    """

    instance_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Target instance identifiers (max 50)",
    )
    step: str = Field(..., description="QC step to execute")
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional step-specific parameters",
    )
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum execution time in seconds (30-3600)",
    )


class BatchExecuteResponse(BaseModel):
    """Response model for batch QC step execution.

    Attributes:
        overall_status: Aggregate status (success, partial, failed).
        step: QC step that was executed.
        success_count: Number of successful executions.
        failure_count: Number of failed executions.
        results: Per-instance execution results.
        message: Human-readable summary message.
    """

    overall_status: str
    step: str
    success_count: int
    failure_count: int
    results: List[Dict[str, Any]]
    message: str


class InstanceReadinessRequest(BaseModel):
    """Request model for checking instance readiness.

    Attributes:
        instance_ids: List of instance identifiers to check.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
    """

    instance_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Instance identifiers to check (max 50)",
    )
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")


class InstanceReadinessResponse(BaseModel):
    """Response model for instance readiness check.

    Attributes:
        ready_instances: List of instances ready for patching.
        not_ready_instances: List of instances not ready with reasons.
        message: Human-readable summary.
    """

    ready_instances: List[str]
    not_ready_instances: List[Dict[str, Any]]
    message: str


# =============================================================================
# QC Step Definitions
# =============================================================================


# Available QC steps with their script content
# These are generic Linux scripts that work across providers
QC_STEPS: Dict[str, Dict[str, str]] = {
    "check_disk_space": {
        "description": "Check available disk space on root and var partitions",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

# Check disk space thresholds
MIN_ROOT_GB=5
MIN_VAR_GB=2

check_disk() {
    local mount=$1
    local min_gb=$2
    local available_kb=$(df "$mount" | tail -1 | awk '{print $4}')
    local available_gb=$((available_kb / 1024 / 1024))

    if [ "$available_gb" -lt "$min_gb" ]; then
        echo "FAIL: $mount has ${available_gb}GB free, requires ${min_gb}GB"
        return 1
    else
        echo "PASS: $mount has ${available_gb}GB free"
        return 0
    fi
}

echo "=== Disk Space Check ==="
check_disk "/" $MIN_ROOT_GB
check_disk "/var" $MIN_VAR_GB 2>/dev/null || check_disk "/" $MIN_VAR_GB

echo "=== Disk Space Check Complete ==="
""",
    },
    "verify_agent": {
        "description": "Verify management agent is running and responsive",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Agent Verification ==="

# Check for common management agents
if command -v amazon-ssm-agent &> /dev/null; then
    if systemctl is-active --quiet amazon-ssm-agent; then
        echo "PASS: SSM Agent is running"
    else
        echo "FAIL: SSM Agent is not running"
        exit 1
    fi
elif command -v waagent &> /dev/null; then
    if systemctl is-active --quiet walinuxagent 2>/dev/null || systemctl is-active --quiet waagent 2>/dev/null; then
        echo "PASS: Azure Linux Agent is running"
    else
        echo "FAIL: Azure Linux Agent is not running"
        exit 1
    fi
else
    echo "WARN: No recognized management agent found"
fi

echo "=== Agent Verification Complete ==="
""",
    },
    "check_running_processes": {
        "description": "Check for blocking processes that prevent patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Process Check ==="

# Check for package manager locks
BLOCKING_PROCESSES=("yum" "dn" "apt" "dpkg" "rpm" "zypper")
FOUND_BLOCKING=0

for proc in "${BLOCKING_PROCESSES[@]}"; do
    if pgrep -x "$proc" > /dev/null 2>&1; then
        echo "WARN: $proc is currently running"
        FOUND_BLOCKING=1
    fi
done

# Check for lock files
if [ -f /var/run/yum.pid ]; then
    echo "WARN: YUM lock file exists"
    FOUND_BLOCKING=1
fi

if [ -f /var/lib/dpkg/lock-frontend ]; then
    if fuser /var/lib/dpkg/lock-frontend 2>/dev/null; then
        echo "WARN: DPKG lock is held"
        FOUND_BLOCKING=1
    fi
fi

if [ $FOUND_BLOCKING -eq 0 ]; then
    echo "PASS: No blocking processes found"
else
    echo "FAIL: Blocking processes detected"
    exit 1
fi

echo "=== Process Check Complete ==="
""",
    },
    "check_system_health": {
        "description": "Check overall system health indicators",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== System Health Check ==="

# Check system load
LOAD=$(cat /proc/loadavg | awk '{print $1}')
CPUS=$(nproc)
LOAD_THRESHOLD=$((CPUS * 2))
LOAD_INT=${LOAD%.*}

if [ "$LOAD_INT" -gt "$LOAD_THRESHOLD" ]; then
    echo "WARN: High system load: $LOAD (threshold: $LOAD_THRESHOLD)"
else
    echo "PASS: System load acceptable: $LOAD"
fi

# Check memory
MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_PERCENT=$((MEM_AVAILABLE * 100 / MEM_TOTAL))

if [ "$MEM_PERCENT" -lt 10 ]; then
    echo "FAIL: Low memory: ${MEM_PERCENT}% available"
    exit 1
else
    echo "PASS: Memory available: ${MEM_PERCENT}%"
fi

# Check uptime (ensure system has been up for at least 5 minutes)
UPTIME_SECONDS=$(cat /proc/uptime | awk '{print int($1)}')
if [ "$UPTIME_SECONDS" -lt 300 ]; then
    echo "WARN: System recently rebooted (uptime: ${UPTIME_SECONDS}s)"
else
    echo "PASS: System uptime: ${UPTIME_SECONDS}s"
fi

echo "=== System Health Check Complete ==="
""",
    },
    "pre_patch_snapshot": {
        "description": "Capture system state before patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Pre-Patch Snapshot ==="

# Capture package list
echo "--- Installed Packages ---"
if command -v rpm &> /dev/null; then
    rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' | head -50
elif command -v dpkg &> /dev/null; then
    dpkg -l | grep '^ii' | awk '{print $2"-"$3}' | head -50
fi
echo "(truncated to 50 packages)"

# Capture kernel version
echo "--- Kernel Version ---"
uname -r

# Capture running services
echo "--- Running Services ---"
systemctl list-units --type=service --state=running --no-pager | head -20

echo "=== Pre-Patch Snapshot Complete ==="
""",
    },
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_qc_step_script(step: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Get the script content for a QC step.

    Args:
        step: QC step identifier.
        parameters: Optional parameters to customize the script.

    Returns:
        Dictionary with 'script' and 'interpreter' keys.

    Raises:
        HTTPException: 400 if step is not found.
    """
    if step not in QC_STEPS:
        available_steps = list(QC_STEPS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unknown QC step: '{step}'. Available steps: {available_steps}",
        )

    step_config = QC_STEPS[step]
    script_content = step_config["script"]

    # Apply any parameter substitutions if provided
    if parameters:
        for key, value in parameters.items():
            placeholder = f"${{{key}}}"
            script_content = script_content.replace(placeholder, str(value))

    return {
        "script": script_content,
        "interpreter": step_config["interpreter"],
    }


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("/steps")
async def list_qc_steps() -> Dict[str, Any]:
    """List available QC preparation steps.

    Returns a list of all available QC steps with their descriptions.
    These steps can be executed on instances to prepare for patching.

    Returns:
        Dictionary with available steps and their descriptions.
    """
    steps = {
        step_name: {
            "description": step_config["description"],
            "interpreter": step_config["interpreter"],
        }
        for step_name, step_config in QC_STEPS.items()
    }

    return {
        "steps": steps,
        "count": len(steps),
    }


@router.post("/execute-step", response_model=ExecuteQCStepResponse)
async def execute_qc_step(
    request: Request,
    step_request: ExecuteQCStepRequest,
) -> ExecuteQCStepResponse:
    """Execute a QC preparation step on a single instance.

    Executes the specified QC step script on the target instance using
    the provider's script execution capability (SSM, Run Command, etc.).

    Args:
        request: FastAPI request object for session access.
        step_request: QC step execution request details.

    Returns:
        ExecuteQCStepResponse with execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if step is invalid.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Get the script for this step
    step_config = get_qc_step_script(step_request.step, step_request.parameters)

    try:
        result = await provider.execute_script(
            instance_id=step_request.instance_id,
            script_content=step_config["script"],
            interpreter=step_config["interpreter"],
            account_id=step_request.account_id,
            region=step_request.region,
            timeout=step_request.timeout,
        )

        success = result.get("status") == "success" and result.get("exit_code", 1) == 0

        return ExecuteQCStepResponse(
            success=success,
            instance_id=step_request.instance_id,
            step=step_request.step,
            status=result.get("status", "unknown"),
            output=result.get("output"),
            error=result.get("error"),
            exit_code=result.get("exit_code"),
            message=f"QC step '{step_request.step}' {'completed successfully' if success else 'failed'}",
        )

    except NotImplementedError as e:
        # Provider method not yet implemented
        return ExecuteQCStepResponse(
            success=False,
            instance_id=step_request.instance_id,
            step=step_request.step,
            status="not_implemented",
            output=None,
            error=str(e),
            exit_code=None,
            message="QC step execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute QC step: {e!s}",
        )


@router.post("/execute-batch", response_model=BatchExecuteResponse)
async def execute_qc_step_batch(
    request: Request,
    batch_request: BatchExecuteRequest,
) -> BatchExecuteResponse:
    """Execute a QC preparation step on multiple instances.

    Executes the specified QC step script on all target instances using
    the provider's batch execution capability for efficiency.

    Args:
        request: FastAPI request object for session access.
        batch_request: Batch QC step execution request details.

    Returns:
        BatchExecuteResponse with aggregated execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if step is invalid.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Get the script for this step
    step_config = get_qc_step_script(batch_request.step, batch_request.parameters)

    try:
        result = await provider.execute_script_batch(
            instance_ids=batch_request.instance_ids,
            script_content=step_config["script"],
            interpreter=step_config["interpreter"],
            account_id=batch_request.account_id,
            region=batch_request.region,
            timeout=batch_request.timeout,
        )

        overall_status = result.get("overall_status", "unknown")
        success_count = result.get("success_count", 0)
        failure_count = result.get("failure_count", 0)
        results = result.get("results", [])

        return BatchExecuteResponse(
            overall_status=overall_status,
            step=batch_request.step,
            success_count=success_count,
            failure_count=failure_count,
            results=results,
            message=f"QC step '{batch_request.step}' executed on {len(batch_request.instance_ids)} instances: "
            f"{success_count} succeeded, {failure_count} failed",
        )

    except NotImplementedError as e:
        # Provider method not yet implemented
        return BatchExecuteResponse(
            overall_status="not_implemented",
            step=batch_request.step,
            success_count=0,
            failure_count=len(batch_request.instance_ids),
            results=[
                {"instance_id": iid, "status": "not_implemented", "error": str(e)}
                for iid in batch_request.instance_ids
            ],
            message="Batch QC step execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute batch QC step: {e!s}",
        )


@router.post("/check-readiness", response_model=InstanceReadinessResponse)
async def check_instance_readiness(
    request: Request,
    readiness_request: InstanceReadinessRequest,
) -> InstanceReadinessResponse:
    """Check if instances are ready for patching.

    Runs a series of readiness checks on the specified instances to verify
    they are in a suitable state for patching operations.

    Args:
        request: FastAPI request object for session access.
        readiness_request: Readiness check request details.

    Returns:
        InstanceReadinessResponse with ready and not-ready instance lists.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if check fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Use verify_agent step for readiness check
    step_config = get_qc_step_script("verify_agent")

    ready_instances: List[str] = []
    not_ready_instances: List[Dict[str, Any]] = []

    try:
        result = await provider.execute_script_batch(
            instance_ids=readiness_request.instance_ids,
            script_content=step_config["script"],
            interpreter=step_config["interpreter"],
            account_id=readiness_request.account_id,
            region=readiness_request.region,
            timeout=60,  # Shorter timeout for readiness check
        )

        for instance_result in result.get("results", []):
            instance_id = instance_result.get("instance_id")
            if instance_result.get("status") == "success" and instance_result.get("exit_code", 1) == 0:
                ready_instances.append(instance_id)
            else:
                not_ready_instances.append({
                    "instance_id": instance_id,
                    "reason": instance_result.get("error") or "Agent check failed",
                    "status": instance_result.get("status"),
                })

    except NotImplementedError:
        # Mark all as not ready when not implemented
        not_ready_instances = [
            {
                "instance_id": iid,
                "reason": "Readiness check not yet implemented for this provider",
                "status": "not_implemented",
            }
            for iid in readiness_request.instance_ids
        ]

    total = len(readiness_request.instance_ids)
    ready_count = len(ready_instances)
    not_ready_count = len(not_ready_instances)

    return InstanceReadinessResponse(
        ready_instances=ready_instances,
        not_ready_instances=not_ready_instances,
        message=f"{ready_count}/{total} instances ready for patching"
        + (f", {not_ready_count} not ready" if not_ready_count else ""),
    )


@router.post("/run-all-checks")
async def run_all_qc_checks(
    request: Request,
    step_request: ExecuteQCStepRequest,
) -> Dict[str, Any]:
    """Run all QC preparation checks on a single instance.

    Executes all available QC steps sequentially on the target instance
    and returns a comprehensive readiness report.

    Args:
        request: FastAPI request object for session access.
        step_request: Base request with instance and account details.

    Returns:
        Dictionary with results from all QC checks.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if checks fail unexpectedly.
    """
    provider = get_authenticated_provider(request)

    all_results: Dict[str, Any] = {
        "instance_id": step_request.instance_id,
        "checks": {},
        "overall_ready": True,
        "summary": [],
    }

    # Run each QC step
    for step_name in QC_STEPS.keys():
        step_config = get_qc_step_script(step_name)

        try:
            result = await provider.execute_script(
                instance_id=step_request.instance_id,
                script_content=step_config["script"],
                interpreter=step_config["interpreter"],
                account_id=step_request.account_id,
                region=step_request.region,
                timeout=step_request.timeout,
            )

            success = result.get("status") == "success" and result.get("exit_code", 1) == 0
            all_results["checks"][step_name] = {
                "success": success,
                "output": result.get("output"),
                "error": result.get("error"),
                "exit_code": result.get("exit_code"),
            }

            if not success:
                all_results["overall_ready"] = False
                all_results["summary"].append(f"{step_name}: FAILED")
            else:
                all_results["summary"].append(f"{step_name}: PASSED")

        except NotImplementedError:
            all_results["checks"][step_name] = {
                "success": False,
                "error": "Not implemented",
            }
            all_results["overall_ready"] = False
            all_results["summary"].append(f"{step_name}: NOT IMPLEMENTED")

        except Exception as e:
            all_results["checks"][step_name] = {
                "success": False,
                "error": str(e),
            }
            all_results["overall_ready"] = False
            all_results["summary"].append(f"{step_name}: ERROR - {e!s}")

    all_results["message"] = (
        "Instance is ready for patching"
        if all_results["overall_ready"]
        else "Instance has failed one or more readiness checks"
    )

    return all_results
