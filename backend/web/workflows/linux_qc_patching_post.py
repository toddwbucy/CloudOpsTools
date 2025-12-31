"""Provider-agnostic Linux QC patching post-validation workflow.

This module handles Linux QC (Quality Control) post-patching validation workflows
using the provider abstraction layer. It manages post-patching verification,
service health checks, and validation across any cloud provider.

The workflow validates instances after patching to ensure:
- System is back online and responsive
- Critical services are running
- Kernel and packages were updated correctly
- System state is healthy post-patch

Example usage:
    # In FastAPI app setup
    from backend.web.workflows.linux_qc_patching_post import router
    app.include_router(router, prefix="/linux-qc-post", tags=["linux-qc-post"])

    # Client POST /linux-qc-post/execute-step
    # Body: {"instance_id": "i-xxx", "step": "verify_services", ...}
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.providers.base import ProviderBase
from backend.web.utils import get_authenticated_provider, safe_substitute_parameters

router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================


class ExecutePostQCStepRequest(BaseModel):
    """Request model for executing a post-patching QC step.

    Attributes:
        instance_id: Target instance identifier.
        step: QC step to execute (e.g., "verify_services", "check_reboot_status").
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


class ExecutePostQCStepResponse(BaseModel):
    """Response model for post-patching QC step execution.

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


class BatchPostQCExecuteRequest(BaseModel):
    """Request model for batch post-patching QC step execution.

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


class BatchPostQCExecuteResponse(BaseModel):
    """Response model for batch post-patching QC step execution.

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


class PostPatchValidationRequest(BaseModel):
    """Request model for comprehensive post-patch validation.

    Attributes:
        instance_ids: List of instance identifiers to validate.
        account_id: Provider account/subscription identifier.
        region: Target region for the operation.
    """

    instance_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Instance identifiers to validate (max 50)",
    )
    account_id: str = Field(..., description="Provider account identifier")
    region: str = Field(..., description="Target region")


class PostPatchValidationResponse(BaseModel):
    """Response model for post-patch validation.

    Attributes:
        validated_instances: List of instances that passed validation.
        failed_instances: List of instances that failed with reasons.
        message: Human-readable summary.
    """

    validated_instances: List[str]
    failed_instances: List[Dict[str, Any]]
    message: str


# =============================================================================
# Post-Patching QC Step Definitions
# =============================================================================


# Available post-patching QC steps with their script content
# These are generic Linux scripts that work across providers
POST_QC_STEPS: Dict[str, Dict[str, str]] = {
    "verify_reboot": {
        "description": "Verify system has rebooted if required and is responding",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Reboot Verification ==="

# Check uptime to see if system recently rebooted
UPTIME_SECONDS=$(cat /proc/uptime | awk '{print int($1)}')
UPTIME_HOURS=$((UPTIME_SECONDS / 3600))

echo "System uptime: ${UPTIME_SECONDS} seconds (${UPTIME_HOURS} hours)"

# Check if there are pending reboots
if [ -f /var/run/reboot-required ]; then
    echo "WARN: Reboot still required"
    cat /var/run/reboot-required 2>/dev/null || true
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
else
    echo "PASS: No pending reboot required"
fi

# Check boot time
BOOT_TIME=$(who -b 2>/dev/null | awk '{print $3, $4}' || uptime -s 2>/dev/null || echo "unknown")
echo "Last boot: $BOOT_TIME"

echo "=== Reboot Verification Complete ==="
""",
    },
    "verify_services": {
        "description": "Verify critical services are running after patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Service Verification ==="

# List of critical services to check
CRITICAL_SERVICES=("sshd" "systemd-journald" "dbus")
FAILED_SERVICES=()

for service in "${CRITICAL_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "PASS: $service is running"
    elif systemctl is-active --quiet "${service}.service" 2>/dev/null; then
        echo "PASS: ${service}.service is running"
    else
        echo "FAIL: $service is not running"
        FAILED_SERVICES+=("$service")
    fi
done

# Check management agent
if command -v amazon-ssm-agent &> /dev/null; then
    if systemctl is-active --quiet amazon-ssm-agent; then
        echo "PASS: SSM Agent is running"
    else
        echo "WARN: SSM Agent is not running"
        FAILED_SERVICES+=("amazon-ssm-agent")
    fi
elif command -v waagent &> /dev/null; then
    if systemctl is-active --quiet walinuxagent 2>/dev/null || systemctl is-active --quiet waagent 2>/dev/null; then
        echo "PASS: Azure Linux Agent is running"
    else
        echo "WARN: Azure Linux Agent is not running"
        FAILED_SERVICES+=("waagent")
    fi
fi

# Check for failed systemd units
FAILED_UNITS=$(systemctl --failed --no-pager --no-legend 2>/dev/null | wc -l || echo "0")
if [ "$FAILED_UNITS" -gt 0 ]; then
    echo "WARN: $FAILED_UNITS failed systemd units detected"
    systemctl --failed --no-pager 2>/dev/null | head -10 || true
else
    echo "PASS: No failed systemd units"
fi

if [ ${#FAILED_SERVICES[@]} -eq 0 ]; then
    echo "PASS: All critical services running"
else
    echo "FAIL: Some services not running: ${FAILED_SERVICES[*]}"
    exit 1
fi

echo "=== Service Verification Complete ==="
""",
    },
    "verify_kernel": {
        "description": "Verify kernel version after patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Kernel Verification ==="

# Current running kernel
CURRENT_KERNEL=$(uname -r)
echo "Running kernel: $CURRENT_KERNEL"

# Check for installed kernels
echo "--- Installed Kernels ---"
if command -v rpm &> /dev/null; then
    rpm -qa kernel* 2>/dev/null | sort || echo "No kernel packages found via rpm"
elif command -v dpkg &> /dev/null; then
    dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2"-"$3}' || echo "No kernel packages found via dpkg"
fi

# Check for latest installed kernel
echo "--- Latest Available Kernel ---"
if command -v rpm &> /dev/null; then
    LATEST_KERNEL=$(rpm -qa 'kernel-[0-9]*' --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\\n' 2>/dev/null | sort -V | tail -1 || echo "unknown")
    echo "Latest installed: $LATEST_KERNEL"
elif command -v dpkg &> /dev/null; then
    LATEST_KERNEL=$(dpkg -l 'linux-image-[0-9]*' 2>/dev/null | grep '^ii' | awk '{print $2}' | sort -V | tail -1 || echo "unknown")
    echo "Latest installed: $LATEST_KERNEL"
fi

# Check if reboot is needed for new kernel
if [ -f /var/run/reboot-required ]; then
    if grep -q "linux" /var/run/reboot-required.pkgs 2>/dev/null; then
        echo "WARN: Reboot required for new kernel"
    fi
fi

echo "=== Kernel Verification Complete ==="
""",
    },
    "verify_packages": {
        "description": "Verify packages were updated successfully",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Package Verification ==="

# Check package manager status
echo "--- Package Manager Status ---"
if command -v yum &> /dev/null; then
    echo "Package manager: yum"
    yum check 2>/dev/null || echo "WARN: yum check found issues"

    # Check for available updates
    UPDATES=$(yum check-update 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
    echo "Pending updates: $UPDATES packages"

elif command -v dnf &> /dev/null; then
    echo "Package manager: dn"

    # Check for available updates
    UPDATES=$(dnf check-update -q 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
    echo "Pending updates: $UPDATES packages"

elif command -v apt &> /dev/null; then
    echo "Package manager: apt"
    apt-get check 2>/dev/null || echo "WARN: apt check found issues"

    # Update cache to check for updates
    apt-get update -qq 2>/dev/null || true
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
    echo "Pending updates: $UPDATES packages"
fi

# Check for broken packages
echo "--- Package Integrity ---"
if command -v rpm &> /dev/null; then
    BROKEN=$(rpm -Va 2>/dev/null | grep -c "^..5" || echo "0")
    if [ "$BROKEN" -gt 0 ]; then
        echo "WARN: $BROKEN packages with modified checksums"
    else
        echo "PASS: No package integrity issues"
    fi
elif command -v dpkg &> /dev/null; then
    BROKEN=$(dpkg --audit 2>/dev/null | wc -l || echo "0")
    if [ "$BROKEN" -gt 0 ]; then
        echo "WARN: $BROKEN packages with issues"
    else
        echo "PASS: No package integrity issues"
    fi
fi

echo "=== Package Verification Complete ==="
""",
    },
    "post_patch_snapshot": {
        "description": "Capture system state after patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Post-Patch Snapshot ==="

# Capture current package list
echo "--- Currently Installed Packages ---"
if command -v rpm &> /dev/null; then
    rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' | sort | head -50
elif command -v dpkg &> /dev/null; then
    dpkg -l | grep '^ii' | awk '{print $2"-"$3}' | sort | head -50
fi
echo "(truncated to 50 packages)"

# Capture kernel version
echo "--- Current Kernel Version ---"
uname -r

# Capture running services
echo "--- Running Services ---"
systemctl list-units --type=service --state=running --no-pager | head -20

# Capture system uptime and load
echo "--- System Status ---"
uptime

# Capture memory usage
echo "--- Memory Usage ---"
free -h

# Capture disk usage
echo "--- Disk Usage ---"
df -h | head -10

echo "=== Post-Patch Snapshot Complete ==="
""",
    },
    "check_system_health": {
        "description": "Comprehensive system health check post-patching",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Post-Patch System Health Check ==="

# Check system load
echo "--- System Load ---"
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
echo "--- Memory Status ---"
MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_PERCENT=$((MEM_AVAILABLE * 100 / MEM_TOTAL))

if [ "$MEM_PERCENT" -lt 10 ]; then
    echo "FAIL: Low memory: ${MEM_PERCENT}% available"
    exit 1
else
    echo "PASS: Memory available: ${MEM_PERCENT}%"
fi

# Check disk space
echo "--- Disk Space ---"
DISK_PERCENT=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_PERCENT" -gt 90 ]; then
    echo "WARN: Root filesystem ${DISK_PERCENT}% full"
else
    echo "PASS: Root filesystem ${DISK_PERCENT}% used"
fi

# Check for OOM events
echo "--- OOM Events ---"
OOM_COUNT=$(dmesg 2>/dev/null | grep -ci "out of memory" || echo "0")
if [ "$OOM_COUNT" -gt 0 ]; then
    echo "WARN: $OOM_COUNT OOM events in kernel ring buffer"
else
    echo "PASS: No OOM events detected"
fi

# Check for kernel errors
echo "--- Kernel Errors ---"
KERNEL_ERRORS=$(dmesg 2>/dev/null | grep -ci "error" || echo "0")
if [ "$KERNEL_ERRORS" -gt 10 ]; then
    echo "WARN: $KERNEL_ERRORS errors in kernel ring buffer"
else
    echo "PASS: Kernel error count acceptable: $KERNEL_ERRORS"
fi

echo "=== Post-Patch System Health Check Complete ==="
""",
    },
    "verify_connectivity": {
        "description": "Verify network connectivity and essential endpoints",
        "interpreter": "bash",
        "script": """#!/bin/bash
set -e

echo "=== Connectivity Verification ==="

# Check network interfaces
echo "--- Network Interfaces ---"
ip addr show | grep "inet " | grep -v "127.0.0.1" | head -5

# Check default gateway
echo "--- Default Gateway ---"
ip route | grep default || echo "WARN: No default gateway found"

# Check DNS resolution
echo "--- DNS Resolution ---"
if nslookup google.com &>/dev/null || host google.com &>/dev/null || dig google.com +short &>/dev/null; then
    echo "PASS: DNS resolution working"
else
    echo "WARN: DNS resolution may have issues"
fi

# Check metadata service (cloud-specific)
echo "--- Cloud Metadata Service ---"
if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id &>/dev/null; then
    echo "PASS: AWS metadata service accessible"
elif curl -s --connect-timeout 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
    echo "PASS: Azure metadata service accessible"
elif curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/id &>/dev/null; then
    echo "PASS: GCP metadata service accessible"
else
    echo "WARN: No cloud metadata service detected"
fi

echo "=== Connectivity Verification Complete ==="
""",
    },
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_post_qc_step_script(step: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Get the script content for a post-patching QC step.

    Args:
        step: QC step identifier.
        parameters: Optional parameters to customize the script.

    Returns:
        Dictionary with 'script' and 'interpreter' keys.

    Raises:
        HTTPException: 400 if step is not found.
    """
    if step not in POST_QC_STEPS:
        available_steps = list(POST_QC_STEPS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unknown post-patching QC step: '{step}'. Available steps: {available_steps}",
        )

    step_config = POST_QC_STEPS[step]
    script_content = step_config["script"]

    # Apply any parameter substitutions if provided (with shell escaping for security)
    script_content = safe_substitute_parameters(script_content, parameters)

    return {
        "script": script_content,
        "interpreter": step_config["interpreter"],
    }


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("/steps")
async def list_post_qc_steps() -> Dict[str, Any]:
    """List available post-patching QC steps.

    Returns a list of all available post-patching QC steps with their descriptions.
    These steps can be executed on instances to validate post-patching state.

    Returns:
        Dictionary with available steps and their descriptions.
    """
    steps = {
        step_name: {
            "description": step_config["description"],
            "interpreter": step_config["interpreter"],
        }
        for step_name, step_config in POST_QC_STEPS.items()
    }

    return {
        "steps": steps,
        "count": len(steps),
    }


@router.post("/execute-step", response_model=ExecutePostQCStepResponse)
async def execute_post_qc_step(
    request: Request,
    step_request: ExecutePostQCStepRequest,
) -> ExecutePostQCStepResponse:
    """Execute a post-patching QC step on a single instance.

    Executes the specified post-patching QC step script on the target instance
    using the provider's script execution capability (SSM, Run Command, etc.).

    Args:
        request: FastAPI request object for session access.
        step_request: QC step execution request details.

    Returns:
        ExecutePostQCStepResponse with execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if step is invalid.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Get the script for this step
    step_config = get_post_qc_step_script(step_request.step, step_request.parameters)

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

        return ExecutePostQCStepResponse(
            success=success,
            instance_id=step_request.instance_id,
            step=step_request.step,
            status=result.get("status", "unknown"),
            output=result.get("output"),
            error=result.get("error"),
            exit_code=result.get("exit_code"),
            message=f"Post-patching QC step '{step_request.step}' {'completed successfully' if success else 'failed'}",
        )

    except NotImplementedError as e:
        # Provider method not yet implemented
        return ExecutePostQCStepResponse(
            success=False,
            instance_id=step_request.instance_id,
            step=step_request.step,
            status="not_implemented",
            output=None,
            error=str(e),
            exit_code=None,
            message="Post-patching QC step execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute post-patching QC step: {e!s}",
        )


@router.post("/execute-batch", response_model=BatchPostQCExecuteResponse)
async def execute_post_qc_step_batch(
    request: Request,
    batch_request: BatchPostQCExecuteRequest,
) -> BatchPostQCExecuteResponse:
    """Execute a post-patching QC step on multiple instances.

    Executes the specified post-patching QC step script on all target instances
    using the provider's batch execution capability for efficiency.

    Args:
        request: FastAPI request object for session access.
        batch_request: Batch QC step execution request details.

    Returns:
        BatchPostQCExecuteResponse with aggregated execution results.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 400 if step is invalid.
        HTTPException: 500 if execution fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Get the script for this step
    step_config = get_post_qc_step_script(batch_request.step, batch_request.parameters)

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

        return BatchPostQCExecuteResponse(
            overall_status=overall_status,
            step=batch_request.step,
            success_count=success_count,
            failure_count=failure_count,
            results=results,
            message=f"Post-patching QC step '{batch_request.step}' executed on {len(batch_request.instance_ids)} instances: "
            f"{success_count} succeeded, {failure_count} failed",
        )

    except NotImplementedError as e:
        # Provider method not yet implemented
        return BatchPostQCExecuteResponse(
            overall_status="not_implemented",
            step=batch_request.step,
            success_count=0,
            failure_count=len(batch_request.instance_ids),
            results=[
                {"instance_id": iid, "status": "not_implemented", "error": str(e)}
                for iid in batch_request.instance_ids
            ],
            message="Batch post-patching QC step execution not yet implemented for this provider",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute batch post-patching QC step: {e!s}",
        )


@router.post("/validate", response_model=PostPatchValidationResponse)
async def validate_post_patch(
    request: Request,
    validation_request: PostPatchValidationRequest,
) -> PostPatchValidationResponse:
    """Validate instances after patching.

    Runs a series of validation checks on the specified instances to verify
    they are in a healthy state after patching operations.

    Args:
        request: FastAPI request object for session access.
        validation_request: Validation request details.

    Returns:
        PostPatchValidationResponse with validated and failed instance lists.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if validation fails unexpectedly.
    """
    provider = get_authenticated_provider(request)

    # Use verify_services step for validation
    step_config = get_post_qc_step_script("verify_services")

    validated_instances: List[str] = []
    failed_instances: List[Dict[str, Any]] = []

    try:
        result = await provider.execute_script_batch(
            instance_ids=validation_request.instance_ids,
            script_content=step_config["script"],
            interpreter=step_config["interpreter"],
            account_id=validation_request.account_id,
            region=validation_request.region,
            timeout=120,  # Timeout for validation check
        )

        for instance_result in result.get("results", []):
            instance_id = instance_result.get("instance_id")
            if instance_result.get("status") == "success" and instance_result.get("exit_code", 1) == 0:
                validated_instances.append(instance_id)
            else:
                failed_instances.append({
                    "instance_id": instance_id,
                    "reason": instance_result.get("error") or "Post-patch validation failed",
                    "status": instance_result.get("status"),
                })

    except NotImplementedError:
        # Mark all as failed when not implemented
        failed_instances = [
            {
                "instance_id": iid,
                "reason": "Post-patch validation not yet implemented for this provider",
                "status": "not_implemented",
            }
            for iid in validation_request.instance_ids
        ]

    total = len(validation_request.instance_ids)
    validated_count = len(validated_instances)
    failed_count = len(failed_instances)

    return PostPatchValidationResponse(
        validated_instances=validated_instances,
        failed_instances=failed_instances,
        message=f"{validated_count}/{total} instances passed post-patch validation"
        + (f", {failed_count} failed" if failed_count else ""),
    )


@router.post("/run-all-checks")
async def run_all_post_qc_checks(
    request: Request,
    step_request: ExecutePostQCStepRequest,
) -> Dict[str, Any]:
    """Run all post-patching QC checks on a single instance.

    Executes all available post-patching QC steps sequentially on the target
    instance and returns a comprehensive validation report.

    Args:
        request: FastAPI request object for session access.
        step_request: Base request with instance and account details.

    Returns:
        Dictionary with results from all post-patching QC checks.

    Raises:
        HTTPException: 401 if not authenticated.
        HTTPException: 500 if checks fail unexpectedly.
    """
    provider = get_authenticated_provider(request)

    all_results: Dict[str, Any] = {
        "instance_id": step_request.instance_id,
        "checks": {},
        "overall_healthy": True,
        "summary": [],
    }

    # Run each post-patching QC step
    for step_name in POST_QC_STEPS.keys():
        step_config = get_post_qc_step_script(step_name)

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
                all_results["overall_healthy"] = False
                all_results["summary"].append(f"{step_name}: FAILED")
            else:
                all_results["summary"].append(f"{step_name}: PASSED")

        except NotImplementedError:
            all_results["checks"][step_name] = {
                "success": False,
                "error": "Not implemented",
            }
            all_results["overall_healthy"] = False
            all_results["summary"].append(f"{step_name}: NOT IMPLEMENTED")

        except Exception as e:
            all_results["checks"][step_name] = {
                "success": False,
                "error": str(e),
            }
            all_results["overall_healthy"] = False
            all_results["summary"].append(f"{step_name}: ERROR - {e!s}")

    all_results["message"] = (
        "Instance passed all post-patch validations"
        if all_results["overall_healthy"]
        else "Instance has failed one or more post-patch validation checks"
    )

    return all_results
