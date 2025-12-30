"""AWS SFT Fixer Tool - Web Interface"""

import logging
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.templates import templates
from backend.db.models.execution import Execution
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


# SFT enrollment token - should be configured via environment variable
import os

SFT_ENROLLMENT_TOKEN = os.environ.get('SFT_ENROLLMENT_TOKEN', '')

if not SFT_ENROLLMENT_TOKEN:
    logger.warning("SFT enrollment token not configured. Set SFT_ENROLLMENT_TOKEN environment variable. Scripts will not function properly without it.")


def generate_sft_detection_script() -> str:
    """Generate script to detect if SFT is installed"""
    script_content = """#!/bin/bash
echo "=== SFT Detection Script ==="
echo "Checking if ScaleFT/SFT is installed..."

# Check if sftd service exists (Linux)
if systemctl list-unit-files sftd.service >/dev/null 2>&1; then
    echo "SFT_INSTALLED=true"
    echo "SFT_TYPE=linux"
    
    # Check service status
    if systemctl is-active sftd >/dev/null 2>&1; then
        echo "SFT_STATUS=running"
    else
        echo "SFT_STATUS=stopped"
    fi
    
    # Check if enrollment token exists
    if [ -f "/var/lib/sftd/enrollment.token" ]; then
        echo "SFT_ENROLLMENT_TOKEN=exists"
    else
        echo "SFT_ENROLLMENT_TOKEN=missing"
    fi
    
    # Check if device token exists
    if [ -f "/var/lib/sftd/device.token" ]; then
        echo "SFT_DEVICE_TOKEN=exists"
    else
        echo "SFT_DEVICE_TOKEN=missing"
    fi
    
    # Check configuration
    if [ -f "/etc/sft/sftd.yaml" ]; then
        echo "SFT_CONFIG=exists"
        echo "Config contents:"
        cat /etc/sft/sftd.yaml
    else
        echo "SFT_CONFIG=missing"
    fi
    
else
    echo "SFT_INSTALLED=false"
    echo "SFT_TYPE=unknown"
    
    # Check if this is Ubuntu or RHEL
    if [ -f /etc/redhat-release ]; then
        echo "LINUX_DISTRO=rhel"
    elif [ -f /etc/lsb-release ] || [ -f /etc/debian_version ]; then
        echo "LINUX_DISTRO=ubuntu"
    else
        echo "LINUX_DISTRO=unknown"
    fi
fi

echo "=== Detection Complete ==="
"""
    return script_content


def generate_windows_sft_detection_script() -> str:
    """Generate PowerShell script to detect if SFT is installed on Windows"""
    script_content = '''# Windows SFT Detection Script
Write-Host "=== Windows SFT Detection Script ==="
Write-Host "Checking if ScaleFT/SFT is installed..."

try {
    # Check if scaleft-server-tools service exists
    $service = Get-Service -Name "scaleft-server-tools" -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Host "SFT_INSTALLED=true"
        Write-Host "SFT_TYPE=windows"
        
        # Check service status
        if ($service.Status -eq "Running") {
            Write-Host "SFT_STATUS=running"
        } else {
            Write-Host "SFT_STATUS=stopped"
        }
        
        # Check if enrollment token exists
        $enrollmentTokenPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\ScaleFT\\enrollment.token"
        if (Test-Path $enrollmentTokenPath) {
            Write-Host "SFT_ENROLLMENT_TOKEN=exists"
        } else {
            Write-Host "SFT_ENROLLMENT_TOKEN=missing"
        }
        
        # Check if device token exists
        $deviceTokenPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\ScaleFT\\state\\device.token"
        if (Test-Path $deviceTokenPath) {
            Write-Host "SFT_DEVICE_TOKEN=exists"
        } else {
            Write-Host "SFT_DEVICE_TOKEN=missing"
        }
        
        # Check configuration
        $configPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\scaleft\\sftd.yaml"
        if (Test-Path $configPath) {
            Write-Host "SFT_CONFIG=exists"
            Write-Host "Config contents:"
            Get-Content $configPath
        } else {
            Write-Host "SFT_CONFIG=missing"
        }
        
    } else {
        Write-Host "SFT_INSTALLED=false"
        Write-Host "SFT_TYPE=windows"
    }
} catch {
    Write-Host "Error during detection: $($_.Exception.Message)"
    Write-Host "SFT_INSTALLED=unknown"
    Write-Host "SFT_TYPE=windows"
}

Write-Host "=== Detection Complete ==="
'''
    return script_content


def generate_rhel_sft_install_script() -> str:
    """Generate RHEL SFT installation script"""
    script_content = f"""#!/bin/bash
echo "=== RHEL SFT Installation Script ==="

# Get IP address
ipassign=$(for i in `ip route show default | awk {{'print $5'}}`; do ip addr list $i | grep "inet " | awk {{'print $2'}} | awk -F"/" {{'print $1'}}; done)
echo "Detected IP address: $ipassign"

# Create directories
mkdir -p /etc/sft/
mkdir -p /var/lib/sftd

# Add ScaleFT repository
curl -C - -o /etc/yum.repos.d/scaleft.repo "https://pkg.scaleft.com/scaleft_yum.repo"

# Import GPG key
rpm --import https://dist.scaleft.com/GPG-KEY-OktaPAM-2023

# Install ScaleFT
yum -y install scaleft-server-tools

# Configure enrollment token
echo "{SFT_ENROLLMENT_TOKEN}" > /var/lib/sftd/enrollment.token

# Configure sftd.yaml
echo -e "Autoenroll: false\\nAccessAddress: $ipassign" > /etc/sft/sftd.yaml

# Start service
systemctl enable sftd
systemctl start sftd

echo "=== RHEL SFT Installation Complete ==="
echo "Service status:"
systemctl status sftd --no-pager -l
"""
    return script_content


def generate_ubuntu_sft_install_script() -> str:
    """Generate Ubuntu SFT installation script"""
    script_content = f"""#!/bin/bash
echo "=== Ubuntu SFT Installation Script ==="

# Get IP address
ipassign=$(for i in `ip route show default | awk {{'print $5'}}`; do ip addr list $i | grep "inet " | awk {{'print $2'}} | awk -F"/" {{'print $1'}}; done)
echo "Detected IP address: $ipassign"

# Create directories
mkdir -p /etc/sft/
mkdir -p /var/lib/sftd

# Add GPG key and repository
curl -fsSL https://dist.scaleft.com/GPG-KEY-OktaPAM-2023 | gpg --dearmor | sudo tee /usr/share/keyrings/oktapam-2023-archive-keyring.gpg > /dev/null

# Add repository (using jammy as specified)
echo "deb [signed-by=/usr/share/keyrings/oktapam-2023-archive-keyring.gpg] https://dist.scaleft.com/repos/deb jammy okta" | sudo tee /etc/apt/sources.list.d/oktapam-stable.list

# Update package list
apt-get update

# Install ScaleFT (Note: fixing typo from user's script scalft -> scaleft)
apt-get install -y scaleft-server-tools

# Configure enrollment token
echo "{SFT_ENROLLMENT_TOKEN}" > /var/lib/sftd/enrollment.token

# Configure sftd.yaml
echo -e "Autoenroll: false\\nAccessAddress: $ipassign" > /etc/sft/sftd.yaml

# Start service
systemctl enable sftd
systemctl start sftd

echo "=== Ubuntu SFT Installation Complete ==="
echo "Service status:"
systemctl status sftd --no-pager -l
"""
    return script_content


def generate_windows_sft_install_script() -> str:
    """Generate Windows SFT installation script (placeholder)"""
    script_content = '''# Windows SFT Installation Script
Write-Host "=== Windows SFT Installation Script ==="
Write-Host "Windows SFT installation is not yet implemented."
Write-Host "Please install ScaleFT manually on this Windows instance."
Write-Host "Once installed, use the reset functionality to configure it."
Write-Host "=== Installation Placeholder ==="
'''
    return script_content


def generate_linux_sft_reset_script() -> str:
    """Generate Linux SFT reset script (works for both RHEL and Ubuntu)"""
    script_content = f"""#!/bin/bash
echo "=== Linux SFT Reset Script ==="

# Get IP address
ipassign=$(for i in `ip route show default | awk {{'print $5'}}`; do ip addr list $i | grep "inet " | awk {{'print $2'}} | awk -F"/" {{'print $1'}}; done)
echo "Detected IP address: $ipassign"

# Create directories (in case they don't exist)
mkdir -p /etc/sft/
mkdir -p /var/lib/sftd

# Stop the service
systemctl stop sftd

# Remove old device token
rm -f /var/lib/sftd/device.token
echo "Removed old device token"

# Configure enrollment token
echo "{SFT_ENROLLMENT_TOKEN}" > /var/lib/sftd/enrollment.token
echo "Updated enrollment token"

# Configure sftd.yaml
echo -e "Autoenroll: false\\nAccessAddress: $ipassign" > /etc/sft/sftd.yaml
echo "Updated configuration with IP: $ipassign"

# Start service
systemctl start sftd

echo "=== Linux SFT Reset Complete ==="
echo "Service status:"
systemctl status sftd --no-pager -l

echo "Configuration:"
cat /etc/sft/sftd.yaml
"""
    return script_content


def generate_windows_sft_reset_script() -> str:
    """Generate Windows SFT reset script"""
    script_content = f'''# Windows SFT Reset Script
Write-Host "=== Windows SFT Reset Script ==="

try {{
    # Get IP address
    $ipassign = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.IPAddress -notlike '127.*' }} | Select-Object -First 1).IPAddress
    Write-Host "Detected IP address: $ipassign"

    # Stop the service
    Stop-Service "scaleft-server-tools" -Force
    Write-Host "Stopped ScaleFT service"

    # Remove old device token
    $deviceTokenPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\ScaleFT\\state\\device.token"
    if (Test-Path $deviceTokenPath) {{
        Remove-Item $deviceTokenPath -Force
        Write-Host "Removed old device token"
    }}

    # Set enrollment token
    $enrollmentTokenPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\ScaleFT\\enrollment.token"
    Set-Content $enrollmentTokenPath "{SFT_ENROLLMENT_TOKEN}"
    Write-Host "Updated enrollment token"

    # Configure sftd.yaml
    $configPath = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\scaleft\\sftd.yaml"
    $configContent = @"
Autoenroll: false
AccessAddress: $ipassign
"@
    Set-Content $configPath $configContent
    Write-Host "Updated configuration with IP: $ipassign"

    # Start service
    Start-Service "scaleft-server-tools"
    Write-Host "Started ScaleFT service"

    Write-Host "=== Windows SFT Reset Complete ==="
    
    # Show service status
    $service = Get-Service "scaleft-server-tools"
    Write-Host "Service Status: $($service.Status)"
    
    # Show configuration
    Write-Host "Configuration:"
    Get-Content $configPath

}} catch {{
    Write-Host "Error during reset: $($_.Exception.Message)"
    exit 1
}}
'''
    return script_content


@router.get("/", response_class=HTMLResponse)
async def sft_fixer_page(request: Request, db: Session = Depends(get_db)):
    """SFT Fixer Tool main page"""
    # Check credential status from session
    com_credentials = request.session.get("aws_com_credentials", False)
    gov_credentials = request.session.get("aws_gov_credentials", False)

    return templates.TemplateResponse(
        "aws/sft_fixer.html",
        {
            "request": request,
            "settings": settings,
            "com_credentials": com_credentials,
            "gov_credentials": gov_credentials,
        },
    )


# Pre-defined scripts for SFT fixing
SFT_SCRIPTS = {
    "detect": {
        "name": "SFT Detection",
        "description": "Detect if SFT is installed and its current state",
        "interpreter": "bash",
        "content": generate_sft_detection_script(),
    },
    "detect_windows": {
        "name": "Windows SFT Detection",
        "description": "Detect if SFT is installed on Windows",
        "interpreter": "powershell",
        "content": generate_windows_sft_detection_script(),
    },
    "install_rhel": {
        "name": "RHEL SFT Installation",
        "description": "Install ScaleFT on RHEL/CentOS systems",
        "interpreter": "bash",
        "content": generate_rhel_sft_install_script(),
    },
    "install_ubuntu": {
        "name": "Ubuntu SFT Installation",
        "description": "Install ScaleFT on Ubuntu systems",
        "interpreter": "bash",
        "content": generate_ubuntu_sft_install_script(),
    },
    "install_windows": {
        "name": "Windows SFT Installation",
        "description": "Install ScaleFT on Windows systems (placeholder)",
        "interpreter": "powershell",
        "content": generate_windows_sft_install_script(),
    },
    "reset_linux": {
        "name": "Linux SFT Reset",
        "description": "Reset and reconfigure SFT on Linux systems",
        "interpreter": "bash",
        "content": generate_linux_sft_reset_script(),
    },
    "reset_windows": {
        "name": "Windows SFT Reset",
        "description": "Reset and reconfigure SFT on Windows systems",
        "interpreter": "powershell",
        "content": generate_windows_sft_reset_script(),
    },
}


@router.post("/validate-instance")
async def validate_instance(request: Request, instance_data: dict, db: Session = Depends(get_db)):
    """Validate instance configuration - simplified validation using same approach as other tools"""
    try:
        os_type = instance_data.get("os_type")
        instance_id = instance_data.get("instance_id")
        region = instance_data.get("region")
        account_number = instance_data.get("account_number")

        # Basic validation
        if not all([os_type, instance_id, region, account_number]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        # Check credentials availability (same pattern as Linux QC Patching tool)
        if region.startswith("us-gov"):
            credentials = request.session.get("aws_gov_credentials")
            environment = AWSEnvironment.GOV
        else:
            credentials = request.session.get("aws_com_credentials")
            environment = AWSEnvironment.COM

        if not credentials:
            raise HTTPException(status_code=400, detail="AWS credentials not configured")

        # Simplified validation - just check basic parameters
        # The actual SSM connectivity will be tested during script execution,
        # same as how the Linux QC Patching and Script Runner tools work
        logger.info(f"Validated SFT Fixer target: {instance_id} in {region} (account: {account_number})")

        return JSONResponse(content={
            "status": "success",
            "message": f"Configuration validated for {instance_id}. SSM connectivity will be confirmed during script execution."
        })

    except Exception as e:
        logger.error(f"Instance validation failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/execute-script")
async def execute_script(request: Request, script_data: dict, db: Session = Depends(get_db)):
    """Execute SFT script on target instance"""
    try:
        instance_config = script_data.get("instance_config")
        script_type = script_data.get("script_type")

        if not instance_config or not script_type:
            raise HTTPException(status_code=400, detail="Missing instance config or script type")

        if script_type not in SFT_SCRIPTS:
            raise HTTPException(status_code=400, detail=f"Unknown script type: {script_type}")

        script = SFT_SCRIPTS[script_type]

        # Import required models
        from backend.core.config import AWSCredentials, AWSEnvironment
        from backend.core.utils.encryption import decrypt_session_credentials
        from backend.db.models.execution import Execution
        from backend.db.models.script import Script

        # Create instance data in the format expected by the executor
        instance_data = {
            "instance_id": instance_config["instance_id"],
            "account_id": instance_config["account_number"],  # Note: changed from 'account' to 'account_id'
            "region": instance_config["region"],
            "environment": "gov" if "gov" in instance_config["region"] else "com",
            "name": f"SFT-Fixer-{instance_config['instance_id']}"
        }

        # Generate batch ID and change number
        batch_id = f"sft-fixer-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        change_number = f"SFT-FIXER-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Check credentials for the environment
        env = instance_data["environment"]
        aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
        credentials = credential_manager.get_credentials(aws_env)

        # If not in credential manager, try to restore from session
        if not credentials:
            session_creds_key = f"aws_{env}_credential_data"
            encrypted_creds = request.session.get(session_creds_key)
            if encrypted_creds:
                session_creds = decrypt_session_credentials(encrypted_creds)
                if session_creds:
                    logger.info(f"Restoring {env} credentials from session to credential manager")
                    restored_creds = AWSCredentials(
                        access_key=session_creds["access_key"],
                        secret_key=session_creds["secret_key"],
                        session_token=session_creds.get("session_token"),
                        environment=aws_env,
                    )
                    credential_manager.store_credentials(restored_creds)
                    credentials = credential_manager.get_credentials(aws_env)

        if not credentials:
            raise HTTPException(
                status_code=400,
                detail=f"No credentials configured for {env.upper()} environment"
            )

        # Create or get script in database
        db_script = db.query(Script).filter(
            Script.name == script["name"],
            Script.content == script["content"]
        ).first()

        if not db_script:
            db_script = Script(
                name=script["name"],
                content=script["content"],
                script_type="bash",
                interpreter=script["interpreter"],
                description=script["description"]
            )
            db.add(db_script)
            db.flush()

        # Create execution record
        execution = Execution(
            script_id=db_script.id,
            instance_id=instance_data["instance_id"],
            account_id=instance_data["account_id"],
            region=instance_data["region"],
            status="pending",
            batch_id=batch_id,
            change_number=change_number,
            execution_metadata={
                "script_name": script["name"],
                "script_interpreter": script["interpreter"],
                "environment": instance_data["environment"],
                "instance_name": instance_data.get("name", ""),
                "sft_action": script_type  # Track which SFT action was performed
            }
        )
        db.add(execution)
        db.commit()

        # Group instances by environment for the executor
        instances_by_env = {
            instance_data["environment"]: [instance_data]
        }

        # Prepare script dict for executor
        script_dict = {
            "id": db_script.id,
            "name": script["name"],
            "content": script["content"],
            "interpreter": script["interpreter"]
        }

        # Submit to shared executor service
        logger.info(f"Submitting SFT Fixer batch {batch_id} to executor service")
        future = submit_execution(
            batch_id,
            script_dict,
            [execution.id],  # Pass execution IDs
            instances_by_env,
            credential_manager
        )

        # Store batch info in session for tracking
        jobs = request.session.get("background_jobs", [])
        jobs.append({
            "id": batch_id,
            "name": f"SFT Fixer - {script['name']}",
            "status": "running",
            "start_time": datetime.now().isoformat(),
            "total": 1,
            "completed": 0
        })
        request.session["background_jobs"] = jobs

        return JSONResponse(content={
            "status": "success",
            "batch_id": batch_id,
            "message": f"Executing {script['name']} on {instance_config['instance_id']}"
        })

    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/batch-status/{batch_id}")
async def get_batch_status(batch_id: str, db: Session = Depends(get_db)):
    """Get the status of a batch execution using proper batch tracking like Script Runner"""
    try:
        logger.info(f"Getting batch status for: {batch_id}")

        # Query executions by batch_id (same approach as Script Runner)
        executions = db.query(Execution).filter(Execution.batch_id == batch_id).all()

        if not executions:
            logger.warning(f"No executions found for batch_id: {batch_id}")
            raise HTTPException(status_code=404, detail=f"No executions found for batch {batch_id}")

        # Calculate batch status
        total_count = len(executions)
        completed_count = sum(1 for exec in executions if exec.status in ['completed', 'failed'])

        # Determine overall batch status
        if completed_count == total_count:
            batch_status_overall = "completed"
        elif any(exec.status == 'failed' for exec in executions):
            batch_status_overall = "failed"
        elif any(exec.status == 'running' for exec in executions):
            batch_status_overall = "running"
        else:
            batch_status_overall = "pending"

        # Convert executions to results format
        results = []
        for execution in executions:
            results.append({
                "instance_id": execution.instance_id,
                "status": "success" if execution.status == "completed" else execution.status,
                "output": execution.output or ""
            })

        batch_status = {
            "status": batch_status_overall,
            "completed_count": completed_count,
            "total_count": total_count,
            "results": results
        }

        logger.info(f"Batch {batch_id} status: {batch_status_overall} ({completed_count}/{total_count})")

        return JSONResponse(content={
            "status": "success",
            "batch_status": batch_status
        })

    except Exception as e:
        logger.error(f"Failed to get batch status for {batch_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
