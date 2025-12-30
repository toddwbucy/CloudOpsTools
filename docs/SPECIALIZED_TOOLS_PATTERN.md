# Specialized Tools Pattern Guide

## Overview

This guide documents the architectural pattern for creating specialized AWS execution tools in the PCM-Ops Tools platform. Following the refactoring from the general-purpose Script Runner to specialized tools, this pattern ensures secure, controlled script execution while maintaining powerful backend capabilities.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Web Interface                         │
│  (Specialized Tool - e.g., Linux QC Patching Prep)      │
├─────────────────────────────────────────────────────────┤
│                  Tool-Specific Logic                     │
│  • Pre-defined scripts (hardcoded)                       │
│  • Controlled parameters                                 │
│  • Specialized workflows                                 │
├─────────────────────────────────────────────────────────┤
│              Shared Script Executor Service              │
│  (backend/providers/aws/common/services/                │
│           script_executor.py)                            │
│  • Thread pool management                                │
│  • SSM execution                                         │
│  • Result polling                                        │
│  • Database tracking                                     │
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Shared Script Executor Service
Location: `/backend/providers/aws/common/services/script_executor.py`

This is the backend-only execution engine that handles:
- Thread pool management (MAX_CONCURRENT_EXECUTIONS = 10)
- SSM command execution
- Result polling and database updates
- Multi-account/region support

Key Functions:
- `submit_execution()` - Main entry point for tools
- `execute_batch()` - Handles actual script execution
- `poll_and_update_results()` - Monitors SSM commands

### 2. Database Models
- `Script` - Stores script definitions
- `Execution` - Tracks individual executions
- `Change` - ServiceNow change management
- `ChangeInstance` - Instance-to-change mapping

### 3. Credential Management
- Uses shared `credential_manager` from `/backend/web/aws/auth.py`
- Supports COM and GOV environments
- Session-based credential storage with encryption

## Creating a New Specialized Tool

### Step 1: Define Your Tool's Purpose and Scripts

Create a Python file in `/backend/web/aws/your_tool.py`:

```python
"""AWS Your Tool Name - Web Interface"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.templates import templates
from backend.db.session import get_db
from backend.providers.aws.common.services.credential_manager import AWSEnvironment

# Import shared components
from backend.web.aws.auth import credential_manager
from backend.providers.aws.common.services.script_executor import submit_execution

logger = logging.getLogger(__name__)
router = APIRouter()

# Define your pre-approved scripts
YOUR_TOOL_SCRIPTS = {
    "action_1": {
        "name": "Action 1 Name",
        "description": "What this action does",
        "content": """#!/bin/bash
# Your script content here
echo "Performing action 1"
""",
        "interpreter": "bash",
    },
    "action_2": {
        "name": "Action 2 Name",
        "description": "What this other action does",
        "content": """#!/bin/bash
# Your script content here
echo "Performing action 2"
""",
        "interpreter": "bash",
    },
}
```

### Step 2: Implement the Main Page Route

```python
@router.get("/", response_class=HTMLResponse)
async def your_tool_page(request: Request, db: Session = Depends(get_db)):
    """Your Tool main page"""
    # Check credential status from session
    com_credentials = request.session.get("aws_com_credentials", False)
    gov_credentials = request.session.get("aws_gov_credentials", False)
    
    return templates.TemplateResponse(
        "aws/your_tool.html",
        {
            "request": request,
            "scripts": YOUR_TOOL_SCRIPTS,
            "settings": settings,
            "com_credentials": com_credentials,
            "gov_credentials": gov_credentials,
        },
    )
```

### Step 3: Implement Script Execution

```python
@router.post("/execute-action")
async def execute_action(request: Request, db: Session = Depends(get_db)):
    """Execute a specific action on target instances"""
    try:
        data = await request.json()
        action_type = data.get("action_type")
        instance_ids = data.get("instance_ids", [])
        
        if action_type not in YOUR_TOOL_SCRIPTS:
            raise HTTPException(status_code=400, detail="Invalid action type")
        
        script = YOUR_TOOL_SCRIPTS[action_type]
        
        # Import required models
        from backend.db.models.script import Script
        from backend.db.models.execution import Execution
        from backend.core.config import AWSCredentials, AWSEnvironment
        from backend.core.utils.encryption import decrypt_session_credentials
        
        # Generate batch ID
        batch_id = f"your-tool-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
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
        
        # Create execution records for each instance
        execution_ids = []
        instances_by_env = {"com": [], "gov": []}
        
        for instance_data in data.get("instances", []):
            # Determine environment
            env = "gov" if "gov" in instance_data["region"] else "com"
            instances_by_env[env].append(instance_data)
            
            # Create execution record
            execution = Execution(
                script_id=db_script.id,
                instance_id=instance_data["instance_id"],
                account_id=instance_data["account_id"],
                region=instance_data["region"],
                status="pending",
                batch_id=batch_id,
                execution_metadata={
                    "action_type": action_type,
                    "tool": "your_tool"
                }
            )
            db.add(execution)
            db.flush()
            execution_ids.append(execution.id)
        
        db.commit()
        
        # Validate credentials
        for env in ["com", "gov"]:
            if instances_by_env[env]:
                aws_env = AWSEnvironment.COM if env == "com" else AWSEnvironment.GOV
                credentials = credential_manager.get_credentials(aws_env.value)
                
                if not credentials:
                    # Try to restore from session
                    # ... (credential restoration logic)
                    pass
        
        # Prepare script dict for executor
        script_dict = {
            "id": db_script.id,
            "name": script["name"],
            "content": script["content"],
            "interpreter": script["interpreter"]
        }
        
        # Submit to shared executor service
        logger.info(f"Submitting batch {batch_id} to executor service")
        future = submit_execution(
            batch_id,
            script_dict,
            execution_ids,
            instances_by_env,
            credential_manager
        )
        
        return JSONResponse({
            "status": "success",
            "batch_id": batch_id,
            "message": f"Executing {script['name']} on {len(execution_ids)} instance(s)"
        })
        
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
```

### Step 4: Create the HTML Template

Create `/backend/templates/aws/your_tool.html`:

```html
{% extends "base.html" %}

{% block title %}Your Tool Name - AWS{% endblock %}

{% block content %}
<div class="container mt-4">
    <h1>Your Tool Name</h1>
    <p class="lead">Brief description of what your tool does</p>
    
    <!-- Credential Status -->
    <div class="card mb-4">
        <div class="card-body">
            <h5>Credential Status</h5>
            <div class="row">
                <div class="col-md-6">
                    <span class="badge {% if com_credentials %}bg-success{% else %}bg-danger{% endif %}">
                        COM: {% if com_credentials %}Configured{% else %}Not Configured{% endif %}
                    </span>
                </div>
                <div class="col-md-6">
                    <span class="badge {% if gov_credentials %}bg-success{% else %}bg-danger{% endif %}">
                        GOV: {% if gov_credentials %}Configured{% else %}Not Configured{% endif %}
                    </span>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Action Selection -->
    <div class="card mb-4">
        <div class="card-header">
            <h5>Select Action</h5>
        </div>
        <div class="card-body">
            {% for key, script in scripts.items() %}
            <div class="form-check mb-2">
                <input class="form-check-input" type="radio" name="action" id="action_{{ key }}" value="{{ key }}">
                <label class="form-check-label" for="action_{{ key }}">
                    <strong>{{ script.name }}</strong> - {{ script.description }}
                </label>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <!-- Instance Selection -->
    <div class="card mb-4">
        <div class="card-header">
            <h5>Target Instances</h5>
        </div>
        <div class="card-body">
            <!-- Your instance selection UI here -->
        </div>
    </div>
    
    <!-- Execute Button -->
    <button class="btn btn-primary" onclick="executeAction()">
        Execute Action
    </button>
</div>

<script>
function executeAction() {
    // Get selected action
    const action = document.querySelector('input[name="action"]:checked')?.value;
    if (!action) {
        alert('Please select an action');
        return;
    }
    
    // Prepare data
    const data = {
        action_type: action,
        instances: [/* your instance data */]
    };
    
    // Submit execution
    fetch('/aws/your-tool/execute-action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            alert(`Execution started: ${result.message}`);
        }
    });
}
</script>
{% endblock %}
```

### Step 5: Register Your Tool

In `/backend/main.py`:

```python
from backend.web.aws import your_tool as your_tool_web

# In the web routers section
app.include_router(
    your_tool_web.router, 
    prefix="/aws/your-tool", 
    tags=["AWS Your Tool Web"]
)
```

## Best Practices

### 1. Security
- **NEVER** allow user-provided scripts
- All scripts must be hardcoded in the tool
- Validate all inputs thoroughly
- Use parameterized scripts where possible (using format strings)

### 2. Script Design
- Keep scripts focused and single-purpose
- Include error handling in bash scripts
- Use clear, descriptive names
- Document what each script does

### 3. Error Handling
- Catch and log all exceptions
- Provide meaningful error messages to users
- Handle credential issues gracefully
- Monitor execution status properly

### 4. Database Management
- Always create Script records for tracking
- Use Execution records for each instance
- Include metadata for debugging
- Clean up old records periodically

### 5. UI/UX
- Show credential status clearly
- Provide real-time execution feedback
- Display results in a user-friendly format
- Include help text and documentation

## Example Tools

### Linux QC Patching Prep
- **Purpose**: Prepare Linux systems for patching
- **Scripts**: Initial QC, Kernel Staging, Final Report
- **Features**: Multi-step workflow, kernel version management

### Linux QC Patching Post
- **Purpose**: Post-patching validation
- **Scripts**: Service checks, reboot verification
- **Features**: Comprehensive validation reports

### SFT Fixer
- **Purpose**: Fix ScaleFT agent issues
- **Scripts**: Detection, repair, enrollment
- **Features**: Single-instance targeted fixes

## Testing Your Tool

1. **Unit Tests**: Test script generation and validation
2. **Integration Tests**: Test database operations
3. **End-to-End Tests**: Test full execution flow
4. **Security Tests**: Verify no arbitrary code execution

## Common Issues and Solutions

### Issue: Credentials not found
**Solution**: Implement session-based credential restoration

### Issue: Thread pool exhaustion
**Solution**: Use the shared executor's thread pool management

### Issue: SSM command timeouts
**Solution**: Implement proper polling with reasonable timeouts

### Issue: Database record mismatches
**Solution**: Ensure proper transaction management and commits

## Migration from Script Runner

If migrating existing Script Runner functionality:

1. Identify commonly used scripts
2. Create specialized tools for specific use cases
3. Hardcode scripts with proper validation
4. Remove ability to create/edit scripts via UI
5. Maintain execution history in database

## Support and Maintenance

- Keep scripts version controlled
- Document any script changes
- Monitor execution success rates
- Collect user feedback for improvements
- Regular security audits

## Conclusion

This pattern ensures secure, controlled script execution while maintaining the powerful capabilities needed for AWS operations. By following this guide, new tools can be created that are both powerful and safe.