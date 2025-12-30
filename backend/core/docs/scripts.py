"""
API documentation examples for the scripts API endpoints.
These examples will be used to enhance the OpenAPI documentation in the FastAPI application.
"""

# Example request and response payloads for Swagger UI documentation

SCRIPT_CREATE_EXAMPLE = {
    "name": "Update System Packages",
    "description": "Updates all system packages on Linux instances",
    "content": "#!/bin/bash\napt-get update && apt-get upgrade -y",
    "tool_id": 1,
    "parameters": {"timeout": "600", "requires_sudo": "true"},
}

SCRIPT_UPDATE_EXAMPLE = {
    "name": "Update System Packages",
    "description": "Updates all system packages on Linux instances with less verbosity",
    "content": "#!/bin/bash\napt-get update -qq && apt-get upgrade -y -qq",
    "tool_id": 1,
    "parameters": {"timeout": "300", "requires_sudo": "true"},
}

SCRIPT_RESPONSE_EXAMPLE = {
    "id": 1,
    "name": "Update System Packages",
    "description": "Updates all system packages on Linux instances",
    "content": "#!/bin/bash\napt-get update && apt-get upgrade -y",
    "tool_id": 1,
    "parameters": {"timeout": "600", "requires_sudo": "true"},
    "created_at": "2025-05-24T14:00:00",
    "updated_at": "2025-05-24T14:00:00",
}

SCRIPT_LIST_EXAMPLE = {
    "scripts": [
        {
            "id": 1,
            "name": "Update System Packages",
            "description": "Updates all system packages on Linux instances",
            "tool_id": 1,
            "created_at": "2025-05-24T14:00:00",
            "updated_at": "2025-05-24T14:00:00",
        },
        {
            "id": 2,
            "name": "Restart Web Server",
            "description": "Restarts Apache or Nginx web server",
            "tool_id": 1,
            "created_at": "2025-05-24T14:05:00",
            "updated_at": "2025-05-24T14:05:00",
        },
    ],
    "total": 2,
    "page": 1,
    "size": 10,
}

TOOL_CREATE_EXAMPLE = {
    "name": "Bash",
    "description": "Linux Bash shell scripting",
    "platform": "LINUX",
    "icon": "bash-icon",
}

TOOL_RESPONSE_EXAMPLE = {
    "id": 1,
    "name": "Bash",
    "description": "Linux Bash shell scripting",
    "platform": "LINUX",
    "icon": "bash-icon",
    "created_at": "2025-05-24T14:00:00",
    "updated_at": "2025-05-24T14:00:00",
}

TOOL_LIST_EXAMPLE = {
    "items": [
        {
            "id": 1,
            "name": "Bash",
            "description": "Linux Bash shell scripting",
            "platform": "LINUX",
            "icon": "bash-icon",
            "created_at": "2025-05-24T14:00:00",
            "updated_at": "2025-05-24T14:00:00",
        },
        {
            "id": 2,
            "name": "PowerShell",
            "description": "Windows PowerShell scripting",
            "platform": "WINDOWS",
            "icon": "powershell-icon",
            "created_at": "2025-05-24T14:05:00",
            "updated_at": "2025-05-24T14:05:00",
        },
    ],
    "total": 2,
    "page": 1,
    "size": 10,
}

# Documentation descriptions for endpoints

LIST_SCRIPTS_DESCRIPTION = """
Retrieve a list of scripts with optional filtering.

This endpoint supports pagination and filtering by name, tool ID, and platform.
Results include basic script information but not the full script content.
"""

GET_SCRIPT_DESCRIPTION = """
Retrieve detailed information about a specific script.

This endpoint returns comprehensive details about a script including
the full script content and any associated parameters.
"""

CREATE_SCRIPT_DESCRIPTION = """
Create a new script.

This endpoint allows creating a new script with the specified name, description,
content, and associated tool. The script content should be compatible with the
selected tool's platform (Linux or Windows).

Parameters are optional and can be used to specify script-specific settings like
timeout values, permissions, or configuration options.
"""

UPDATE_SCRIPT_DESCRIPTION = """
Update an existing script.

This endpoint allows modifying an existing script's properties including
name, description, content, and parameters. The script ID cannot be changed.
Any fields not provided in the request will remain unchanged.
"""

DELETE_SCRIPT_DESCRIPTION = """
Delete a script.

This endpoint permanently removes a script from the system. This operation cannot be undone.
Scripts that are referenced by existing executions will not be deleted to maintain historical records.
"""

LIST_TOOLS_DESCRIPTION = """
Retrieve a list of available script tools.

This endpoint returns all available script tools that can be used when creating
scripts. Tools define the platform (Linux/Windows) and execution environment for scripts.
"""

GET_TOOL_DESCRIPTION = """
Retrieve detailed information about a specific script tool.

This endpoint returns comprehensive details about a tool including
its name, description, platform, and icon.
"""

CREATE_TOOL_DESCRIPTION = """
Create a new script tool.

This endpoint allows creating a new script tool with the specified name, description,
platform, and icon. Tools define the execution environment for scripts.
"""
