"""
API documentation examples for the executions API endpoints.
These examples will be used to enhance the OpenAPI documentation in the FastAPI application.
"""

# Example request and response payloads for Swagger UI documentation

EXECUTION_CREATE_EXAMPLE = {
    "script_id": 1,
    "instance_id": 2,
    "parameters": {"param1": "value1", "param2": "value2"},
}

EXECUTION_BATCH_CREATE_EXAMPLE = {
    "script_id": 1,
    "instance_ids": [1, 2, 3],
    "parameters": {"param1": "value1", "param2": "value2"},
}

EXECUTION_RESPONSE_EXAMPLE = {
    "id": 1,
    "script_id": 1,
    "instance_id": 2,
    "status": "RUNNING",
    "command_id": "cmd-0123456789abcdef0",
    "parameters": {"param1": "value1", "param2": "value2"},
    "output": "Command output will appear here...",
    "exit_code": None,
    "start_time": "2025-05-24T14:00:00",
    "end_time": None,
    "created_at": "2025-05-24T14:00:00",
    "updated_at": "2025-05-24T14:00:05",
}

EXECUTION_LIST_EXAMPLE = {
    "items": [
        {
            "id": 1,
            "script_id": 1,
            "instance_id": 2,
            "status": "COMPLETED",
            "command_id": "cmd-0123456789abcdef0",
            "parameters": {"param1": "value1"},
            "output": "Command completed successfully",
            "exit_code": 0,
            "start_time": "2025-05-24T14:00:00",
            "end_time": "2025-05-24T14:01:00",
            "created_at": "2025-05-24T14:00:00",
            "updated_at": "2025-05-24T14:01:00",
        },
        {
            "id": 2,
            "script_id": 1,
            "instance_id": 3,
            "status": "RUNNING",
            "command_id": "cmd-0123456789abcdef1",
            "parameters": {"param1": "value1"},
            "output": "Command is still running...",
            "exit_code": None,
            "start_time": "2025-05-24T14:05:00",
            "end_time": None,
            "created_at": "2025-05-24T14:05:00",
            "updated_at": "2025-05-24T14:05:05",
        },
    ],
    "total": 2,
    "page": 1,
    "size": 10,
}

EXECUTION_STATUS_EXAMPLE = {
    "status": "RUNNING",
    "command_id": "cmd-0123456789abcdef0",
    "output": "Command is still running...",
    "exit_code": None,
}

BATCH_PROGRESS_EXAMPLE = {
    "total": 3,
    "completed": 1,
    "running": 1,
    "failed": 0,
    "pending": 1,
    "executions": [
        {"id": 1, "instance_id": 2, "status": "COMPLETED", "exit_code": 0},
        {"id": 2, "instance_id": 3, "status": "RUNNING", "exit_code": None},
        {"id": 3, "instance_id": 4, "status": "PENDING", "exit_code": None},
    ],
}

# Documentation descriptions for endpoints

LIST_EXECUTIONS_DESCRIPTION = """
Retrieve a list of script executions with optional filtering.

This endpoint supports pagination and filtering by status, script ID, and instance ID.
Results are sorted by creation date in descending order (newest first).
"""

GET_EXECUTION_DESCRIPTION = """
Retrieve detailed information about a specific script execution.

This endpoint returns comprehensive details about an execution including
status, output, exit code, and timestamps.
"""

GET_EXECUTION_STATUS_DESCRIPTION = """
Get the current status of an execution.

This endpoint retrieves the current status of an execution and optionally
refreshes it from AWS if the execution is still running. Use the `refresh`
query parameter to fetch the latest status from AWS SSM.
"""

CREATE_EXECUTION_DESCRIPTION = """
Create a new script execution.

This endpoint creates a new execution record and starts the script execution
on the specified EC2 instance as a background task. The script will be executed
via AWS SSM Run Command.

The execution will be set to PENDING status initially, then updated to RUNNING
when the command is sent to SSM. The status will be updated to COMPLETED or FAILED
when the command completes.
"""

CREATE_EXECUTION_BATCH_DESCRIPTION = """
Create multiple script executions on different instances.

This endpoint allows executing the same script on multiple instances in a single API call.
It returns a batch ID that can be used to track the progress of all executions.

Each instance will have its own execution record that can be monitored individually
or as part of the batch.
"""

GET_BATCH_PROGRESS_DESCRIPTION = """
Get the progress of a batch execution.

This endpoint provides a summary of the status of all executions in a batch,
including counts of completed, running, failed, and pending executions.
"""

CANCEL_EXECUTION_DESCRIPTION = """
Cancel a running script execution.

This endpoint attempts to cancel a running execution by sending a cancellation
request to AWS SSM. It will only work if the execution is in RUNNING status and
has a valid command ID.
"""
