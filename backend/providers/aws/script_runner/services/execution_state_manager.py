"""
AWS Execution State Manager - Manages long-running execution states across credential refreshes
"""

import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, cast

from pydantic import BaseModel, ConfigDict

from backend.providers.aws.common.services.credential_manager import CredentialManager

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """Status of a long-running AWS execution"""

    PENDING = "pending"
    RUNNING = "running"
    CREDENTIALS_EXPIRED = "credentials_expired"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionStep(BaseModel):
    """Step in an AWS execution process"""

    name: str
    status: str
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ExecutionState(BaseModel):
    """State of a long-running AWS execution"""

    id: str
    execution_type: str
    environment: str
    started_at: float
    last_updated_at: float
    status: ExecutionStatus
    params: Dict[str, Any]
    steps: List[ExecutionStep]
    current_step_idx: int = 0
    results: Dict[str, Any] = {}
    credential_check_time: float

    model_config = ConfigDict(extra="allow")


class AWSExecutionStateManager:
    """
    Manages the state of long-running AWS executions across credential refreshes.

    This class enables operations to be paused when AWS credentials expire and
    resumed when new credentials are provided, without losing progress.
    """

    _instance = None

    @classmethod
    def get_instance(cls, credential_manager: Optional[CredentialManager] = None):
        """Get the singleton instance of the execution state manager"""
        if cls._instance is None:
            if credential_manager is None:
                # Import here to avoid circular imports
                from backend.providers.aws.common.services import (
                    credential_manager as cm,
                )
                from backend.providers.aws.common.services.credential_manager import (
                    CredentialManager,
                )

                # Get the actual instance from the module
                credential_manager = cast(CredentialManager, cm)
            cls._instance = cls(credential_manager)
        return cls._instance

    def __init__(self, credential_manager: CredentialManager):
        """Initialize the execution state manager

        Args:
            credential_manager: The credential manager to use for validating credentials
        """
        self.credential_manager = credential_manager
        self._executions: Dict[str, ExecutionState] = {}

    def create_execution(
        self,
        execution_type: str,
        environment: str,
        params: Dict[str, Any],
        steps: List[Dict[str, Any]],
    ) -> str:
        """Create a new execution

        Args:
            execution_type: Type of execution (e.g., "org_traverse", "resource_scan")
            environment: AWS environment (com or gov)
            params: Parameters for the execution
            steps: List of steps for the execution

        Returns:
            Execution ID
        """
        # Check if credentials are valid
        if not self.credential_manager.are_credentials_valid(environment):
            raise ValueError(f"No valid credentials for {environment}")

        # Create execution ID
        execution_id = str(uuid.uuid4())

        # Create execution steps
        execution_steps = [
            ExecutionStep(name=step["name"], status="pending") for step in steps
        ]

        # Create execution state
        now = time.time()
        state = ExecutionState(
            id=execution_id,
            execution_type=execution_type,
            environment=environment,
            started_at=now,
            last_updated_at=now,
            status=ExecutionStatus.PENDING,
            params=params,
            steps=execution_steps,
            credential_check_time=now,
        )

        # Store the execution
        self._executions[execution_id] = state

        logger.info(f"Created execution {execution_id} of type {execution_type}")
        return execution_id

    def start_execution(self, execution_id: str) -> bool:
        """Start an execution

        Args:
            execution_id: ID of the execution to start

        Returns:
            True if the execution was started, False otherwise
        """
        if execution_id not in self._executions:
            return False

        # Get execution state
        state = self._executions[execution_id]

        # Check if credentials are valid
        if not self.credential_manager.are_credentials_valid(state.environment):
            state.status = ExecutionStatus.CREDENTIALS_EXPIRED
            return False

        # Update execution state
        state.status = ExecutionStatus.RUNNING
        state.last_updated_at = time.time()

        # If there are steps, start the first one
        if state.steps and state.current_step_idx < len(state.steps):
            step = state.steps[state.current_step_idx]
            step.status = "running"
            step.started_at = time.time()

        logger.info(f"Started execution {execution_id}")
        return True

    def check_credentials(self, execution_id: str) -> bool:
        """Check if credentials for an execution are still valid

        Args:
            execution_id: ID of the execution to check credentials for

        Returns:
            True if credentials are valid, False otherwise
        """
        if execution_id not in self._executions:
            return False

        # Get execution state
        state = self._executions[execution_id]

        # Only check periodically (every 5 minutes)
        now = time.time()
        time_since_last_check = now - state.credential_check_time

        # If within throttle window, return the previous result without calling credential manager
        if time_since_last_check < 300:  # 5 minutes
            logger.debug(f"Credential check throttled for execution {execution_id}")
            # For a recently running execution, we assume credentials are still valid
            # This is just a local optimization to avoid calling the credential manager too often
            if state.status == ExecutionStatus.RUNNING:
                return True
            # For a paused execution, maintain the paused state
            elif state.status == ExecutionStatus.CREDENTIALS_EXPIRED:
                return False
            # For other states, we'll check credentials

        # Log that we're performing a real check
        logger.debug(f"Performing credential check for execution {execution_id}")

        # Check if credentials are valid - this is the actual credential manager call
        valid = self.credential_manager.are_credentials_valid(state.environment)

        # Update the check time
        state.credential_check_time = now

        # If not valid, update execution state
        if not valid and state.status == ExecutionStatus.RUNNING:
            state.status = ExecutionStatus.CREDENTIALS_EXPIRED
            state.last_updated_at = now

            # If there's a current step, mark it as paused
            if state.steps and state.current_step_idx < len(state.steps):
                step = state.steps[state.current_step_idx]
                if step.status == "running":
                    step.status = "paused"

            logger.warning(f"Credentials expired for execution {execution_id}")

        return bool(valid)

    def resume_execution(self, execution_id: str) -> bool:
        """Resume an execution after credentials have been refreshed

        Args:
            execution_id: ID of the execution to resume

        Returns:
            True if the execution was resumed, False otherwise
        """
        if execution_id not in self._executions:
            return False

        # Get execution state
        state = self._executions[execution_id]

        # Only resume if credentials expired
        if state.status != ExecutionStatus.CREDENTIALS_EXPIRED:
            return False

        # Check if credentials are now valid
        if not self.credential_manager.are_credentials_valid(state.environment):
            return False

        # Update execution state
        state.status = ExecutionStatus.RUNNING
        state.last_updated_at = time.time()
        state.credential_check_time = time.time()

        # If there's a current step, mark it as running
        if state.steps and state.current_step_idx < len(state.steps):
            step = state.steps[state.current_step_idx]
            if step.status == "paused":
                step.status = "running"

        logger.info(f"Resumed execution {execution_id}")
        return True

    def complete_step(
        self, execution_id: str, result: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Complete the current step of an execution

        Args:
            execution_id: ID of the execution
            result: Optional result of the step

        Returns:
            True if there are more steps, False if the execution is complete
        """
        if execution_id not in self._executions:
            return False

        # Get execution state
        state = self._executions[execution_id]

        # Only complete steps for running executions
        if state.status != ExecutionStatus.RUNNING:
            return False

        # If there's a current step, mark it as completed
        if state.steps and state.current_step_idx < len(state.steps):
            step = state.steps[state.current_step_idx]
            step.status = "completed"
            step.completed_at = time.time()
            if result:
                step.result = result

            # Store result in the overall results
            if result:
                state.results[step.name] = result

            # Update execution state
            state.current_step_idx += 1
            state.last_updated_at = time.time()

            # If there are more steps, start the next one
            if state.current_step_idx < len(state.steps):
                next_step = state.steps[state.current_step_idx]
                next_step.status = "running"
                next_step.started_at = time.time()
                logger.info(f"Execution {execution_id}: Started step {next_step.name}")
                return True
            else:
                # Execution is complete
                state.status = ExecutionStatus.COMPLETED
                logger.info(f"Completed execution {execution_id}")
                return False

        # No steps to complete
        return False

    def fail_step(self, execution_id: str, error: str) -> None:
        """Mark the current step of an execution as failed

        Args:
            execution_id: ID of the execution
            error: Error message
        """
        if execution_id not in self._executions:
            return

        # Get execution state
        state = self._executions[execution_id]

        # If there's a current step, mark it as failed
        if state.steps and state.current_step_idx < len(state.steps):
            step = state.steps[state.current_step_idx]
            step.status = "failed"
            step.error = error

        # Update execution state
        state.status = ExecutionStatus.FAILED
        state.last_updated_at = time.time()

        logger.error(f"Execution {execution_id} failed: {error}")

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get details of an execution

        Args:
            execution_id: ID of the execution

        Returns:
            Execution details or None if not found
        """
        if execution_id not in self._executions:
            return None

        state = self._executions[execution_id]
        # Use model_dump() instead of dict() for Pydantic v2 compatibility
        return cast(Dict[str, Any], state.model_dump())

    def list_executions(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all executions

        Args:
            status: Optional status to filter by

        Returns:
            List of execution summaries
        """
        executions = []

        for execution_id, state in self._executions.items():
            # Filter by status if provided
            if status and state.status != status:
                continue

            # Create execution summary
            executions.append(
                {
                    "id": execution_id,
                    "type": state.execution_type,
                    "environment": state.environment,
                    "status": state.status,
                    "started_at": state.started_at,
                    "last_updated_at": state.last_updated_at,
                }
            )

        return executions
