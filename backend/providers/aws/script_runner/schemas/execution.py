from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, ConfigDict


class ExecutionStatus(str, Enum):
    """Enum for execution status values"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionBase(BaseModel):
    """Base schema for Execution"""

    script_id: int = Field(..., description="ID of the script to execute")
    instance_id: Union[int, str] = Field(
        ...,
        description="ID of the instance to run the script on (can be database ID or AWS instance ID)",
    )


class ExecutionCreate(ExecutionBase):
    """Schema for creating an Execution"""

    parameters: Optional[Dict[str, Any]] = Field(
        None, description="Optional parameters for script execution"
    )


class Execution(ExecutionBase):
    """Schema for Execution response"""

    id: int
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    output: Optional[str] = None
    exit_code: Optional[int] = None
    command_id: Optional[str] = None
    batch_id: Optional[int] = None
    script_name: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionList(BaseModel):
    """Schema for listing Executions"""

    executions: List[Execution]
    total: int

    model_config = ConfigDict(from_attributes=True)


class ExecutionBatchBase(BaseModel):
    """Base schema for ExecutionBatch"""

    name: str = Field(..., description="Batch name")
    description: Optional[str] = Field(None, description="Batch description")


class InstanceData(BaseModel):
    """Schema for instance data in execution requests"""

    instance_id: str = Field(..., description="AWS instance ID")
    account_id: str = Field(..., description="AWS account ID")
    region: str = Field(..., description="AWS region")
    environment: str = Field(..., description="AWS environment (com/gov)")


class ExecutionBatchCreate(BaseModel):
    """Schema for creating an ExecutionBatch"""

    script_id: int = Field(..., description="ID of the script to execute")
    instances: List[InstanceData] = Field(
        ..., description="List of instances to run the script on"
    )
    change_number: Optional[str] = Field(
        None, description="Change number for this execution"
    )
    parameters: Optional[Dict[str, Any]] = Field(
        None, description="Optional parameters for script execution"
    )

    # Optional fields for backwards compatibility (auto-generated if not provided)
    name: Optional[str] = Field(
        None, description="Batch name (auto-generated if not provided)"
    )
    description: Optional[str] = Field(None, description="Batch description")


class ExecutionBatch(ExecutionBatchBase):
    """Schema for ExecutionBatch response"""

    id: int
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    parameters: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionProgress(BaseModel):
    """Schema for execution progress"""

    total_instances: int
    completed_instances: int
    failed_instances: int
    pending_instances: int
    overall_status: ExecutionStatus


class CommandInfo(BaseModel):
    """Schema for command information"""

    account: str = Field(..., description="AWS account ID")
    region: str = Field(..., description="AWS region")
    instanceIDs: List[str] = Field(
        ..., description="List of instance IDs for this command"
    )


class ExecutionBatchWithCommands(BaseModel):
    """Schema for ExecutionBatch response with command ID mapping"""

    batch_id: int = Field(..., description="Batch ID")
    status: ExecutionStatus = Field(..., description="Overall batch status")
    start_time: datetime = Field(..., description="Batch start time")
    command_mapping: Dict[str, CommandInfo] = Field(
        ..., description="Mapping of command IDs to their details"
    )
    total_instances: int = Field(..., description="Total number of instances")
    change_number: Optional[str] = Field(
        None, description="Change number for this execution"
    )


class ExecutionReport(BaseModel):
    """Schema for execution reports"""

    report_id: str = Field(..., description="Unique report identifier")
    executions: List[Execution] = Field(..., description="List of executions in report")
    metadata: Dict[str, Any] = Field(..., description="Report metadata")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    total_executions: int = Field(..., description="Total number of executions")
    success_count: int = Field(..., description="Number of successful executions")
    failure_count: int = Field(..., description="Number of failed executions")

    model_config = ConfigDict(from_attributes=True)
