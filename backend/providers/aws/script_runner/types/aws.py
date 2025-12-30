"""Type definitions for AWS services"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

# Environment types
Environment = Literal["gov", "com"]

# AWS Region types
RegionName = str
GovRegion = Literal["us-gov-west-1", "us-gov-east-1"]
ComRegion = Literal["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
AWSRegion = Union[GovRegion, ComRegion]

# AWS Account types
AccountId = str


# AWS Credentials
class AWSCredentialsDict(TypedDict):
    """Type for AWS credentials dictionary"""

    AccessKeyId: str
    SecretAccessKey: str
    SessionToken: str  # Required for STS credentials
    Expiration: Optional[datetime]


# EC2 Instance types
InstanceId = str
InstanceState = Literal[
    "pending", "running", "shutting-down", "terminated", "stopping", "stopped"
]
Platform = Literal["linux", "windows"]


class EC2InstanceDict(TypedDict):
    """Type for EC2 instance dictionary"""

    InstanceId: InstanceId
    State: Dict[str, str]
    PrivateIpAddress: Optional[str]
    PublicIpAddress: Optional[str]
    Platform: Optional[str]
    Tags: List[Dict[str, str]]


# SSM Command types
CommandId = str
CommandStatus = Literal[
    "Pending", "InProgress", "Success", "Cancelled", "Failed", "TimedOut", "Cancelling"
]


class SSMCommandDict(TypedDict):
    """Type for SSM command dictionary"""

    CommandId: CommandId
    Status: CommandStatus
    InstanceId: InstanceId
    DocumentName: str
    RequestedDateTime: datetime
    ExpiresAfter: datetime


class SSMCommandInvocationDict(TypedDict):
    """Type for SSM command invocation dictionary"""

    CommandId: CommandId
    InstanceId: InstanceId
    Status: CommandStatus
    StatusDetails: str
    StandardOutputContent: str
    StandardErrorContent: str
    ResponseCode: int


# Service result types
class SessionResult(TypedDict, total=False):
    """Type for session creation results"""

    status: str
    session: Optional[Any]
    message: str


class CommandResult(TypedDict, total=False):
    """Type for command execution results"""

    CommandId: CommandId
    InstanceId: InstanceId
    Status: str
    StatusDetails: str
    Output: str
    Error: str
    ExitCode: int
