from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict


class AWSCredentialsRequest(BaseModel):
    """Schema for AWS credentials included in API requests"""

    access_key: str = Field(..., description="AWS access key ID")
    secret_key: str = Field(..., description="AWS secret access key")
    session_token: Optional[str] = Field(
        None, description="AWS session token (for temporary credentials)"
    )
    environment: str = Field(..., description="AWS environment (gov or com)")


class RegionBase(BaseModel):
    """Base schema for Region"""

    name: str = Field(..., description="Region name (e.g., us-east-1)")


class RegionCreate(RegionBase):
    """Schema for creating a Region"""

    pass


class Region(RegionBase):
    """Schema for Region response"""

    id: int
    account_id: int

    model_config = ConfigDict(from_attributes=True)


class AccountBase(BaseModel):
    """Base schema for Account"""

    account_id: str = Field(..., description="AWS account ID")
    name: Optional[str] = Field(None, description="Account name or description")
    environment: str = Field(..., description="AWS environment (gov or com)")


class AccountCreate(AccountBase):
    """Schema for creating an Account"""

    regions: List[RegionCreate] = Field(
        default_factory=list, description="List of regions associated with this account"
    )


class Account(AccountBase):
    """Schema for Account response"""

    id: int
    active: bool
    regions: List[Region] = []

    model_config = ConfigDict(from_attributes=True)


class InstanceBase(BaseModel):
    """Base schema for Instance"""

    instance_id: str = Field(..., description="EC2 instance ID")
    platform: str = Field(..., description="Instance platform (linux or windows)")


class InstanceCreate(InstanceBase):
    """Schema for creating an Instance"""

    region_id: int = Field(..., description="Region ID this instance belongs to")


class Instance(InstanceBase):
    """Schema for Instance response"""

    id: int
    region_id: int

    model_config = ConfigDict(from_attributes=True)


class AWSCredentials(BaseModel):
    """Schema for AWS credentials"""

    access_key: str
    secret_key: str
    session_token: str  # Required for STS credentials
    expiration: float
    environment: str

    model_config = ConfigDict(from_attributes=True, extra="allow")
