from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class ChangeInstanceBase(BaseModel):
    """Base schema for change instance data"""

    instance_id: str
    account_id: str
    region: str
    platform: str
    instance_metadata: Optional[Dict[str, Any]] = None


class ChangeInstanceCreate(ChangeInstanceBase):
    """Schema for creating a change instance"""

    pass


class ChangeInstance(ChangeInstanceBase):
    """Schema for returned change instance data"""

    id: int
    change_id: int

    model_config = ConfigDict(from_attributes=True)


class ChangeBase(BaseModel):
    """Base schema for change data"""

    change_number: str
    description: Optional[str] = None
    status: str = "new"
    change_metadata: Optional[Dict[str, Any]] = None


class ChangeCreate(ChangeBase):
    """Schema for creating a change"""

    instances: List[ChangeInstanceCreate]


class Change(ChangeBase):
    """Schema for returned change data"""

    id: int
    created_at: datetime
    updated_at: datetime
    instances: List[ChangeInstance]

    model_config = ConfigDict(from_attributes=True)


class ChangeList(BaseModel):
    """Schema for returning a list of changes"""

    changes: List[Change]
    total: int


class ChangedInstanceDetail(BaseModel):
    """Schema for instance change details"""

    instance_id: str
    old: Dict[str, str]
    new: Dict[str, str]


class ChangeDiff(BaseModel):
    """Schema for comparing changes"""

    change_number: str
    existing: Change
    new: ChangeCreate
    added_instances: List[str]
    removed_instances: List[str]
    changed_instances: List[ChangedInstanceDetail]
