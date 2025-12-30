"""Script and tool schema definitions."""
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ToolBase(BaseModel):
    """Base schema for Tool"""

    name: str = Field(..., description="Tool name")
    description: Optional[str] = Field(None, description="Tool description")
    tool_type: str = Field(..., description="Tool type")
    platform: Optional[str] = Field(
        None, description="Platform the tool runs on (linux, windows, etc.)"
    )


class ToolCreate(ToolBase):
    """Schema for creating a Tool"""

    pass


class Tool(ToolBase):
    """Schema for Tool response"""

    id: int

    model_config = ConfigDict(from_attributes=True)


class ScriptBase(BaseModel):
    """Base schema for Script"""

    name: str = Field(..., description="Script name")
    content: str = Field(..., description="Script content")
    description: Optional[str] = Field(None, description="Script description")
    script_type: str = Field(..., description="Script type (bash, powershell, etc.)")


class ScriptCreate(ScriptBase):
    """Schema for creating a Script"""

    tool_id: Optional[int] = Field(
        None, description="Optional tool ID to associate with this script"
    )


class Script(ScriptBase):
    """Schema for Script response"""

    id: int
    tool_id: Optional[int] = None
    tool: Optional[Tool] = None

    model_config = ConfigDict(from_attributes=True)


class ScriptList(BaseModel):
    """Schema for listing Scripts"""

    scripts: List[Script]
    total: int
    skip: int = 0
    limit: int = 100

    model_config = ConfigDict(from_attributes=True)
