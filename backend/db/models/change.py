from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import (  # type: ignore[attr-defined]
    Mapped,
    mapped_column,
    relationship,
)

from backend.db.base import Base

# Handle circular imports
if TYPE_CHECKING:
    from backend.db.models.script import Script


class Change(Base):
    """Model for AWS change records"""

    # Typed columns
    id: Mapped[int] = mapped_column(primary_key=True)
    change_number: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String, nullable=False, default="new"
    )  # new, approved, completed, etc.
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    change_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )  # For additional change details

    # Relationships
    instances: Mapped[List["ChangeInstance"]] = relationship(
        "ChangeInstance", back_populates="change", cascade="all, delete-orphan"
    )
    scripts: Mapped[List["Script"]] = relationship(
        "Script", back_populates="change", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Change(id={self.id}, change_number='{self.change_number}', status='{self.status}')>"


class ChangeInstance(Base):
    """Model for linking changes with instances"""

    # Typed columns
    id: Mapped[int] = mapped_column(primary_key=True)
    change_id: Mapped[int] = mapped_column(ForeignKey("change.id"), nullable=False)
    instance_id: Mapped[str] = mapped_column(
        String, nullable=False
    )  # AWS instance ID (not FK to allow storing instances not in our DB)
    account_id: Mapped[str] = mapped_column(String, nullable=False)  # AWS account ID
    region: Mapped[str] = mapped_column(String, nullable=False)  # AWS region
    platform: Mapped[str] = mapped_column(String, nullable=False)  # linux or windows
    instance_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )  # For additional instance details

    # Relationships
    change: Mapped["Change"] = relationship("Change", back_populates="instances")

    def __repr__(self) -> str:
        return f"<ChangeInstance(id={self.id}, change_id={self.change_id}, instance_id='{self.instance_id}')>"
