from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (  # type: ignore[attr-defined]
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.sql import func

from backend.db.base import Base

# Handle circular imports
if TYPE_CHECKING:
    from backend.db.models.script import Script


class Execution(Base):
    """Model for script execution records"""

    # Typed columns
    script_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("script.id"), nullable=False
    )
    instance_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )  # EC2 instance ID
    account_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(
        String, nullable=False, default="pending"
    )  # pending, running, completed, failed
    start_time: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    command_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )  # SSM command ID
    batch_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )  # Batch identifier
    change_number: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )  # Change management number
    execution_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )  # Store additional data

    # Relationships
    script: Mapped["Script"] = relationship("Script", back_populates="executions")

    def __repr__(self) -> str:
        return f"<Execution(id={self.id}, script_id={self.script_id}, instance_id={self.instance_id}, status='{self.status}')>"


class ExecutionBatch(Base):
    """Model for batch execution records"""

    # Typed columns
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    script_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("script.id"), nullable=False
    )
    total_instances: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_instances: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_instances: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Table-level constraints
    __table_args__ = (
        CheckConstraint(
            "completed_instances >= 0", name="check_completed_instances_non_negative"
        ),
        CheckConstraint(
            "failed_instances >= 0", name="check_failed_instances_non_negative"
        ),
        CheckConstraint(
            "completed_instances + failed_instances <= total_instances",
            name="check_instances_sum_not_exceed_total",
        ),
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "pending", "running", "completed", "failed", name="execution_batch_status"
        ),
        nullable=False,
        default="pending",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )
    batch_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )  # Store additional data

    # Relationships
    script: Mapped["Script"] = relationship(
        "Script", back_populates="execution_batches"
    )

    def __repr__(self) -> str:
        return f"<ExecutionBatch(id={self.id}, script_id={self.script_id}, status='{self.status}')>"
