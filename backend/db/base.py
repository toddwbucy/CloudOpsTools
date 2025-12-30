from datetime import datetime

from sqlalchemy import DateTime, Integer, MetaData
from sqlalchemy.ext.declarative import declared_attr

# Import SQLAlchemy 2.0 features with type ignores for compatibility with mypy stubs
from sqlalchemy.orm import (
    DeclarativeBase,  # type: ignore[attr-defined]
    Mapped,  # type: ignore
    mapped_column,  # type: ignore[attr-defined]
    registry,  # type: ignore
)
from sqlalchemy.sql import func

# Define naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=convention)
mapper_registry = registry(metadata=metadata)


class Base(DeclarativeBase):
    """Base class for all database models."""

    # Use the mapper registry
    registry = mapper_registry
    metadata = metadata

    # Tablename is automatically derived from the class name
    @declared_attr  # type: ignore[arg-type]
    @classmethod
    def __tablename__(cls) -> str:
        return cls.__name__.lower()

    # Common columns for all models
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )
