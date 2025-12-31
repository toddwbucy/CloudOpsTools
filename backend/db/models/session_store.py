from typing import Any, Optional

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base


class SessionData(Base):
    """Server-side session data storage for large transient payloads."""

    # Base provides: id, created_at, updated_at
    key: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    data: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[Optional[DateTime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SessionData(key={self.key!r})>"

