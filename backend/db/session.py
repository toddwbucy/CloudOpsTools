from contextlib import contextmanager
from typing import Generator, Dict, Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import settings

# Determine database-specific connection arguments
def get_connect_args() -> Dict[str, Any]:
    """Get database-specific connection arguments"""
    if settings.DATABASE_URL.startswith("sqlite"):
        # SQLite needs check_same_thread=False for FastAPI
        return {"check_same_thread": False}
    # PostgreSQL and other databases don't need special args
    return {}

# Create database engine with appropriate connection args
engine = create_engine(
    settings.DATABASE_URL,
    connect_args=get_connect_args(),
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for getting DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_sync() -> Generator[Session, None, None]:
    """Get a synchronous DB session for background tasks with proper resource management"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
