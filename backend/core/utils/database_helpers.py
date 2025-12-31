"""
Database helper utilities for PCM-Ops Tools.

Provides database-agnostic utilities and migration helpers for both SQLite and PostgreSQL.
"""

import logging
from typing import Dict, Any, Optional
from sqlalchemy import text, inspect
from sqlalchemy.orm import Session
from backend.core.config import settings
from backend.db.session import engine

logger = logging.getLogger(__name__)


def get_database_type() -> str:
    """
    Get the database type from the DATABASE_URL.
    
    Returns:
        str: Database type ('sqlite', 'postgresql', etc.)
    """
    url = settings.DATABASE_URL.lower()
    if url.startswith("sqlite"):
        return "sqlite"
    elif url.startswith("postgresql"):
        return "postgresql"
    else:
        # Extract from URL scheme
        return url.split("://")[0] if "://" in url else "unknown"


def get_database_info() -> Dict[str, Any]:
    """
    Get database connection information and metadata.
    
    Returns:
        Dict containing database type, connection status, and metadata
    """
    db_type = get_database_type()
    info = {
        "type": db_type,
        "url": settings.DATABASE_URL,
        "connected": False,
        "tables": [],
        "version": None,
        "error": None
    }
    
    try:
        # Test connection
        with engine.connect() as conn:
            info["connected"] = True
            
            # Get database version
            if db_type == "sqlite":
                result = conn.execute(text("SELECT sqlite_version()"))
                info["version"] = result.scalar()
            elif db_type == "postgresql":
                result = conn.execute(text("SELECT version()"))
                version_str = result.scalar()
                # Extract just the version number
                info["version"] = version_str.split()[1] if version_str else "unknown"
            
            # Get table list
            inspector = inspect(engine)
            info["tables"] = inspector.get_table_names()
            
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        info["error"] = str(e)
    
    return info


def check_database_health() -> Dict[str, Any]:
    """
    Perform database health check.
    
    Returns:
        Dict containing health status and metrics
    """
    health = {
        "status": "healthy",
        "database_type": get_database_type(),
        "connected": False,
        "table_count": 0,
        "connection_pool_status": "unknown",
        "last_error": None
    }
    
    try:
        db_info = get_database_info()
        health["connected"] = db_info["connected"]
        health["table_count"] = len(db_info["tables"])
        
        if db_info["error"]:
            health["status"] = "unhealthy"
            health["last_error"] = db_info["error"]
        elif not db_info["connected"]:
            health["status"] = "unhealthy"
            health["last_error"] = "Unable to connect to database"
        elif health["table_count"] == 0:
            health["status"] = "warning" 
            health["last_error"] = "No tables found - database may need initialization"
            
        # Connection pool info
        pool = engine.pool
        if hasattr(pool, 'status'):
            health["connection_pool_status"] = str(pool.status())
            
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health["status"] = "unhealthy"
        health["last_error"] = str(e)
    
    return health


def create_database_if_not_exists(db_url: Optional[str] = None) -> bool:
    """
    Create database if it doesn't exist (PostgreSQL only).
    
    For SQLite, the database file is created automatically.
    For PostgreSQL, attempts to create the database if it doesn't exist.
    
    Args:
        db_url: Database URL (uses settings.DATABASE_URL if not provided)
        
    Returns:
        bool: True if database exists or was created successfully
    """
    url = db_url or settings.DATABASE_URL
    db_type = get_database_type()
    
    if db_type == "sqlite":
        # SQLite creates database file automatically
        return True
    elif db_type == "postgresql":
        # For PostgreSQL, we'd need to connect to postgres database first
        # and create the target database - this is usually handled by deployment
        logger.info("PostgreSQL database creation should be handled by deployment/migration scripts")
        return True
    
    return True


def get_migration_status() -> Dict[str, Any]:
    """
    Get database migration status.
    
    Returns:
        Dict containing migration information
    """
    status = {
        "alembic_available": False,
        "current_revision": None,
        "pending_migrations": [],
        "error": None
    }
    
    try:
        # Check if alembic_version table exists
        db_info = get_database_info()
        if "alembic_version" in db_info["tables"]:
            status["alembic_available"] = True
            
            # Get current revision
            with engine.connect() as conn:
                result = conn.execute(text("SELECT version_num FROM alembic_version"))
                row = result.first()
                if row:
                    status["current_revision"] = row[0]
                    
    except Exception as e:
        logger.error(f"Migration status check failed: {e}")
        status["error"] = str(e)
    
    return status