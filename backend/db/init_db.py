#!/usr/bin/env python3
"""Initialize the database with proper schema"""

import logging
import sys
from pathlib import Path

# Add the backend directory to Python path using absolute path
backend_dir = Path(__file__).parent.parent.parent.resolve()
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from backend.db.base import Base
from backend.db.session import engine

logger = logging.getLogger("cloudopstools.database")

# Import all models explicitly to register them with SQLAlchemy
# This ensures all tables are created when create_all() is called
from backend.db.models import account as _model_account  # noqa: F401
from backend.db.models import change as _model_change  # noqa: F401
from backend.db.models import execution as _model_execution  # noqa: F401
from backend.db.models import script as _model_script  # noqa: F401
from backend.db.models import session_store as _model_session_store  # noqa: F401


def init_database():
    """Create all tables with proper schema"""
    try:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully!")

        # Log table info with structured data
        table_names = [table.name for table in Base.metadata.sorted_tables]
        logger.info("Created database tables", extra={
            "table_count": len(table_names),
            "tables": table_names
        })
        
        for table_name in table_names:
            logger.debug(f"Created table: {table_name}")
            
    except Exception as e:
        logger.error(f"Error initializing database: {e}", extra={
            "error_type": type(e).__name__,
            "database_url": "[REDACTED]"  # Don't log connection strings
        })
        logger.error("Please check database connection settings and permissions.")
        raise


if __name__ == "__main__":
    init_database()
