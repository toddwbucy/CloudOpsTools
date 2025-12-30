#!/usr/bin/env python3
"""
Database setup script for PCM-Ops Tools.

This script initializes the database with proper tables for both SQLite and PostgreSQL.
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from backend.core.config import settings
from backend.core.utils.database_helpers import get_database_info, check_database_health
from backend.db.init_db import init_database


def main():
    """Initialize database based on configuration"""
    print("🗄️  PCM-Ops Tools Database Setup")
    print("=" * 40)
    
    # Show database configuration
    print(f"Database URL: {settings.DATABASE_URL}")
    
    # Get database info
    db_info = get_database_info()
    print(f"Database Type: {db_info['type']}")
    print(f"Connected: {db_info['connected']}")
    
    if db_info['error']:
        print(f"❌ Connection Error: {db_info['error']}")
        return False
    
    if db_info['version']:
        print(f"Database Version: {db_info['version']}")
    
    print(f"Existing Tables: {len(db_info['tables'])}")
    if db_info['tables']:
        for table in sorted(db_info['tables']):
            print(f"  - {table}")
    
    print("\n🔧 Initializing database...")
    
    try:
        # Initialize database (create tables)
        init_database()
        print("✅ Database initialized successfully!")
        
        # Check final status
        health = check_database_health()
        print(f"Health Status: {health['status']}")
        print(f"Table Count: {health['table_count']}")
        
        if health['status'] != 'healthy':
            print(f"⚠️  Warning: {health['last_error']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)