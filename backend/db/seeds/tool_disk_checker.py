#!/usr/bin/env python3
"""
Seed file for Disk Checker Tool
"""

import logging
from sqlalchemy.orm import Session

from backend.db.models.script import Tool

logger = logging.getLogger("cloudopstools.seeds")


def create_disk_checker_tool(db: Session) -> Tool:
    """
    Create the disk checker tool in the database if it doesn't exist
    """
    # Check if tool already exists
    existing_tool = db.query(Tool).filter(Tool.name == "disk_checker").first()

    if existing_tool:
        logger.info("Disk checker tool already exists", extra={
            "tool_id": existing_tool.id,
            "tool_name": existing_tool.name
        })
        # Use explicit cast to fix the return type
        from typing import cast

        return cast(Tool, existing_tool)

    # Create the tool
    # Add type annotation to make mypy happy
    disk_checker: Tool = Tool(
        name="disk_checker",
        description="Comprehensive disk information gathering tool. Checks all drives, UUIDs, disk space, and LVM configuration.",
        script_path="/scripts/disk_checker.sh",
        platform="linux",
        parameters={
            "output_format": {
                "type": "string",
                "description": "Output format (json or text)",
                "default": "json",
                "enum": ["json", "text"],
            },
            "output_file": {
                "type": "string",
                "description": "Optional path to save output file on the target host",
                "required": False,
            },
        },
        version="1.0.0",
        is_active=True,
    )

    db.add(disk_checker)
    db.commit()
    db.refresh(disk_checker)

    logger.info("Created disk checker tool", extra={
        "tool_id": disk_checker.id,
        "tool_name": disk_checker.name,
        "version": disk_checker.version,
        "platform": disk_checker.platform
    })
    return disk_checker


if __name__ == "__main__":
    # This allows running the file directly to seed the database
    from backend.db.session import SessionLocal

    db = SessionLocal()
    try:
        create_disk_checker_tool(db)
    finally:
        db.close()
