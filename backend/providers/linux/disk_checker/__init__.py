"""Linux Disk Checker tool package

Exposes API routers and services for the Linux Disk Checker tool.
"""

import logging
from typing import Any, List, Tuple

# Import API routers - these will be implemented later
routers: List[Tuple[Any, str]] = [
    # Future API endpoints will be added here
    # Example: (disk_checker_router, "/tools/linux/disk-checker")
]

logger = logging.getLogger(__name__)
logger.info("Linux Disk Checker tool initialized")
