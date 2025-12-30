"""AWS provider package

Auto-imports all tool subpackages so they can register themselves with the core application.
"""

import logging
from importlib import import_module
from pkgutil import iter_modules

logger = logging.getLogger(__name__)

# Auto-import all tool subpackages so they can register themselves
for mod in iter_modules(__path__):
    try:
        import_module(f"{__name__}.{mod.name}")
        logger.debug(f"Imported AWS tool: {mod.name}")
    except ImportError as e:
        logger.warning(f"Failed to import AWS tool {mod.name}: {e}")
