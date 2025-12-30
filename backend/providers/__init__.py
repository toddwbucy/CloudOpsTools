"""Provider package for dynamic tool discovery"""

import logging
import pkgutil
from importlib import import_module
from typing import Any, Dict, List

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def discover_provider_routers(app: FastAPI) -> Dict[str, List[Dict[str, Any]]]:
    """Discover and import all provider routers dynamically"""
    # Dynamically discover provider directories
    import os

    provider_dir = os.path.dirname(os.path.abspath(__file__))
    providers = []

    for item in os.listdir(provider_dir):
        item_path = os.path.join(provider_dir, item)
        # Skip non-directories, hidden files, __pycache__, and other non-provider items
        if (
            os.path.isdir(item_path)
            and not item.startswith(".")
            and not item.startswith("__")
            and item not in ["README.md"]
        ):
            providers.append(item)

    # Sort providers for consistent ordering
    providers.sort()
    logger.info(f"Discovered providers: {providers}")

    # Track discovered routers for the providers endpoint
    discovered_providers: Dict[str, List[Dict[str, Any]]] = {}

    for provider in providers:
        try:
            # Try to import the provider package
            provider_pkg = import_module(f"backend.providers.{provider}")
            logger.info(f"Discovered provider: {provider}")
            discovered_providers[provider] = []

            # Look for tools in this provider
            tools_path = provider_pkg.__path__
            for tool_mod in pkgutil.iter_modules(tools_path):
                tool_name = tool_mod.name

                # Skip the common module which isn't a tool
                if tool_name == "common":
                    continue

                try:
                    # Import the tool module and check if it has routers
                    tool_pkg = import_module(
                        f"backend.providers.{provider}.{tool_name}"
                    )

                    if hasattr(tool_pkg, "routers"):
                        # Register all routers from this tool
                        for router, prefix in tool_pkg.routers:
                            tag = f"{provider.upper()} {tool_name.replace('_', ' ').title()}"
                            app.include_router(
                                router, prefix=f"/api{prefix}", tags=[tag]
                            )

                        # Add to discovered providers for the providers endpoint
                        tool_info = {
                            "name": tool_name,
                            "description": (
                                tool_pkg.__doc__.split("\n")[0]
                                if tool_pkg.__doc__
                                else ""
                            ),
                            "endpoints": [
                                f"/api{prefix}" for _, prefix in tool_pkg.routers
                            ],
                        }
                        discovered_providers[provider].append(tool_info)
                        logger.info(f"Registered tool: {provider}.{tool_name}")
                except (ImportError, AttributeError) as e:
                    logger.warning(f"Could not load tool {provider}.{tool_name}: {e}")
        except ImportError as e:
            logger.debug(f"Provider {provider} not available: {e}")

    return discovered_providers
