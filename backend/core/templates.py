"""Shared template configuration for web routes"""

from pathlib import Path
from typing import List, Tuple, Union

from fastapi.templating import Jinja2Templates

# Get backend directory
BACKEND_DIR = Path(__file__).parent.parent

# Create shared templates instance
templates = Jinja2Templates(directory=str(BACKEND_DIR / "templates"))


# Add Flask-compatible template functions
def get_flashed_messages(
    with_categories: bool = False,
) -> Union[List[str], List[Tuple[str, str]]]:
    """Stub for Flask's get_flashed_messages

    Args:
        with_categories: If True, returns messages with categories.

    Returns:
        List[Tuple[str, str]]: Empty list of (category, message) tuples when with_categories is True
        List[str]: Empty list of messages when with_categories is False
    """
    if with_categories:
        # Return empty list of (category, message) tuples when categories requested
        return []
    return []


# Register global functions
templates.env.globals["get_flashed_messages"] = get_flashed_messages

# Export for use in routes
__all__ = ["templates"]
