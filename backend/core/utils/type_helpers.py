"""
Helper functions for ensuring type safety with mypy.
"""

from typing import Any, List, Optional, Sequence, TypeVar

T = TypeVar("T")
U = TypeVar("U")


def safe_str(value: Optional[Any]) -> str:
    """
    Convert a value to string safely, with explicit cast for mypy.

    Args:
        value: Value to convert to string

    Returns:
        String representation of value, or empty string if None
    """
    if value is None:
        return ""  # Return empty string instead of None
    return str(value)


def safe_list(value: Optional[List[T]]) -> List[T]:
    """
    Ensure a list is never None for mypy.

    Args:
        value: List to make safe

    Returns:
        Original list or empty list if None
    """
    if value is None:
        return []
    return value


def safe_int(
    value: Any,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    default: int = 0,
) -> int:
    """
    Ensure a value is an integer for mypy with optional bounds checking.

    Args:
        value: Value to convert to int
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        default: Default value if conversion fails or out of bounds

    Returns:
        Integer value within bounds, or default if None/conversion fails/out of bounds
    """
    if value is None:
        return default
    try:
        result = int(value)

        # Apply bounds checking
        if min_val is not None and result < min_val:
            return min_val
        if max_val is not None and result > max_val:
            return max_val

        return result
    except (ValueError, TypeError):
        return default


def safe_sqlalchemy_in(value: Optional[Sequence[U]]) -> List[U]:
    """
    Create a safe list for SQLAlchemy in_() operations that won't cause mypy errors.

    Args:
        value: A sequence (list, tuple, etc.) or None

    Returns:
        A list guaranteed to be non-None for SQLAlchemy in_() operations
    """
    # Return an empty list if None which will work with SQLAlchemy's in_()
    if value is None:
        return []
    # Convert to list to ensure it's the expected type
    return list(value)
