"""CloudOpsTools Feature Flags Module"""

# Simple feature flag storage
_feature_flags = {}


def is_feature_enabled(feature_name: str) -> bool:
    """Check if a feature flag is enabled"""
    return _feature_flags.get(feature_name, False)


def set_feature_flag(feature_name: str, enabled: bool) -> None:
    """Set a feature flag"""
    _feature_flags[feature_name] = enabled
