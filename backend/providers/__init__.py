"""Cloud provider abstraction layer.

This module provides a provider abstraction pattern for multi-cloud support.
It includes a registry of available providers and a factory function for
instantiating providers by name.

Example usage:
    from backend.providers import get_provider, list_providers

    # Get list of available providers
    providers = list_providers()  # ["aws"]

    # Create a provider instance
    provider = get_provider("aws", {"access_key": "...", "secret_key": "..."})

    # Use the provider interface
    is_valid = await provider.validate_credentials(credentials)
"""

from typing import Any, Dict, List, Type

from backend.providers.aws import AWSProvider
from backend.providers.base import ProviderBase

# Provider registry mapping provider names to their implementation classes
# New providers are registered here as they are implemented
_PROVIDER_REGISTRY: Dict[str, Type[ProviderBase]] = {
    "aws": AWSProvider,
    # Future: "azure": AzureProvider, "gcp": GCPProvider
}


def register_provider(name: str, provider_class: Type[ProviderBase]) -> None:
    """Register a provider implementation in the registry.

    Args:
        name: Provider identifier (e.g., "aws", "azure", "gcp").
        provider_class: Provider class implementing ProviderBase.

    Raises:
        TypeError: If provider_class does not inherit from ProviderBase.
        ValueError: If provider name is already registered.
    """
    if not issubclass(provider_class, ProviderBase):
        raise TypeError(
            f"Provider class must inherit from ProviderBase, got {provider_class}"
        )
    if name in _PROVIDER_REGISTRY:
        raise ValueError(f"Provider '{name}' is already registered")
    _PROVIDER_REGISTRY[name] = provider_class


def get_provider(provider_name: str, credentials: Dict[str, Any]) -> ProviderBase:
    """Factory function to get a provider instance.

    Creates and returns an instance of the specified provider, initialized
    with the provided credentials.

    Args:
        provider_name: Provider identifier (e.g., "aws", "azure", "gcp").
        credentials: Provider-specific credential dictionary.

    Returns:
        An instance of the requested provider implementing ProviderBase.

    Raises:
        ValueError: If provider_name is not registered.

    Example:
        provider = get_provider("aws", {
            "access_key_id": "AKIA...",
            "secret_access_key": "..."
        })
    """
    if provider_name not in _PROVIDER_REGISTRY:
        available = list(_PROVIDER_REGISTRY.keys())
        raise ValueError(
            f"Unknown provider: '{provider_name}'. "
            f"Available providers: {available or 'none registered'}"
        )

    provider_class = _PROVIDER_REGISTRY[provider_name]
    return provider_class(credentials)


def list_providers() -> List[str]:
    """List all registered provider names.

    Returns:
        List of registered provider identifiers.
    """
    return list(_PROVIDER_REGISTRY.keys())


def is_provider_registered(provider_name: str) -> bool:
    """Check if a provider is registered.

    Args:
        provider_name: Provider identifier to check.

    Returns:
        True if the provider is registered, False otherwise.
    """
    return provider_name in _PROVIDER_REGISTRY


# Re-export base classes and providers for convenience
__all__ = [
    "AWSProvider",
    "ProviderBase",
    "get_provider",
    "register_provider",
    "list_providers",
    "is_provider_registered",
]
