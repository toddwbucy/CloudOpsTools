"""Provider-agnostic workflow modules.

This package contains workflow implementations that use the provider
abstraction layer instead of direct cloud provider imports. Workflows
are designed to work with any registered provider (AWS, Azure, GCP)
through the standard ProviderBase interface.

Available modules:
    - auth: Authentication and credential management workflows
"""

from backend.web.workflows import auth

__all__ = ["auth"]
