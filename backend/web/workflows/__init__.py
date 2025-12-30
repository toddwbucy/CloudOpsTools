"""Provider-agnostic workflow modules.

This package contains workflow implementations that use the provider
abstraction layer instead of direct cloud provider imports. Workflows
are designed to work with any registered provider (AWS, Azure, GCP)
through the standard ProviderBase interface.

Available modules:
    - auth: Authentication and credential management workflows
    - linux_qc_patching_prep: Linux QC patching preparation workflows
"""

from backend.web.workflows import auth, linux_qc_patching_prep

__all__ = ["auth", "linux_qc_patching_prep"]
