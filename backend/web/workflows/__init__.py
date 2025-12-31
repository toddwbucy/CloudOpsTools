"""Provider-agnostic workflow modules.

This package contains workflow implementations that use the provider
abstraction layer instead of direct cloud provider imports. Workflows
are designed to work with any registered provider (AWS, Azure, GCP)
through the standard ProviderBase interface.

Available modules:
    - auth: Authentication and credential management workflows
    - linux_qc_patching_prep: Linux QC patching preparation workflows
    - linux_qc_patching_post: Linux QC patching post-validation workflows
    - sft_fixer: System Fix Tool for instance remediation workflows
"""

from backend.web.workflows import auth, linux_qc_patching_prep, linux_qc_patching_post, sft_fixer

__all__ = ["auth", "linux_qc_patching_post", "linux_qc_patching_prep", "sft_fixer"]
