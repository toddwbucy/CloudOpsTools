"""Abstract base class for cloud provider implementations.

This module defines the provider interface contract that all cloud provider
implementations (AWS, Azure, GCP) must conform to. This enables provider-agnostic
workflows in the web layer.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ProviderBase(ABC):
    """Abstract base class for cloud provider implementations.

    All cloud providers must implement these methods to ensure consistent
    behavior across different cloud platforms. Methods are async to support
    non-blocking I/O operations with cloud APIs.

    Example usage:
        provider = get_provider("aws", credentials)
        is_valid = await provider.validate_credentials(credentials)
        instances = await provider.discover_instances({"tag:Environment": "prod"})
    """

    @abstractmethod
    async def validate_credentials(self, credentials: Dict[str, str]) -> bool:
        """Validate provider credentials.

        Args:
            credentials: Provider-specific credential dictionary.
                For AWS: {"access_key_id": "...", "secret_access_key": "..."}

        Returns:
            True if credentials are valid and have appropriate permissions,
            False otherwise.

        Raises:
            ValueError: If required credential fields are missing.
        """
        pass

    @abstractmethod
    async def discover_instances(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Discover instances based on filters.

        Args:
            filters: Provider-specific filter criteria. For AWS, this maps to
                EC2 describe_instances filters (e.g., {"tag:Name": "web-*"}).
                If None, returns all accessible instances.

        Returns:
            List of instance dictionaries with at minimum:
                - instance_id: str
                - state: str (running, stopped, etc.)
                - tags: Dict[str, str]
                - account_id: str
                - region: str
        """
        pass

    @abstractmethod
    async def execute_script(
        self,
        instance_id: str,
        script_content: str,
        interpreter: str,
        account_id: str,
        region: str,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """Execute script on a single instance.

        Uses provider-specific remote execution service (e.g., AWS SSM,
        Azure Run Command, GCP OS Config).

        Args:
            instance_id: Target instance identifier.
            script_content: Script content to execute.
            interpreter: Script interpreter (e.g., "bash", "powershell").
            account_id: Provider account/subscription identifier.
            region: Target region for the operation.
            timeout: Maximum execution time in seconds (default: 300).

        Returns:
            Dictionary with execution results:
                - status: str ("success", "failed", "timeout")
                - output: str (stdout from script)
                - error: str (stderr from script, if any)
                - exit_code: int
                - instance_id: str
        """
        pass

    @abstractmethod
    async def execute_script_batch(
        self,
        instance_ids: List[str],
        script_content: str,
        interpreter: str,
        account_id: str,
        region: str,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """Execute script on multiple instances in batch.

        Uses provider-specific batch execution capabilities for efficiency.
        Results are aggregated across all target instances.

        Args:
            instance_ids: List of target instance identifiers.
            script_content: Script content to execute.
            interpreter: Script interpreter (e.g., "bash", "powershell").
            account_id: Provider account/subscription identifier.
            region: Target region for the operation.
            timeout: Maximum execution time in seconds (default: 300).

        Returns:
            Dictionary with batch execution results:
                - overall_status: str ("success", "partial", "failed")
                - results: List[Dict] with per-instance results
                - success_count: int
                - failure_count: int
        """
        pass

    @abstractmethod
    async def enumerate_accounts(self) -> List[Dict[str, str]]:
        """List accessible accounts/subscriptions.

        Returns all accounts/subscriptions the current credentials have
        access to, useful for multi-account environments.

        Returns:
            List of account dictionaries:
                - account_id: str
                - account_name: str (if available)
                - environment: str (e.g., "com", "gov" for AWS)
        """
        pass

    @abstractmethod
    async def enumerate_regions(self) -> List[str]:
        """List available regions.

        Returns all regions enabled for the current account/credentials.

        Returns:
            List of region identifiers (e.g., ["us-east-1", "us-west-2"]).
        """
        pass
