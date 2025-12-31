"""AWS provider implementation package.

This package contains the AWS-specific implementation of the provider interface,
including the AWSProvider class and supporting services for credential management,
instance discovery, and script execution via AWS SSM.
"""

from backend.providers.aws.provider import AWSProvider

__all__ = ["AWSProvider"]
