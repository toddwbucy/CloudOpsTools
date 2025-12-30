"""AWS Script Runner tool package

Exposes API routers and services for the AWS Script Runner tool.
"""

import logging

# Import API routers
try:
    from backend.providers.aws.script_runner.api import (
        accounts,
        aws_operations,
        changes,
        instances,
        org,
    )
    from backend.providers.aws.script_runner.api.executions import (
        router as executions_router,
    )

    # Export routers for discovery - cleaner AWS-specific prefix
    routers = [
        (accounts.router, "/aws/script-runner/accounts"),
        (executions_router, "/aws/script-runner/executions"),
        (org.router, "/aws/script-runner/org"),
        (aws_operations.router, "/aws/script-runner/scans"),
        (changes.router, "/aws/script-runner/changes"),
        (instances.router, "/aws/script-runner/instances"),
    ]

    logger = logging.getLogger(__name__)
    logger.info("AWS Script Runner API routers loaded successfully")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to load AWS Script Runner API routers: {e}")
    routers = []
