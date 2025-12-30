"""CloudOpsTools Security Module"""

import os
import secrets


def get_or_create_secret_key() -> str:
    """Get or create a secret key for session management"""
    # Check for environment variable first
    secret_key = os.environ.get("SECRET_KEY")
    if secret_key:
        return secret_key

    # Generate a new secret key
    return secrets.token_hex(32)
