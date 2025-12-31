"""
Encryption utilities for securing sensitive data in sessions.
"""

import json
import logging
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from backend.core.config import settings

logger = logging.getLogger(__name__)


class CredentialEncryption:
    """Handles encryption and decryption of sensitive credential data."""

    def __init__(self):
        """Initialize encryption with a key derived from the app's secret key."""
        self.cipher = self._create_cipher()

    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create a new secure salt for key derivation.

        Returns:
            16-byte salt for PBKDF2 key derivation
        """
        # Use the data directory for salt file (same location as database)
        # Safely extract and validate database path
        db_url = settings.DATABASE_URL
        if not db_url.startswith("sqlite:///"):
            raise ValueError("Invalid database URL format")

        db_path = Path(db_url[10:])  # Remove 'sqlite:///' prefix
        db_path = db_path.resolve()
        salt_file = db_path.parent / ".encryption_salt"
        salt_file = salt_file.resolve()

        # Verify salt file is in expected location (prevent traversal)
        if not str(salt_file).startswith(str(db_path.parent.resolve())):
            raise ValueError("Salt file path traversal detected")

        try:
            # Atomic read with validation
            try:
                with open(salt_file, "rb") as f:
                    salt = f.read()
                    if len(salt) == 16:
                        return salt
                    # Invalid salt, will regenerate below
            except FileNotFoundError:
                pass  # File doesn't exist, will create below
            except OSError:
                # Permission or other issues, will handle below
                pass

            # Generate new secure random salt
            salt = secrets.token_bytes(16)

            # Ensure parent directory exists
            salt_file.parent.mkdir(parents=True, exist_ok=True)

            # Use exclusive file creation to prevent race conditions
            try:
                # Create file atomically with restrictive permissions (0o600)
                fd = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, salt)
                finally:
                    os.close(fd)

                logger.info("Created new encryption salt file")
                return salt

            except FileExistsError:
                # Another process created the file - read and validate it
                with open(salt_file, "rb") as f:
                    existing_salt = f.read()
                    if len(existing_salt) == 16:
                        logger.debug("Using salt file created by another process")
                        return existing_salt
                    else:
                        # Corrupted salt file created by another process - regenerate and replace
                        logger.warning(
                            "Invalid salt file created by another process, regenerating"
                        )

                        # Generate new salt
                        new_salt = secrets.token_bytes(16)

                        # Write to temporary file in same directory
                        temp_fd, temp_path = tempfile.mkstemp(
                            dir=os.path.dirname(salt_file), prefix=".salt_tmp_"
                        )
                        try:
                            # Write new salt to temp file with secure permissions
                            os.chmod(temp_path, 0o600)
                            os.write(temp_fd, new_salt)
                            os.close(temp_fd)

                            # Atomically replace corrupted file
                            try:
                                os.replace(temp_path, salt_file)
                                logger.info("Successfully replaced corrupted salt file")
                                return new_salt
                            except OSError as e:
                                # Replace failed - another process may have fixed it
                                logger.debug(f"Failed to replace salt file: {e}")
                                # Try to read the final file
                                try:
                                    with open(salt_file, "rb") as f:
                                        final_salt = f.read()
                                        if len(final_salt) == 16:
                                            logger.info(
                                                "Using salt file fixed by another process"
                                            )
                                            return final_salt
                                except Exception:
                                    pass
                                # If all else fails, use the new salt we generated
                                logger.warning(
                                    "Could not verify final salt file, using generated salt"
                                )
                                return new_salt
                        finally:
                            # Clean up temp file if it still exists
                            try:
                                if 'temp_fd' in locals() and temp_fd is not None:
                                    os.close(temp_fd)
                            except OSError:
                                pass
                            try:
                                if 'temp_path' in locals() and os.path.exists(temp_path):
                                    os.unlink(temp_path)
                            except OSError:
                                pass

        except Exception as e:
            logger.error(f"Failed to get or create salt: {e}")
            # Fallback to a deterministic salt based on settings (less secure but functional)
            import hashlib
            fallback_salt = hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest()[:16]
            logger.warning("Using fallback deterministic salt due to file system issues")
            return fallback_salt

    def _get_kdf_iterations(self) -> int:
        """Get KDF iterations from settings with fallback"""
        kdf_iterations = getattr(settings, 'ENCRYPTION_KDF_ITERATIONS', None)
        if kdf_iterations is None:
            # Try to get from environment variable
            kdf_iterations = os.environ.get('ENCRYPTION_KDF_ITERATIONS', '300000')

        # Parse and validate iterations
        try:
            kdf_iterations = int(kdf_iterations)
            # Enforce reasonable bounds
            if kdf_iterations > 10_000_000:
                logger.warning(f"KDF iterations {kdf_iterations} exceeds maximum, using 1,000,000")
                kdf_iterations = 1_000_000
        except (ValueError, TypeError):
            kdf_iterations = 300000
            logger.warning(f"Invalid KDF iterations value, using default: {kdf_iterations}")

        # Enforce minimum iterations for security
        if kdf_iterations < 100_000:
            logger.warning(f"KDF iterations {kdf_iterations} below recommended minimum, using 300,000")
            kdf_iterations = 300_000

        return kdf_iterations

    def _create_cipher(self) -> Fernet:
        """Create a Fernet cipher using the app's secret key."""
        # Get deployment-specific salt
        salt = self._get_or_create_salt()

        # Get KDF iterations
        kdf_iterations = self._get_kdf_iterations()

        # Derive a proper encryption key from the app's secret key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=kdf_iterations,
        )

        # Use the app's secret key as the password
        secret_bytes = settings.SECRET_KEY.encode('utf-8')
        import base64
        key = base64.urlsafe_b64encode(kdf.derive(secret_bytes))

        return Fernet(key)

    def encrypt_credentials(self, credentials: dict[str, Any]) -> str:
        """
        Encrypt credential data for secure storage.
        
        Args:
            credentials: Dictionary containing credential data
            
        Returns:
            Encrypted string safe for session storage
        """
        try:
            # Convert credentials to JSON
            json_data = json.dumps(credentials)

            # Encrypt the JSON string (Fernet.encrypt returns URL-safe base64)
            encrypted_bytes = self.cipher.encrypt(json_data.encode('utf-8'))

            # Return the encrypted string (already base64 encoded by Fernet)
            return encrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(
                "Failed to encrypt credentials",
                extra={"error_type": type(e).__name__},
            )
            raise

    def decrypt_credentials(self, encrypted_data: str) -> dict[str, Any] | None:
        """
        Decrypt credential data from session storage.
        
        Args:
            encrypted_data: Encrypted credential string
            
        Returns:
            Decrypted credentials dictionary or None if decryption fails
        """
        try:
            # Decrypt the data (Fernet expects URL-safe base64 string)
            decrypted_bytes = self.cipher.decrypt(encrypted_data.encode('utf-8'))

            # Parse JSON from decrypted bytes
            json_data = decrypted_bytes.decode('utf-8')
            return json.loads(json_data)
        except Exception as e:
            logger.error(
                "Failed to decrypt credentials",
                extra={"error_type": type(e).__name__},
            )
            return None


# Global instance
credential_encryption = CredentialEncryption()


def encrypt_session_credentials(credentials: dict[str, Any]) -> str:
    """
    Encrypt credentials for session storage.
    
    Args:
        credentials: Dictionary containing AWS credentials
        
    Returns:
        Encrypted string safe for session storage
    """
    return credential_encryption.encrypt_credentials(credentials)


def decrypt_session_credentials(encrypted_data: str) -> dict[str, Any] | None:
    """
    Decrypt credentials from session storage.
    
    Args:
        encrypted_data: Encrypted credential string from session
        
    Returns:
        Decrypted credentials dictionary or None if decryption fails
    """
    return credential_encryption.decrypt_credentials(encrypted_data)
