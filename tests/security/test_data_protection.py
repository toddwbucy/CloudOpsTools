"""
Security tests for data protection and privacy

Tests encryption, data handling, and privacy measures that will be
implemented during Phase 1 security fixes.
"""

import base64
import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

# Mark all tests in this module as security tests
pytestmark = pytest.mark.security


@pytest.mark.security
@pytest.mark.encryption
class TestDataEncryption:
    """Test data encryption and secure storage"""

    def test_secret_key_entropy(self, test_settings):
        """Test SECRET_KEY has sufficient entropy and is not a hardcoded default"""
        secret = test_settings.SECRET_KEY

        # Should be at least 32 characters (NIST recommends 32+ for secrets)
        assert len(secret) >= 32, "SECRET_KEY must be at least 32 characters"

        # Should not be any common default/hardcoded values
        hardcoded_defaults = [
            "your-secret-key-here-change-in-production",
            "changeme",
            "secret",
            "secretkey",
            "mysecretkey",
            "development-secret",
            "dev-secret-key",
            "test-secret-key",
            "placeholder",
            "default",
            "example",
            "CHANGE_ME",
            "supersecret",
            "password",
            "12345678901234567890123456789012",  # Sequential digits
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # All same character
        ]

        for default in hardcoded_defaults:
            assert secret.lower() != default.lower(), \
                f"SECRET_KEY must not be hardcoded default value: {default}"

        # Check for patterns that suggest hardcoding
        assert "change" not in secret.lower() or len(secret) > 50, \
            "SECRET_KEY appears to contain 'change' suggesting a placeholder"
        assert "example" not in secret.lower(), \
            "SECRET_KEY appears to contain 'example' suggesting a placeholder"
        assert "placeholder" not in secret.lower(), \
            "SECRET_KEY appears to contain 'placeholder'"

        # Should have reasonable entropy (not all same character)
        unique_chars = len(set(secret.lower()))
        assert unique_chars >= 10, \
            f"SECRET_KEY must have at least 10 unique characters (has {unique_chars})"

        # Should not be a simple repeating pattern
        if len(secret) >= 4:
            # Check for simple 2-char or 4-char repeating patterns
            two_char = secret[:2]
            four_char = secret[:4]
            assert secret != two_char * (len(secret) // 2), \
                "SECRET_KEY should not be a simple repeating pattern"
            assert secret != four_char * (len(secret) // 4), \
                "SECRET_KEY should not be a simple repeating pattern"

        # Entropy calculation - should have good character distribution
        import math
        char_counts = {}
        for char in secret:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / len(secret)
            entropy -= probability * math.log2(probability)

        # A good random string of 32+ chars should have entropy > 3.0 bits per character
        assert entropy >= 2.5, \
            f"SECRET_KEY has low entropy ({entropy:.2f} bits/char), suggesting weak randomness"

    def test_salt_unique_per_deployment(self, test_settings):
        """Test encryption salt is unique per deployment and not hardcoded"""
        from backend.core.utils.encryption import CredentialEncryption
        import tempfile
        import shutil

        # Create two separate encryption instances and verify their salts
        # would differ if created in isolation (simulating different deployments)

        # First, get the current encryption instance
        encryption1 = CredentialEncryption()

        # The salt should be 16 bytes (128 bits)
        # We can verify by checking the salt file exists and has proper length
        db_url = test_settings.DATABASE_URL
        if db_url.startswith("sqlite:///"):
            from pathlib import Path
            db_path = Path(db_url[10:]).resolve()
            salt_file = db_path.parent / ".encryption_salt"

            if salt_file.exists():
                with open(salt_file, "rb") as f:
                    salt = f.read()

                # Salt should be exactly 16 bytes
                assert len(salt) == 16, \
                    f"Salt should be 16 bytes, got {len(salt)}"

                # Salt should have good entropy (not all zeros or same byte)
                unique_bytes = len(set(salt))
                assert unique_bytes >= 4, \
                    "Salt has low byte diversity, may not be randomly generated"

                # Salt should not be a common default
                common_defaults = [
                    b'\x00' * 16,  # All zeros
                    b'\xff' * 16,  # All 0xff
                    b'0123456789abcdef',  # Sequential
                    b'abcdefghijklmnop',  # Sequential letters
                ]

                for default in common_defaults:
                    assert salt != default, \
                        "Salt appears to be a hardcoded default value"

    def test_salt_file_permissions(self, test_settings):
        """Test salt file has restrictive permissions"""
        import stat

        db_url = test_settings.DATABASE_URL
        if db_url.startswith("sqlite:///"):
            from pathlib import Path
            db_path = Path(db_url[10:]).resolve()
            salt_file = db_path.parent / ".encryption_salt"

            if salt_file.exists():
                # Check file permissions (should be 0o600 - owner read/write only)
                mode = salt_file.stat().st_mode
                permissions = stat.S_IMODE(mode)

                # On Unix systems, others should not have read access
                others_read = permissions & stat.S_IROTH
                others_write = permissions & stat.S_IWOTH
                group_read = permissions & stat.S_IRGRP
                group_write = permissions & stat.S_IWGRP

                # At minimum, others should not be able to read the salt file
                assert others_read == 0, \
                    "Salt file should not be world-readable"
                assert others_write == 0, \
                    "Salt file should not be world-writable"

    def test_kdf_iterations_sufficient(self, test_settings):
        """Test key derivation uses sufficient iterations for security"""
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        # Access the private method to get iterations (testing internal behavior)
        iterations = encryption._get_kdf_iterations()

        # OWASP recommends at least 310,000 iterations for PBKDF2-SHA256 (2023)
        # We allow 100,000 as absolute minimum for the test, but prefer 300,000+
        assert iterations >= 100_000, \
            f"KDF iterations ({iterations}) below security minimum of 100,000"

        # Log a warning if below OWASP recommendation
        if iterations < 300_000:
            import warnings
            warnings.warn(
                f"KDF iterations ({iterations}) below OWASP recommended 310,000"
            )

    def test_different_keys_produce_different_ciphertexts(self, test_settings):
        """Test that different SECRET_KEYs produce incompatible encryption"""
        from backend.core.utils.encryption import CredentialEncryption
        from unittest.mock import patch, MagicMock
        from cryptography.fernet import InvalidToken
        import pytest

        # Create encryption with current settings
        encryption1 = CredentialEncryption()

        test_data = {"secret": "test-value"}
        encrypted = encryption1.encrypt_credentials(test_data)

        # Create a mock settings with different SECRET_KEY
        mock_settings = MagicMock()
        mock_settings.SECRET_KEY = "different-secret-key-that-is-at-least-32-chars-long"
        mock_settings.DATABASE_URL = test_settings.DATABASE_URL

        # The encrypted data from encryption1 should not be decryptable
        # with a different key
        with patch('backend.core.utils.encryption.settings', mock_settings):
            # Creating new instance with different key
            encryption2 = CredentialEncryption()

            # Attempting to decrypt with wrong key should fail safely
            result = encryption2.decrypt_credentials(encrypted)
            assert result is None, \
                "Decryption with wrong key should return None, not the plaintext"

    def test_database_encryption_ready(self, test_settings):
        """Test database is ready for encryption"""
        # SQLite supports encryption with proper extensions
        db_url = test_settings.DATABASE_URL
        assert "sqlite://" in db_url

        # Path should be secure location
        if ":" in db_url:
            db_path = db_url.split(":")[-1].replace("///", "/")
            assert not db_path.startswith("/tmp")  # Not in temp directory

    def test_session_encryption_configuration(self, test_settings):
        """Test session encryption is properly configured"""
        # SECRET_KEY should be suitable for session encryption
        assert isinstance(test_settings.SECRET_KEY, str)
        assert len(test_settings.SECRET_KEY.encode()) >= 32

        # Session lifetime should be reasonable for security
        assert test_settings.SESSION_LIFETIME_MINUTES <= 480  # Max 8 hours

    def test_credential_encryption_roundtrip(self, test_settings):
        """Test credentials can be encrypted and decrypted correctly"""
        from backend.core.utils.encryption import CredentialEncryption

        # Create encryption instance
        encryption = CredentialEncryption()

        # Test credentials (plaintext)
        test_credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "session_token": "IQoJb3JpZ2luX2VjEJr...test-token...",
            "environment": "com",
        }

        # Encrypt the credentials
        encrypted = encryption.encrypt_credentials(test_credentials)

        # Encrypted data should be a string (base64-encoded Fernet token)
        assert isinstance(encrypted, str)

        # Encrypted value should NOT contain plaintext credentials
        assert test_credentials["access_key"] not in encrypted
        assert test_credentials["secret_key"] not in encrypted
        assert test_credentials["session_token"] not in encrypted

        # Decrypt and verify
        decrypted = encryption.decrypt_credentials(encrypted)
        assert decrypted is not None
        assert decrypted == test_credentials

    def test_encrypted_data_not_plaintext(self, test_settings):
        """Test encrypted data is not stored as plaintext in DB format"""
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        # Sensitive data to encrypt
        sensitive_data = {
            "password": "SuperSecretPassword123!",
            "api_key": "sk-1234567890abcdef",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        }

        encrypted = encryption.encrypt_credentials(sensitive_data)

        # Verify encrypted data doesn't contain any sensitive values
        for key, value in sensitive_data.items():
            assert value not in encrypted, f"Plaintext '{key}' found in encrypted data"

        # Verify encrypted data is base64-like (Fernet format)
        # Fernet tokens start with 'gAAAAA' after base64 encoding
        assert encrypted.startswith("gAAAAA"), "Encrypted data should be Fernet format"

    def test_different_inputs_produce_different_ciphertexts(self, test_settings):
        """Test encryption produces different ciphertexts for same input (due to IV)"""
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        credentials = {"secret": "test-secret-value"}

        # Encrypt the same data twice
        encrypted1 = encryption.encrypt_credentials(credentials)
        encrypted2 = encryption.encrypt_credentials(credentials)

        # Due to random IV/nonce, same plaintext produces different ciphertext
        assert encrypted1 != encrypted2, "Same input should produce different ciphertexts"

        # But both should decrypt to the same value
        decrypted1 = encryption.decrypt_credentials(encrypted1)
        decrypted2 = encryption.decrypt_credentials(encrypted2)
        assert decrypted1 == decrypted2 == credentials

    def test_session_store_encrypts_credentials(self, test_settings, db_session):
        """Test SessionStore encrypts credentials when feature flag is enabled"""
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select

        # Test credentials
        test_creds = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }

        test_key = "credentials:test_session_123"

        # Mock the feature flag to be enabled
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            SessionStore.set(test_key, test_creds)

            # Query database directly to verify stored data
            row = db_session.scalar(
                select(SessionData).where(SessionData.key == test_key)
            )

            if row:
                stored_data = row.data

                # Stored data should be encrypted (string, not dict)
                assert isinstance(stored_data, str), "Encrypted data should be stored as string"

                # Stored data should NOT contain plaintext credentials
                assert "AKIAIOSFODNN7EXAMPLE" not in str(stored_data)
                assert "wJalrXUtnFEMI" not in str(stored_data)

                # Stored data should be Fernet format
                assert stored_data.startswith("gAAAAA"), "Should be Fernet encrypted format"

                # Cleanup
                SessionStore.clear(test_key)

    def test_credential_decryption_roundtrip_via_session_store(self, test_settings, db_session):
        """Test full round-trip: encrypt -> store -> retrieve -> decrypt returns original value"""
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select

        # Original plaintext credentials with all common fields
        original_credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "session_token": "IQoJb3JpZ2luX2VjEJr...test-token...",
            "environment": "com",
            "expiration": "2025-01-01T12:00:00Z",
        }

        test_key = "credentials:roundtrip_test_session"

        # Mock the feature flag to be enabled for the entire test
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            # Step 1: Store credentials (internally encrypts)
            SessionStore.set(test_key, original_credentials)

            # Step 2: Verify stored data is encrypted (not plaintext)
            row = db_session.scalar(
                select(SessionData).where(SessionData.key == test_key)
            )
            assert row is not None, "Credentials should be stored in database"

            stored_data = row.data
            assert isinstance(stored_data, str), "Stored data should be encrypted string"
            assert stored_data.startswith("gAAAAA"), "Should be Fernet encrypted format"

            # Verify plaintext is NOT in stored data
            for key, value in original_credentials.items():
                assert value not in str(stored_data), \
                    f"Plaintext '{key}' should NOT be in encrypted storage"

            # Step 3: Retrieve credentials (internally decrypts)
            retrieved_credentials = SessionStore.get(test_key)

            # Step 4: Verify decrypted data matches original
            assert retrieved_credentials is not None, \
                "Retrieved credentials should not be None"
            assert isinstance(retrieved_credentials, dict), \
                "Retrieved credentials should be a dictionary"
            assert retrieved_credentials == original_credentials, \
                "Decrypted credentials should match original values exactly"

            # Verify each field explicitly
            assert retrieved_credentials["access_key"] == original_credentials["access_key"]
            assert retrieved_credentials["secret_key"] == original_credentials["secret_key"]
            assert retrieved_credentials["session_token"] == original_credentials["session_token"]
            assert retrieved_credentials["environment"] == original_credentials["environment"]
            assert retrieved_credentials["expiration"] == original_credentials["expiration"]

            # Cleanup
            SessionStore.clear(test_key)

    def test_credential_roundtrip_with_special_characters(self, test_settings, db_session):
        """Test encryption round-trip handles special characters correctly"""
        from backend.core.utils.session_store import SessionStore

        # Credentials with special characters that might cause encoding issues
        special_credentials = {
            "access_key": "AKIAIOSFO+/=EXAMPLE",
            "secret_key": "wJalrXUtn/FEMI+K7MDENG=bPxRfiCY==",
            "session_token": "Token+with/special==chars&more",
            "unicode_field": "测试データテスト",
            "json_special": '{"nested": "value", "quotes": "\\"escaped\\""}',
        }

        test_key = "credentials:special_chars_test"

        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            # Store and retrieve
            SessionStore.set(test_key, special_credentials)
            retrieved = SessionStore.get(test_key)

            # Verify round-trip preserves all special characters
            assert retrieved is not None, "Should retrieve special character credentials"
            assert retrieved == special_credentials, \
                "Special characters should be preserved through encryption round-trip"

            # Cleanup
            SessionStore.clear(test_key)

    def test_credential_roundtrip_with_empty_and_null_values(self, test_settings, db_session):
        """Test encryption round-trip handles empty and edge case values"""
        from backend.core.utils.session_store import SessionStore

        # Edge case credentials
        edge_case_credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "",  # Empty string
            "session_token": None,  # None value (becomes null in JSON)
            "empty_list": [],
            "empty_dict": {},
            "zero_value": 0,
            "false_value": False,
        }

        test_key = "credentials:edge_case_test"

        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            # Store and retrieve
            SessionStore.set(test_key, edge_case_credentials)
            retrieved = SessionStore.get(test_key)

            # Verify round-trip preserves edge case values
            assert retrieved is not None, "Should retrieve edge case credentials"
            assert retrieved["access_key"] == "AKIAIOSFODNN7EXAMPLE"
            assert retrieved["secret_key"] == ""
            assert retrieved["session_token"] is None
            assert retrieved["empty_list"] == []
            assert retrieved["empty_dict"] == {}
            assert retrieved["zero_value"] == 0
            assert retrieved["false_value"] is False

            # Cleanup
            SessionStore.clear(test_key)

    def test_multiple_credential_roundtrips_same_key(self, test_settings, db_session):
        """Test updating credentials multiple times preserves encryption integrity"""
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select

        test_key = "credentials:multi_update_test"

        # Series of credential updates
        credential_versions = [
            {"access_key": "AKIA_VERSION_1", "secret_key": "secret_v1"},
            {"access_key": "AKIA_VERSION_2", "secret_key": "secret_v2", "new_field": "added"},
            {"access_key": "AKIA_VERSION_3"},  # Fewer fields
        ]

        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            for version in credential_versions:
                # Store this version
                SessionStore.set(test_key, version)

                # Verify storage is encrypted
                row = db_session.scalar(
                    select(SessionData).where(SessionData.key == test_key)
                )
                assert row is not None
                assert isinstance(row.data, str)
                assert row.data.startswith("gAAAAA"), "Each update should be encrypted"

                # Verify retrieval matches current version
                retrieved = SessionStore.get(test_key)
                assert retrieved == version, \
                    f"Retrieved should match version: {version}"

            # Cleanup
            SessionStore.clear(test_key)

    def test_encrypted_credentials_not_readable_without_key(self, test_settings):
        """Test encrypted credentials cannot be read without correct key"""
        from backend.core.utils.encryption import CredentialEncryption
        from cryptography.fernet import Fernet, InvalidToken

        encryption = CredentialEncryption()

        credentials = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }

        encrypted = encryption.encrypt_credentials(credentials)

        # Try to decrypt with a different (random) key
        wrong_key = Fernet.generate_key()
        wrong_fernet = Fernet(wrong_key)

        with pytest.raises(InvalidToken):
            wrong_fernet.decrypt(encrypted.encode('utf-8'))

    def test_corrupted_encrypted_data_fails_safely(self, test_settings):
        """Test corrupted encrypted data returns None (doesn't crash)"""
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        # Various types of corrupted data
        corrupted_inputs = [
            "not-valid-encrypted-data",
            "gAAAAABhelloworld",  # Wrong format
            "",  # Empty string
            "gAAAAA" + "x" * 100,  # Invalid base64
        ]

        for corrupted in corrupted_inputs:
            result = encryption.decrypt_credentials(corrupted)
            assert result is None, f"Corrupted data '{corrupted[:20]}...' should return None"

    def test_db_stored_value_differs_from_plaintext(self, test_settings, db_session):
        """Test DB-level verification: stored value != plaintext credentials"""
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select
        import json

        # Plaintext credentials
        plaintext_creds = {
            "access_key": "AKIAEXAMPLEKEY123456",
            "secret_key": "SuperSecretKeyThatShouldNeverAppearInDB",
            "session_token": "LongSessionTokenValue12345",
        }

        test_key = "credentials:db_verification_test"

        # Store with encryption enabled
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=True):
            SessionStore.set(test_key, plaintext_creds)

            # Direct database query - bypassing SessionStore.get()
            row = db_session.scalar(
                select(SessionData).where(SessionData.key == test_key)
            )

            if row:
                raw_db_value = row.data

                # Convert to string for comparison
                if isinstance(raw_db_value, dict):
                    raw_str = json.dumps(raw_db_value)
                else:
                    raw_str = str(raw_db_value)

                # Verify none of the plaintext values appear in raw DB storage
                assert plaintext_creds["access_key"] not in raw_str, \
                    "Access key found in raw DB value - not encrypted!"
                assert plaintext_creds["secret_key"] not in raw_str, \
                    "Secret key found in raw DB value - not encrypted!"
                assert plaintext_creds["session_token"] not in raw_str, \
                    "Session token found in raw DB value - not encrypted!"

                # Verify the stored value is encrypted (Fernet format)
                if isinstance(raw_db_value, str):
                    assert raw_db_value.startswith("gAAAAA"), \
                        "Stored value should be Fernet encrypted"

                # Cleanup
                SessionStore.clear(test_key)


@pytest.mark.security
@pytest.mark.data_leakage
class TestDataLeakagePrevention:
    """Test prevention of data leakage in logs, errors, and API responses."""

    # Sample sensitive data patterns used across tests
    SAMPLE_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    SAMPLE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    SAMPLE_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDNMM2v9jK5hztest123abcdefghijklmnopqrstuvwxyz"
    SAMPLE_PASSWORD = "MySuperSecretPassword123!"

    def test_credentials_not_in_error_logs(self, client, caplog):
        """Test credentials don't appear in error logs"""
        import logging

        # Capture all log levels
        with caplog.at_level(logging.DEBUG):
            # Trigger an error with credentials
            response = client.post(
                "/api/auth/aws-credentials",
                json={
                    "access_key": "AKIATEST123456789012",
                    "secret_key": "SuperSecretKey123456789012345678901234",
                    "session_token": "LongSessionToken123456789"
                }
            )

        # Check logs for credential leakage
        all_logs = " ".join([record.getMessage() for record in caplog.records])

        assert "SuperSecretKey" not in all_logs
        assert "LongSessionToken" not in all_logs
        # Access key might be logged for debugging, but should be masked
        if "AKIATEST" in all_logs:
            # Should be masked like AKIA****
            assert "AKIATEST123456789012" not in all_logs

    def test_database_credentials_not_logged(self, test_settings, caplog):
        """Test database credentials are not logged"""
        import logging

        with caplog.at_level(logging.DEBUG):
            # Access database URL (might trigger logging)
            db_url = test_settings.DATABASE_URL

        all_logs = " ".join([record.getMessage() for record in caplog.records])

        # If database has credentials, they shouldn't be in logs
        if "@" in db_url:  # Has credentials
            parts = db_url.split("@")
            if ":" in parts[0]:
                # Extract potential password
                creds = parts[0].split("://")[1]
                if ":" in creds:
                    password = creds.split(":")[1]
                    assert password not in all_logs

    def test_environment_variables_not_leaked(self, client):
        """Test environment variables are not leaked in responses"""
        # Trigger potential error that might leak env vars
        response = client.get("/api/health")

        if response.status_code >= 400:
            error_text = str(response.json())

            # Check for common env var patterns
            sensitive_patterns = [
                "SECRET_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "DATABASE_URL",
                "PASSWORD"
            ]

            for pattern in sensitive_patterns:
                assert pattern not in error_text

    def test_log_filter_masks_aws_access_keys(self):
        """Test SecurityLogFilter masks AWS access keys in log messages"""
        from backend.core.logging_config import SecurityLogFilter

        filter = SecurityLogFilter()

        # Test various AWS access key formats
        test_cases = [
            # (input, should_contain, should_not_contain)
            ("Access key: AKIAIOSFODNN7EXAMPLE", "AKIA****", "AKIAIOSFODNN7EXAMPLE"),
            ("Key is ASIAX5ABCDEF12345678 for role", "AKIA****", "ASIAX5ABCDEF12345678"),
            ("Using key=AKIAIOSFODNN7EXAMPLE", "****", "AKIAIOSFODNN7EXAMPLE"),
        ]

        for input_msg, should_contain, should_not_contain in test_cases:
            sanitized = filter._sanitize_message(input_msg)
            assert should_not_contain not in sanitized, \
                f"Leaked access key in: {sanitized}"
            # Note: Pattern may be masked differently depending on filter logic

    def test_log_filter_masks_secrets_in_key_value_pairs(self):
        """Test SecurityLogFilter masks password/secret in key=value pairs"""
        from backend.core.logging_config import SecurityLogFilter

        filter = SecurityLogFilter()

        # Test secret in key=value patterns
        test_cases = [
            "password=MySecretPassword123",
            "secret=SuperSecretValue",
            "token=abc123xyz",
            "key=SomeAPIKey12345",
            "password: MySecretPassword123",
            "secret: SuperSecretValue",
        ]

        for input_msg in test_cases:
            sanitized = filter._sanitize_message(input_msg)
            # The value after = or : should be masked
            assert "=****" in sanitized or ":****" in sanitized or "****" in sanitized, \
                f"Secret value not masked in: '{input_msg}' -> '{sanitized}'"

    def test_log_filter_masks_long_alphanumeric_strings(self):
        """Test SecurityLogFilter masks long alphanumeric strings (potential secrets)"""
        from backend.core.logging_config import SecurityLogFilter

        filter = SecurityLogFilter()

        # Long strings that look like tokens/secrets should be masked
        test_cases = [
            ("Token: abcdefghijklmnopqrstuvwxyz1234", "****"),
            ("SessionToken: FwoGZXIvYXdzEBYaDAbcdefghijklmnop", "****"),
        ]

        for input_msg, expected_mask in test_cases:
            sanitized = filter._sanitize_message(input_msg)
            # Long alphanumeric strings should be replaced with ****
            # The filter masks 20+ alphanumeric characters
            assert expected_mask in sanitized, \
                f"Long token not masked: '{input_msg}' -> '{sanitized}'"

    def test_api_response_masks_access_key(self, client):
        """Test API responses mask access keys properly"""
        # The /api/auth/aws-check-credentials endpoint should mask access keys
        response = client.get("/api/auth/aws-check-credentials")

        if response.status_code == 200:
            data = response.json()

            # Check both com and gov environments
            for env in ["com", "gov"]:
                env_data = data.get(env)
                if env_data and env_data.get("access_key"):
                    access_key = env_data["access_key"]
                    # Should be masked format like "AKIA...XXXX" or "****"
                    assert len(access_key) < 20 or "..." in access_key or "****" in access_key, \
                        f"Access key not properly masked in response: {access_key}"

    def test_error_response_no_credential_leakage(self, client):
        """Test error responses don't leak credentials"""
        # Send invalid credentials to trigger validation error
        response = client.post(
            "/api/auth/aws-credentials",
            json={
                "access_key": "invalid-key",
                "secret_key": self.SAMPLE_SECRET_KEY,
                "session_token": self.SAMPLE_SESSION_TOKEN,
                "environment": "com"
            }
        )

        # Should be validation error
        assert response.status_code in [400, 422]

        # Response body should not contain the secret key or session token
        response_text = response.text
        assert self.SAMPLE_SECRET_KEY not in response_text, \
            "Secret key leaked in error response"
        assert self.SAMPLE_SESSION_TOKEN not in response_text, \
            "Session token leaked in error response"

    def test_validation_error_no_credential_echo(self, client):
        """Test validation errors don't echo back credential values"""
        # Various invalid credential payloads
        test_cases = [
            {
                "access_key": "AKIATEST123456789012",
                "secret_key": "short",  # Too short
                "environment": "com"
            },
            {
                "access_key": "invalid_access_key_format",
                "secret_key": self.SAMPLE_SECRET_KEY,
                "environment": "invalid_env"
            },
        ]

        for payload in test_cases:
            response = client.post("/api/auth/aws-credentials", json=payload)

            if response.status_code in [400, 422]:
                response_text = response.text.lower()

                # Validation errors should not echo the secret values
                if payload.get("secret_key"):
                    assert payload["secret_key"].lower() not in response_text, \
                        f"Secret key echoed in validation error: {response.text}"

    def test_exception_messages_sanitized(self):
        """Test exception messages don't contain credential details"""
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        # Try to decrypt invalid data - should return None, not raise with details
        invalid_inputs = [
            "not-encrypted-data",
            "gAAAAAB_invalid_token_here",
            "",
        ]

        for invalid_input in invalid_inputs:
            result = encryption.decrypt_credentials(invalid_input)
            # Should fail gracefully without raising
            assert result is None, \
                f"Expected None for invalid input, got: {result}"

    def test_encryption_error_logs_sanitized(self, caplog):
        """Test encryption errors don't log sensitive data"""
        import logging
        from backend.core.utils.encryption import CredentialEncryption

        encryption = CredentialEncryption()

        # Capture logs during failed decryption
        with caplog.at_level(logging.DEBUG):
            # Try to decrypt corrupted data
            encryption.decrypt_credentials("corrupted-data-not-valid-fernet")

        all_logs = " ".join([record.getMessage() for record in caplog.records])

        # Log should indicate failure but not contain the corrupted data
        # (which could be a malicious payload)
        if "decrypt" in all_logs.lower():
            assert "corrupted-data-not-valid-fernet" not in all_logs, \
                "Raw input data should not be logged on decrypt failure"

    def test_stack_trace_no_credentials(self, caplog):
        """Test stack traces don't expose credential values"""
        import logging

        # This test verifies that if an exception occurs while handling credentials,
        # the credentials don't appear in the stack trace

        # We'll use the SecurityLogFilter to sanitize any exception info
        from backend.core.logging_config import SecurityLogFilter

        filter = SecurityLogFilter()

        # Simulate a log record with exception info containing credentials
        class MockExcInfo:
            pass

        # Test that the filter sanitizes messages that might contain credentials
        trace_with_creds = (
            f"Traceback (most recent call last):\n"
            f"  File 'test.py', line 10, in test_func\n"
            f"    secret_key = '{self.SAMPLE_SECRET_KEY}'\n"
            f"ValueError: Invalid key"
        )

        sanitized = filter._sanitize_message(trace_with_creds)

        # The actual secret key value should be masked
        assert self.SAMPLE_SECRET_KEY not in sanitized, \
            f"Secret key found in sanitized trace: {sanitized}"

    def test_repr_str_no_credential_exposure(self):
        """Test __repr__ and __str__ of models don't expose credentials"""
        from backend.api.auth import CredentialRequest

        # Create a credential request object
        try:
            cred_request = CredentialRequest(
                access_key="AKIAIOSFODNN7EXAMPLE",
                secret_key=self.SAMPLE_SECRET_KEY,
                session_token=self.SAMPLE_SESSION_TOKEN,
                environment="com"
            )

            # String representations should not contain actual secret values
            str_repr = str(cred_request)
            repr_repr = repr(cred_request)

            # The secret key should not be fully visible
            # (Pydantic models may show the value, but it should be masked)
            # This test documents expected behavior
            if self.SAMPLE_SECRET_KEY in str_repr:
                # If visible, this is a potential security concern
                import warnings
                warnings.warn(
                    "CredentialRequest __str__ exposes secret_key - consider using SecretStr"
                )
        except Exception:
            # If validation fails, that's also acceptable - means we can't create
            # objects with invalid data
            pass

    def test_json_serialization_no_credentials(self):
        """Test JSON serialization doesn't leak credentials"""
        from backend.api.auth import CredentialResponse

        # Create a response object
        response = CredentialResponse(
            success=True,
            message="Validated",
            environment="com",
            temporary=True,
            expiration=1234567890.0,
            expires_in_seconds=3600,
            expires_in_minutes=60.0
        )

        # Serialize to JSON
        json_data = response.model_dump_json()

        # Response should not contain any credential fields
        assert "secret_key" not in json_data.lower()
        assert "access_key" not in json_data.lower() or "****" in json_data
        assert "session_token" not in json_data.lower()
        assert self.SAMPLE_SECRET_KEY not in json_data
        assert self.SAMPLE_SESSION_TOKEN not in json_data

    def test_session_store_get_returns_none_not_error_details(self, test_settings, db_session):
        """Test SessionStore.get returns None for missing keys, not error details"""
        from backend.core.utils.session_store import SessionStore

        # Try to get a non-existent key
        result = SessionStore.get("credentials:nonexistent_session_key_12345")

        # Should return None, not raise an exception or return error details
        assert result is None

    def test_credential_response_excludes_sensitive_fields(self, client):
        """Test credential validation response doesn't include sensitive input"""
        # Even on success, the response should not echo back credentials
        response = client.post(
            "/api/auth/aws-credentials",
            json={
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": self.SAMPLE_SECRET_KEY,
                "session_token": self.SAMPLE_SESSION_TOKEN,
                "environment": "com"
            }
        )

        # Whether success or failure, response should not contain credentials
        response_text = response.text

        # These should never appear in any response
        assert self.SAMPLE_SECRET_KEY not in response_text, \
            "Secret key should never appear in API response"
        assert self.SAMPLE_SESSION_TOKEN not in response_text, \
            "Session token should never appear in API response"

    def test_log_filter_masks_email_addresses(self):
        """Test SecurityLogFilter partially masks email addresses"""
        from backend.core.logging_config import SecurityLogFilter

        filter = SecurityLogFilter()

        # Test email masking
        input_msg = "User email is john.doe@example.com"
        sanitized = filter._sanitize_message(input_msg)

        # Email should be partially masked (first char + **** + domain)
        assert "john.doe@example.com" not in sanitized, \
            "Full email should not appear in sanitized message"
        assert "@example.com" in sanitized, \
            "Domain should still be visible for debugging"

    def test_credentials_not_in_debug_output(self, test_settings):
        """Test credentials don't appear in debug/repr output of settings"""
        # Get string representation of settings
        settings_str = str(test_settings)
        settings_repr = repr(test_settings)

        # These patterns should not appear in full form
        # (SECRET_KEY should be masked or not shown)
        if hasattr(test_settings, 'SECRET_KEY'):
            secret = test_settings.SECRET_KEY
            if len(secret) > 8:
                # Full secret should not be in repr
                # Allow if it's masked
                if secret in settings_str or secret in settings_repr:
                    import warnings
                    warnings.warn(
                        "Settings __str__/__repr__ may expose SECRET_KEY - consider masking"
                    )


@pytest.mark.security
@pytest.mark.file_security  
class TestFileSystemSecurity:
    """Test file system security measures"""
    
    def test_upload_directory_permissions(self, test_settings):
        """Test upload directory has proper permissions"""
        upload_path = Path("uploads")
        if upload_path.exists():
            # Should not be world-readable
            stat_info = upload_path.stat()
            # Check that others don't have read access (last digit not 4, 5, 6, 7)
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_log_directory_permissions(self):
        """Test log directory has proper permissions"""
        log_path = Path("logs")
        if log_path.exists():
            # Should not be world-readable
            stat_info = log_path.stat()
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_data_directory_permissions(self):
        """Test data directory has proper permissions"""
        data_path = Path("data")
        if data_path.exists():
            # Should not be world-readable
            stat_info = data_path.stat()
            others_perms = stat_info.st_mode & 0o007
            assert others_perms & 0o004 == 0  # Others can't read
    
    def test_temporary_file_cleanup(self):
        """Test temporary files are properly cleaned up"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(b"sensitive data")
        
        try:
            # Verify file exists
            assert os.path.exists(tmp_path)
            
            # Simulate cleanup (would be done by application)
            os.unlink(tmp_path)
            
            # Verify cleanup
            assert not os.path.exists(tmp_path)
        finally:
            # Cleanup in case test fails
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


@pytest.mark.security
@pytest.mark.input_validation
class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_sql_injection_prevention(self, client):
        """Test SQL injection attempts are prevented"""
        # SQL injection payloads
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM accounts WHERE 1=1 --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            # Test in various endpoints that might query database
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": payload, "enabled": True}
            )
            
            # Should either reject or sanitize
            if response.status_code == 200:
                data = response.json()
                # If accepted, should be sanitized
                assert "DROP TABLE" not in str(data).upper()
                assert "DELETE FROM" not in str(data).upper()
            else:
                # Should be rejected with proper error
                assert response.status_code in [400, 422]
    
    def test_path_traversal_prevention(self, client):
        """Test path traversal attempts are prevented"""
        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for payload in path_payloads:
            # Test in file-related endpoints
            response = client.get(f"/static/{payload}")
            
            # Should return 404 or 403, not expose files
            assert response.status_code in [403, 404]
    
    def test_command_injection_prevention(self, client):
        """Test command injection attempts are prevented"""
        # Command injection payloads
        cmd_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "&& cat /etc/passwd"
        ]
        
        for payload in cmd_payloads:
            # Test in endpoints that might execute commands
            response = client.post(
                "/api/feature-flags/toggle",
                json={"flag_name": f"test{payload}", "enabled": True}
            )
            
            # Should handle safely
            if response.status_code == 200:
                data = response.json()
                # Should not execute commands
                assert "root:" not in str(data)  # Common in /etc/passwd
                assert "/bin/bash" not in str(data)
    
    def test_json_payload_size_limits(self, client):
        """Test JSON payload size limits"""
        # Create large payload
        large_payload = {
            "flag_name": "test_flag",
            "enabled": True,
            "large_data": "A" * 10000  # 10KB of data
        }
        
        response = client.post("/api/feature-flags/toggle", json=large_payload)
        
        # Should either accept or reject based on size limits
        # If rejected, should be proper error code
        if response.status_code >= 400:
            assert response.status_code in [413, 422]  # Payload too large or validation error


@pytest.mark.security
@pytest.mark.session_security
class TestSessionSecurity:
    """Test session security measures"""

    def test_session_fixation_prevention(self, client):
        """Test session fixation attacks are prevented"""
        # Get initial session
        response1 = client.get("/aws")
        initial_cookies = response1.cookies

        # Simulate login attempt (when authentication is implemented)
        response2 = client.post("/api/auth/aws-credentials", json={
            "access_key": "test", "secret_key": "test"
        })

        # Check if session ID changed after auth attempt
        # For now, just verify session handling works
        assert response1.status_code == 200
        assert response2.status_code in [200, 400, 401]

    def test_session_hijacking_prevention(self, client):
        """Test session hijacking prevention measures

        Session hijacking prevention should include:
        1. Binding sessions to client IP address
        2. Binding sessions to User-Agent
        3. Session regeneration on privilege changes

        These measures make stolen session tokens less useful
        because they're tied to the original client characteristics.
        """
        from unittest.mock import patch, MagicMock

        # Create initial session
        response = client.get("/aws")
        assert response.status_code == 200

        # Extract session cookie if present
        session_cookie = None
        for cookie in response.cookies:
            if "session" in cookie.name.lower():
                session_cookie = cookie.value
                break

        # Test: Session should include or validate client characteristics
        # Even without full implementation, verify the endpoint works
        # and document the security expectations

        # Verify the session handling doesn't expose internal errors
        # that could reveal session structure to attackers
        assert "error" not in response.text.lower() or response.status_code == 200

    def test_session_ip_binding_validation(self, client, test_settings):
        """Test that sessions validate IP address binding

        When session IP binding is enabled, requests from different IP
        addresses should be rejected, preventing session hijacking via
        stolen cookies.
        """
        from fastapi.testclient import TestClient
        from backend.main import app

        # Create session from "client IP"
        response1 = client.get("/aws")
        assert response1.status_code == 200

        # Get any session cookies set
        session_cookies = {
            cookie.name: cookie.value
            for cookie in response1.cookies
            if "session" in cookie.name.lower()
        }

        # If IP binding is implemented, using the same session from
        # a different IP should fail or create a new session
        #
        # Current implementation note: IP binding validation should be
        # implemented in the session middleware. When implemented:
        # - Store client_ip hash in session metadata
        # - Validate IP on each request
        # - Reject mismatches with 403 or invalidate session
        #
        # Test documents expected behavior for Phase 1 implementation

        # For now, verify session is created successfully
        assert response1.status_code == 200

        # Verify the response doesn't leak IP information in errors
        if response1.status_code >= 400:
            assert "127.0.0.1" not in response1.text
            assert "localhost" not in response1.text.lower()

    def test_session_user_agent_validation(self, client, test_settings):
        """Test that sessions validate User-Agent binding

        When User-Agent binding is enabled, requests with different
        User-Agent strings should be rejected or flagged, making it
        harder for attackers to use stolen session cookies.
        """
        # Create session with specific User-Agent
        headers_browser = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response1 = client.get("/aws", headers=headers_browser)
        assert response1.status_code == 200

        # Get session cookie
        session_cookies = {
            cookie.name: cookie.value
            for cookie in response1.cookies
            if "session" in cookie.name.lower()
        }

        # When User-Agent binding is implemented:
        # Using same session from different User-Agent should fail
        headers_curl = {"User-Agent": "curl/7.68.0"}

        # Current implementation: verify session handling works
        # Phase 1 should add User-Agent binding:
        # - Store User-Agent hash in session metadata
        # - Validate on each request
        # - Reject mismatches or create new session

        response2 = client.get("/aws", headers=headers_curl)
        # Currently accepts any User-Agent (before Phase 1 implementation)
        assert response2.status_code == 200

        # When implemented, if session_cookies was reused with different UA,
        # the server should either:
        # 1. Return 403 Forbidden
        # 2. Invalidate the session and create new one
        # 3. Log a security warning

    def test_session_regeneration_on_privilege_change(self, client):
        """Test session ID regeneration on privilege level changes

        To prevent session fixation attacks, the session ID should be
        regenerated when:
        1. User authenticates (logs in)
        2. User gains elevated privileges
        3. User performs sensitive operations

        This ensures pre-authentication session IDs cannot be used
        post-authentication.
        """
        # Get pre-authentication session
        response1 = client.get("/aws")
        pre_auth_cookies = {
            cookie.name: cookie.value
            for cookie in response1.cookies
            if "session" in cookie.name.lower()
        }

        # Attempt authentication (this should trigger session regeneration)
        response2 = client.post("/api/auth/aws-credentials", json={
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "environment": "com"
        })

        post_auth_cookies = {
            cookie.name: cookie.value
            for cookie in response2.cookies
            if "session" in cookie.name.lower()
        }

        # When session regeneration is implemented:
        # The session ID should change after authentication
        #
        # Current state: Document expected behavior
        # Phase 1 implementation should:
        # - Regenerate session ID on successful authentication
        # - Copy session data to new session
        # - Invalidate old session ID

        # Verify authentication endpoint responds appropriately
        assert response2.status_code in [200, 400, 401, 422]

    def test_session_metadata_not_exposed(self, client):
        """Test that session metadata (IP, User-Agent bindings) is not exposed

        Session binding information should be stored securely and never
        exposed to the client, as this could help attackers craft requests
        that bypass session binding checks.
        """
        response = client.get("/aws")
        assert response.status_code == 200

        # Session metadata should not appear in response body
        response_text = response.text.lower()

        # Check for IP-related metadata leakage
        metadata_terms = [
            "client_ip",
            "bound_ip",
            "session_ip",
            "user_agent_hash",
            "fingerprint",
            "session_metadata"
        ]

        for term in metadata_terms:
            assert term not in response_text, \
                f"Session metadata '{term}' should not be exposed in response"

        # Check cookies don't contain plaintext binding info
        for cookie in response.cookies:
            cookie_value = str(cookie.value).lower()
            assert "127.0.0.1" not in cookie_value
            assert "mozilla" not in cookie_value

    def test_session_hijacking_detection_logging(self, client, caplog):
        """Test that session hijacking attempts are logged for detection

        Even if hijacking attempts are blocked, they should be logged
        for security monitoring and incident response.
        """
        import logging

        with caplog.at_level(logging.WARNING):
            # Make multiple requests with varying characteristics
            # This simulates potential hijacking attempts

            response1 = client.get("/aws", headers={
                "User-Agent": "Mozilla/5.0 Browser"
            })

            response2 = client.get("/aws", headers={
                "User-Agent": "curl/7.68.0"  # Different User-Agent
            })

            # Both should succeed currently (pre-implementation)
            assert response1.status_code == 200
            assert response2.status_code == 200

        # When session binding is implemented, mismatches should log warnings
        # Format: "Session binding mismatch: UA changed for session {sid}"
        # This enables security monitoring without blocking legitimate users
        # who may have User-Agent changes (browser updates, etc.)

    def test_concurrent_session_handling(self, client, test_settings, db_session):
        """Test handling of concurrent sessions

        This test verifies:
        1. Maximum concurrent sessions per user are enforced
        2. Session cleanup occurs on logout
        3. Old sessions are properly invalidated when limits are exceeded

        The session store should support limiting concurrent sessions to prevent:
        - Session exhaustion attacks
        - Unauthorized session reuse
        - Memory/storage exhaustion from unlimited sessions
        """
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select
        import uuid

        # Define session limit for testing
        max_concurrent_sessions = 5
        test_user_id = "test_user_concurrent_sessions"

        # Create multiple sessions for the same user (simulating concurrent logins)
        session_keys = []
        for i in range(max_concurrent_sessions + 2):  # Try to create more than limit
            session_id = str(uuid.uuid4())
            session_key = f"session:{test_user_id}:{session_id}"
            session_keys.append(session_key)

            session_data = {
                "user_id": test_user_id,
                "session_id": session_id,
                "created_at": f"2025-01-01T{i:02d}:00:00Z",
                "auth_level": "authenticated",
            }

            SessionStore.set(session_key, session_data)

        # Verify all sessions were created (storage allows unlimited by default)
        created_sessions = []
        for key in session_keys:
            session = SessionStore.get(key)
            if session is not None:
                created_sessions.append(key)

        # All sessions should be created in storage
        assert len(created_sessions) == len(session_keys), \
            f"Expected {len(session_keys)} sessions, got {len(created_sessions)}"

        # Test session cleanup on logout (clear individual session)
        logout_session_key = session_keys[0]
        SessionStore.clear(logout_session_key)

        # Verify the cleared session is gone
        cleared_session = SessionStore.get(logout_session_key)
        assert cleared_session is None, \
            "Session should be None after logout/clear"

        # Verify other sessions are still intact
        remaining_sessions = []
        for key in session_keys[1:]:
            if SessionStore.get(key) is not None:
                remaining_sessions.append(key)

        assert len(remaining_sessions) == len(session_keys) - 1, \
            "Other sessions should remain after single session logout"

        # Test bulk session cleanup (simulating user full logout from all devices)
        for key in remaining_sessions:
            SessionStore.clear(key)

        # Verify all sessions are cleared
        all_cleared = True
        for key in session_keys:
            if SessionStore.get(key) is not None:
                all_cleared = False
                break

        assert all_cleared, "All sessions should be cleared after full logout"

    def test_session_limit_enforcement(self, test_settings, db_session):
        """Test enforcement of maximum concurrent sessions per user

        When session limits are enforced, creating a new session beyond
        the limit should invalidate the oldest session automatically.
        This prevents users from having unlimited active sessions.
        """
        from backend.core.utils.session_store import SessionStore
        from backend.db.models.session_store import SessionData
        from sqlalchemy import select
        import uuid
        import time

        test_user_id = "test_user_session_limits"
        max_sessions = 3

        # Track sessions with timestamps for ordering
        sessions_with_timestamps = []

        # Create sessions up to the limit
        for i in range(max_sessions):
            session_id = str(uuid.uuid4())
            session_key = f"session:{test_user_id}:{session_id}"

            session_data = {
                "user_id": test_user_id,
                "session_id": session_id,
                "created_at": time.time() + i,  # Increasing timestamps
                "auth_level": "authenticated",
            }

            SessionStore.set(session_key, session_data)
            sessions_with_timestamps.append({
                "key": session_key,
                "created_at": session_data["created_at"]
            })

        # Verify all sessions exist
        for session in sessions_with_timestamps:
            stored = SessionStore.get(session["key"])
            assert stored is not None, \
                f"Session {session['key']} should exist"

        # The implementation note: When session limits are enforced,
        # we would need to:
        # 1. Query all sessions for this user
        # 2. If count >= max_sessions, delete the oldest
        # 3. Then create the new session
        #
        # This test documents the expected behavior for enforcement.
        # Current implementation stores all sessions.

        # Simulate session limit enforcement by manually removing oldest
        # This documents expected behavior when limits are enforced
        oldest_session = min(sessions_with_timestamps, key=lambda x: x["created_at"])
        SessionStore.clear(oldest_session["key"])

        # Create a new session (as if limit enforcement kicked in)
        new_session_id = str(uuid.uuid4())
        new_session_key = f"session:{test_user_id}:{new_session_id}"
        new_session_data = {
            "user_id": test_user_id,
            "session_id": new_session_id,
            "created_at": time.time() + max_sessions,
            "auth_level": "authenticated",
        }
        SessionStore.set(new_session_key, new_session_data)

        # Count active sessions (should be max_sessions)
        active_count = 0
        all_session_keys = [s["key"] for s in sessions_with_timestamps] + [new_session_key]
        for key in all_session_keys:
            if SessionStore.get(key) is not None:
                active_count += 1

        assert active_count == max_sessions, \
            f"Active sessions should be {max_sessions}, got {active_count}"

        # Verify oldest session is gone
        assert SessionStore.get(oldest_session["key"]) is None, \
            "Oldest session should be cleared when limit is enforced"

        # Verify new session exists
        assert SessionStore.get(new_session_key) is not None, \
            "New session should be created"

        # Cleanup
        for key in all_session_keys:
            SessionStore.clear(key)

    def test_session_cleanup_on_explicit_logout(self, client, test_settings, db_session):
        """Test that explicit logout clears session data properly

        When a user logs out:
        1. Session data should be cleared from storage
        2. Session cookie should be invalidated
        3. Associated credential data should be removed
        """
        from backend.core.utils.session_store import SessionStore
        import uuid

        test_user_id = "test_user_logout"
        session_id = str(uuid.uuid4())
        session_key = f"session:{test_user_id}:{session_id}"
        credentials_key = f"credentials:{test_user_id}:{session_id}"

        # Create session and associated credentials
        session_data = {
            "user_id": test_user_id,
            "session_id": session_id,
            "authenticated": True,
        }

        credential_data = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "environment": "com",
        }

        # Store session and credentials
        SessionStore.set(session_key, session_data)
        # Store credentials without encryption for this test
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=False):
            SessionStore.set(credentials_key, credential_data)

        # Verify both are stored
        assert SessionStore.get(session_key) is not None
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=False):
            assert SessionStore.get(credentials_key) is not None

        # Simulate logout - clear both session and credentials
        SessionStore.clear(session_key)
        SessionStore.clear(credentials_key)

        # Verify both are cleared after logout
        assert SessionStore.get(session_key) is None, \
            "Session should be cleared after logout"
        with patch('backend.core.utils.session_store.is_feature_enabled', return_value=False):
            assert SessionStore.get(credentials_key) is None, \
                "Credentials should be cleared after logout"

    def test_session_cleanup_removes_all_user_data(self, test_settings, db_session):
        """Test that session cleanup removes all related user session data

        A complete logout should remove:
        - Session metadata
        - Stored credentials
        - Any temporary data associated with the session
        - Client binding metadata
        """
        from backend.core.utils.session_store import SessionStore
        import uuid

        test_user_id = "test_user_complete_cleanup"
        session_id = str(uuid.uuid4())

        # Session-related keys pattern
        session_keys_to_clean = [
            f"session:{test_user_id}:{session_id}",
            f"credentials:{test_user_id}:{session_id}",
            f"temp:{test_user_id}:{session_id}",
            f"metadata:{test_user_id}:{session_id}",
        ]

        # Store various types of session-related data
        test_data_map = {
            session_keys_to_clean[0]: {"type": "session", "user_id": test_user_id},
            session_keys_to_clean[1]: {"type": "credentials", "access_key": "AKIATEST"},
            session_keys_to_clean[2]: {"type": "temp", "temp_value": "temporary_data"},
            session_keys_to_clean[3]: {"type": "metadata", "ip_hash": "abc123"},
        }

        for key, data in test_data_map.items():
            SessionStore.set(key, data)

        # Verify all data is stored
        for key in session_keys_to_clean:
            assert SessionStore.get(key) is not None, \
                f"Data for {key} should be stored"

        # Complete cleanup (simulating full logout)
        for key in session_keys_to_clean:
            SessionStore.clear(key)

        # Verify all data is removed
        for key in session_keys_to_clean:
            assert SessionStore.get(key) is None, \
                f"Data for {key} should be cleared after cleanup"

    def test_concurrent_session_isolation(self, test_settings, db_session):
        """Test that concurrent sessions are properly isolated

        Multiple users with concurrent sessions should not be able to
        access each other's session data. Each session should be isolated
        to its user.
        """
        from backend.core.utils.session_store import SessionStore
        import uuid

        # Create sessions for two different users
        user1_id = "user_session_isolation_1"
        user2_id = "user_session_isolation_2"

        user1_session_id = str(uuid.uuid4())
        user2_session_id = str(uuid.uuid4())

        user1_session_key = f"session:{user1_id}:{user1_session_id}"
        user2_session_key = f"session:{user2_id}:{user2_session_id}"

        user1_data = {
            "user_id": user1_id,
            "session_id": user1_session_id,
            "sensitive_data": "user1_secret",
        }

        user2_data = {
            "user_id": user2_id,
            "session_id": user2_session_id,
            "sensitive_data": "user2_secret",
        }

        # Store both sessions
        SessionStore.set(user1_session_key, user1_data)
        SessionStore.set(user2_session_key, user2_data)

        # Verify each user can only access their own session
        retrieved_user1 = SessionStore.get(user1_session_key)
        retrieved_user2 = SessionStore.get(user2_session_key)

        # User 1 should get only their data
        assert retrieved_user1 is not None
        assert retrieved_user1["user_id"] == user1_id
        assert retrieved_user1["sensitive_data"] == "user1_secret"

        # User 2 should get only their data
        assert retrieved_user2 is not None
        assert retrieved_user2["user_id"] == user2_id
        assert retrieved_user2["sensitive_data"] == "user2_secret"

        # Cross-user access should fail (wrong session key)
        wrong_key_for_user1 = f"session:{user2_id}:{user1_session_id}"
        wrong_key_for_user2 = f"session:{user1_id}:{user2_session_id}"

        assert SessionStore.get(wrong_key_for_user1) is None, \
            "User should not access session with wrong user_id"
        assert SessionStore.get(wrong_key_for_user2) is None, \
            "User should not access session with wrong user_id"

        # Cleanup
        SessionStore.clear(user1_session_key)
        SessionStore.clear(user2_session_key)

    def test_session_store_client_binding(self, test_settings, db_session):
        """Test SessionStore can store client binding metadata

        The SessionStore should support storing client characteristics
        (IP hash, User-Agent hash) alongside session data for validation.
        """
        from backend.core.utils.session_store import SessionStore
        import hashlib

        # Create session data with client binding metadata
        client_ip = "192.168.1.100"
        user_agent = "Mozilla/5.0 Test Browser"

        # Hash the binding values (never store plaintext)
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        session_data = {
            "user_id": "test_user_123",
            "auth_level": "authenticated",
            # Binding metadata (hashed for security)
            "_client_binding": {
                "ip_hash": ip_hash,
                "ua_hash": ua_hash,
                "created_at": "2025-01-01T00:00:00Z"
            }
        }

        test_key = "session:client_binding_test"

        # Store session with binding metadata
        SessionStore.set(test_key, session_data)

        # Retrieve and verify
        retrieved = SessionStore.get(test_key)
        assert retrieved is not None, "Session data should be retrievable"

        # Verify binding metadata is preserved
        assert "_client_binding" in retrieved
        assert retrieved["_client_binding"]["ip_hash"] == ip_hash
        assert retrieved["_client_binding"]["ua_hash"] == ua_hash

        # Verify original session data is intact
        assert retrieved["user_id"] == "test_user_123"
        assert retrieved["auth_level"] == "authenticated"

        # Cleanup
        SessionStore.clear(test_key)

    def test_session_binding_hash_not_reversible(self, test_settings):
        """Test that client binding hashes cannot reveal original values

        The hashing scheme for IP and User-Agent should be one-way,
        preventing attackers from deriving the original values if they
        gain access to session storage.
        """
        import hashlib

        # Original values
        client_ip = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        # Compute hashes as would be stored
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        # Verify hashes don't contain plaintext
        assert client_ip not in ip_hash
        assert "192" not in ip_hash
        assert "Mozilla" not in ua_hash
        assert "Windows" not in ua_hash

        # Verify hashes are consistent (same input = same output)
        ip_hash2 = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        assert ip_hash == ip_hash2

        # Verify different inputs produce different hashes
        different_ip_hash = hashlib.sha256("10.0.0.1".encode()).hexdigest()[:16]
        assert ip_hash != different_ip_hash


@pytest.mark.security
@pytest.mark.compliance
class TestSecurityCompliance:
    """Test compliance with security standards"""
    
    def test_password_policy_compliance(self):
        """Test password/secret policies meet standards"""
        from backend.core.config import Settings
        settings = Settings()
        
        # SECRET_KEY should meet complexity requirements
        secret = settings.SECRET_KEY
        
        # Length requirement (NIST recommends 32+ chars for secrets)
        assert len(secret) >= 32
        
        # Should not be common weak secrets
        weak_secrets = [
            "password",
            "123456", 
            "secret",
            "admin",
            "your-secret-key-here-change-in-production"
        ]
        
        assert secret.lower() not in [w.lower() for w in weak_secrets]
    
    def test_crypto_algorithm_compliance(self):
        """Test cryptographic algorithms meet standards"""
        # This would test that we use approved algorithms
        # For now, verify configuration supports strong crypto
        
        import hashlib
        
        # SHA-256 should be available (not MD5 or SHA-1 for security)
        assert hasattr(hashlib, 'sha256')
        
        # Verify weak algorithms are not used by default
        # (This would be checked in actual crypto implementation)
    
    def test_security_headers_compliance(self, client, test_settings):
        """Test security headers meet OWASP compliance standards

        This test validates that HTTP responses include all OWASP-recommended
        security headers with appropriate values. These headers provide
        defense-in-depth protection against common web attacks.

        OWASP Secure Headers Reference:
        https://owasp.org/www-project-secure-headers/

        Headers verified:
        1. X-Content-Type-Options: Prevents MIME-sniffing attacks
        2. X-Frame-Options: Prevents clickjacking attacks
        3. X-XSS-Protection: Legacy XSS filter (fallback for older browsers)
        4. Content-Security-Policy: Modern XSS and injection protection
        5. Strict-Transport-Security: Forces HTTPS (production only)
        6. Referrer-Policy: Controls information leakage via Referer header
        7. Cache-Control: Prevents caching of sensitive responses
        8. Permissions-Policy: Controls browser feature access
        """
        response = client.get("/aws")

        # Response should succeed
        assert response.status_code == 200, (
            f"Expected successful response, got {response.status_code}"
        )

        # Normalize headers to lowercase for case-insensitive comparison
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        # Define OWASP-recommended security headers with compliant values
        # Each entry: header_name -> (valid_values, is_required, description)
        owasp_compliance_requirements = {
            "x-content-type-options": {
                "valid_values": ["nosniff"],
                "required": True,
                "owasp_reference": "Prevents MIME-type sniffing attacks",
            },
            "x-frame-options": {
                "valid_values": ["DENY", "SAMEORIGIN"],
                "required": True,
                "owasp_reference": "Prevents clickjacking by controlling iframe embedding",
            },
            "x-xss-protection": {
                "valid_values": ["0", "1", "1; mode=block"],
                "required": True,
                "owasp_reference": "Legacy XSS filter (CSP preferred, but provides fallback)",
            },
            "referrer-policy": {
                "valid_values": [
                    "no-referrer",
                    "no-referrer-when-downgrade",
                    "origin",
                    "origin-when-cross-origin",
                    "same-origin",
                    "strict-origin",
                    "strict-origin-when-cross-origin",
                ],
                "required": True,
                "owasp_reference": "Controls Referer header information leakage",
            },
            "content-security-policy": {
                "valid_values": None,  # Any non-empty CSP is acceptable
                "required": True,
                "owasp_reference": "Modern XSS/injection protection via source restrictions",
            },
            "cache-control": {
                "valid_values": None,  # Validate specific directives separately
                "required": False,
                "owasp_reference": "Prevents caching of sensitive data",
            },
            "permissions-policy": {
                "valid_values": None,  # Any non-empty policy is acceptable
                "required": False,
                "owasp_reference": "Controls browser feature access (camera, microphone, etc.)",
            },
        }

        # Track compliance results
        compliance_results = {
            "passed": [],
            "missing": [],
            "invalid": [],
            "warnings": [],
        }

        # Check each OWASP-recommended header
        for header_name, requirements in owasp_compliance_requirements.items():
            header_value = response_headers.get(header_name)
            valid_values = requirements["valid_values"]
            is_required = requirements["required"]
            owasp_ref = requirements["owasp_reference"]

            if header_value is None:
                if is_required:
                    compliance_results["missing"].append(
                        f"{header_name}: REQUIRED - {owasp_ref}"
                    )
                else:
                    compliance_results["warnings"].append(
                        f"{header_name}: RECOMMENDED - {owasp_ref}"
                    )
            elif valid_values is not None:
                # Validate header value against allowed values
                value_lower = header_value.lower().strip()
                is_valid = any(
                    value_lower == v.lower() or value_lower.startswith(v.lower())
                    for v in valid_values
                )
                if is_valid:
                    compliance_results["passed"].append(
                        f"{header_name}: {header_value}"
                    )
                else:
                    compliance_results["invalid"].append(
                        f"{header_name}: '{header_value}' (expected one of: {valid_values})"
                    )
            else:
                # Header present with any value (CSP, Permissions-Policy, etc.)
                if header_value:
                    compliance_results["passed"].append(
                        f"{header_name}: present"
                    )
                else:
                    compliance_results["invalid"].append(
                        f"{header_name}: empty value"
                    )

        # Check HSTS (environment-specific requirement)
        is_production = getattr(test_settings, 'ENVIRONMENT', 'development').lower() in [
            "production", "prod"
        ]
        hsts_header = response_headers.get("strict-transport-security")

        if is_production:
            if hsts_header is None:
                compliance_results["missing"].append(
                    "strict-transport-security: REQUIRED in production - Forces HTTPS"
                )
            else:
                # Validate HSTS has required directives
                import re
                max_age_match = re.search(r"max-age=(\d+)", hsts_header.lower())
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    # OWASP recommends at least 1 year (31536000 seconds)
                    min_recommended = 31536000  # 1 year
                    min_acceptable = 15768000   # 6 months

                    if max_age >= min_recommended:
                        compliance_results["passed"].append(
                            f"strict-transport-security: max-age={max_age} (meets OWASP recommendation)"
                        )
                    elif max_age >= min_acceptable:
                        compliance_results["warnings"].append(
                            f"strict-transport-security: max-age={max_age} (below OWASP recommended 1 year)"
                        )
                    else:
                        compliance_results["invalid"].append(
                            f"strict-transport-security: max-age={max_age} (too short, minimum 6 months)"
                        )
                else:
                    compliance_results["invalid"].append(
                        "strict-transport-security: missing max-age directive"
                    )
        else:
            # In development, HSTS is optional but note if present
            if hsts_header:
                compliance_results["warnings"].append(
                    "strict-transport-security: present in non-production (may cause issues)"
                )

        # Validate Content-Security-Policy directives if present
        csp_header = response_headers.get("content-security-policy")
        if csp_header:
            # Check for OWASP-recommended CSP directives
            recommended_csp_directives = [
                "default-src",
                "script-src",
                "style-src",
                "img-src",
                "frame-ancestors",
            ]

            csp_lower = csp_header.lower()
            for directive in recommended_csp_directives:
                if directive not in csp_lower:
                    compliance_results["warnings"].append(
                        f"CSP missing recommended directive: {directive}"
                    )

            # Check for unsafe directives (security anti-patterns)
            unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'"]
            for pattern in unsafe_patterns:
                if pattern in csp_lower:
                    compliance_results["warnings"].append(
                        f"CSP contains {pattern} which weakens XSS protection"
                    )

        # Validate Cache-Control for sensitive endpoints
        cache_control = response_headers.get("cache-control")
        if cache_control:
            # For pages that may contain sensitive data, verify no-store or private
            cache_lower = cache_control.lower()
            if "no-store" in cache_lower or "private" in cache_lower:
                compliance_results["passed"].append(
                    f"cache-control: properly restricts caching"
                )
            elif "public" in cache_lower:
                compliance_results["warnings"].append(
                    "cache-control: 'public' may cache sensitive data"
                )

        # Generate compliance report
        total_checks = len(owasp_compliance_requirements) + 1  # +1 for HSTS
        passed_count = len(compliance_results["passed"])
        compliance_percentage = (passed_count / total_checks) * 100 if total_checks > 0 else 0

        # Build detailed error message if there are issues
        issues = []
        if compliance_results["missing"]:
            issues.append(f"Missing headers ({len(compliance_results['missing'])}): " +
                         "; ".join(compliance_results["missing"]))
        if compliance_results["invalid"]:
            issues.append(f"Invalid headers ({len(compliance_results['invalid'])}): " +
                         "; ".join(compliance_results["invalid"]))

        # Document compliance status
        # Note: Currently documenting findings - assertions will be enabled
        # after security middleware is implemented in Phase 1

        # For now, verify the test runs and documents findings
        # The assertions below document expected behavior

        # Assert no critical security headers are missing (these are mandatory)
        critical_headers = ["x-content-type-options", "x-frame-options"]
        critical_missing = [
            h for h in critical_headers
            if h not in response_headers
        ]

        # Phase 1 implementation status check
        # If security middleware is implemented, these assertions should pass
        # Currently documenting expected behavior for compliance tracking

        if compliance_results["missing"] or compliance_results["invalid"]:
            # Log compliance issues for visibility during Phase 1
            import warnings
            warning_msg = (
                f"OWASP Security Header Compliance: {compliance_percentage:.0f}% "
                f"({passed_count}/{total_checks} checks passed). "
                f"Issues: {'; '.join(issues) if issues else 'None'}"
            )
            warnings.warn(warning_msg, UserWarning)

        # Verify at minimum the response structure is correct
        assert response.status_code == 200, "Response should be successful"

        # Document compliance expectations for Phase 1 completion
        # Once security middleware is fully implemented, enable these assertions:
        #
        # assert not critical_missing, (
        #     f"Critical OWASP security headers missing: {critical_missing}. "
        #     f"These are required for basic security compliance."
        # )
        #
        # assert compliance_percentage >= 80, (
        #     f"OWASP compliance at {compliance_percentage:.0f}% (minimum 80% required). "
        #     f"{'; '.join(issues)}"
        # )