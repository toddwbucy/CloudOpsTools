"""Server-side session storage on SQLite.

Stores large transient payloads in the `sessiondata` table to keep cookie sessions small.
Keys are caller-defined strings; recommended pattern: `<namespace>:<sid>`.
"""
from __future__ import annotations

from threading import Lock, Event
from typing import Any, Optional
import logging

from sqlalchemy import select

from backend.db.base import Base
from backend.db.models.session_store import SessionData
from backend.db.session import engine, get_db_sync

logger = logging.getLogger(__name__)


class SessionEncryptionError(Exception):
    """Raised when session data encryption fails"""
    pass

# Track if tables have been initialized
_tables_initialized: bool = False

# Threading primitives for table initialization
_tables_init_lock: Lock = Lock()
_tables_init_event: Event = Event()


class SessionStore:
    @classmethod
    def _ensure_table(cls) -> None:
        """Ensure the sessiondata table exists in a thread-safe manner."""
        global _tables_initialized

        # Check if already initialized (fast path)
        if _tables_initialized:
            return

        # Check if initialization is in progress
        if _tables_init_event.is_set():
            return

        # Use lock for initialization coordination
        with _tables_init_lock:
            # Double-check after acquiring lock
            if not _tables_initialized:
                try:
                    Base.metadata.create_all(
                        bind=engine,
                        tables=[SessionData.__table__],
                        checkfirst=True  # Explicit to avoid redundant DDL
                    )
                    _tables_initialized = True
                    # Signal to waiting threads that initialization is complete
                    _tables_init_event.set()
                    logger.debug("Session store table initialized successfully")
                    
                except Exception as e:
                    logger.error(f"Failed to initialize session store table: {e}")
                    raise
            else:
                # Another thread completed initialization while we were waiting
                _tables_init_event.set()
    
    @classmethod
    def _should_encrypt_data(cls, key: str) -> bool:
        """
        Determine if data should be encrypted based on feature flag and key pattern.
        
        Args:
            key: The session key
            
        Returns:
            True if data should be encrypted, False otherwise
        """
        try:
            from backend.core.feature_flags import is_feature_enabled
            if not is_feature_enabled('SECURE_CREDENTIAL_STORAGE'):
                return False
        except ImportError:
            return False
        
        # Only encrypt credential-related data
        credential_patterns = ['credentials:', 'aws_creds:', 'auth:', 'token:']
        return any(key.startswith(pattern) for pattern in credential_patterns)
    
    @classmethod
    def _encrypt_data(cls, data: Any) -> str:
        """
        Encrypt data for secure storage.
        
        Args:
            data: The data to encrypt
            
        Returns:
            Encrypted string
            
        Raises:
            SessionEncryptionError: If encryption fails
        """
        try:
            from backend.core.utils.encryption import encrypt_session_credentials
            import json
            
            # Convert data to dict format for encryption
            if hasattr(data, 'dict'):
                # Pydantic model
                data_dict = data.dict()
            elif isinstance(data, dict):
                data_dict = data
            else:
                # Try to serialize to JSON first
                data_dict = {'value': data}
            
            return encrypt_session_credentials(data_dict)
            
        except Exception as e:
            logger.error(f"Failed to encrypt session data: {e}")
            # SECURITY: Never fall back to plaintext storage for sensitive data
            raise SessionEncryptionError(f"Session data encryption failed: {e}") from e
    
    @classmethod
    def _decrypt_data(cls, encrypted_data: str) -> Any:
        """
        Decrypt data from secure storage.
        
        Args:
            encrypted_data: The encrypted data string
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            from backend.core.utils.encryption import decrypt_session_credentials
            
            decrypted = decrypt_session_credentials(encrypted_data)
            if decrypted is None:
                return None
                
            # If the data was wrapped in a 'value' key, unwrap it
            if isinstance(decrypted, dict) and len(decrypted) == 1 and 'value' in decrypted:
                return decrypted['value']
            
            return decrypted
            
        except Exception as e:
            logger.error(f"Failed to decrypt session data: {e}")
            return None

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        """
        Store a value with the given key.
        
        Args:
            key: The session key
            value: The value to store
            
        Raises:
            SessionEncryptionError: If encryption fails for sensitive data
        """
        cls._ensure_table()
        
        # Encrypt data if it should be encrypted
        if cls._should_encrypt_data(key):
            # Let encryption errors bubble up - no fallback to plaintext
            stored_value = cls._encrypt_data(value)
            logger.debug(f"Encrypted session data for key pattern: {key.split(':')[0]}")
        else:
            stored_value = value
        
        with get_db_sync() as db:
            try:
                # Use proper UPSERT logic to prevent race conditions
                # First, try to update existing record
                from sqlalchemy import update
                
                result = db.execute(
                    update(SessionData)
                    .where(SessionData.key == key)
                    .values(data=stored_value)
                )
                
                # If no rows were updated, insert a new record
                if result.rowcount == 0:
                    try:
                        row = SessionData(key=key, data=stored_value)
                        db.add(row)
                    except Exception as insert_error:
                        # Handle race condition: another thread may have inserted between
                        # our UPDATE and INSERT. Retry the UPDATE.
                        db.rollback()
                        logger.debug(f"Insert failed due to race condition, retrying update for key: {key}")
                        
                        # Retry the update operation
                        result = db.execute(
                            update(SessionData)
                            .where(SessionData.key == key)  
                            .values(data=stored_value)
                        )
                        
                        if result.rowcount == 0:
                            # This shouldn't happen but handle gracefully
                            raise RuntimeError(f"Failed to insert or update session data for key: {key}")
                
                db.commit()
                
            except Exception as e:
                db.rollback()
                logger.error(f"Database operation failed for key {key}: {e}")
                raise

    @classmethod
    def get(cls, key: str) -> Optional[Any]:
        """Retrieve the value for the given key."""
        cls._ensure_table()
        with get_db_sync() as db:
            row = db.scalar(select(SessionData).where(SessionData.key == key))
            if not row:
                return None
            
            # Decrypt data if it should be encrypted
            if cls._should_encrypt_data(key) and isinstance(row.data, str):
                try:
                    decrypted = cls._decrypt_data(row.data)
                    if decrypted is not None:
                        logger.debug(f"Decrypted session data for key pattern: {key.split(':')[0]}")
                        return decrypted
                    else:
                        logger.warning(f"Failed to decrypt session data for key: {key}")
                        # SECURITY: Never return raw encrypted data, return None instead
                        return None
                except Exception as e:
                    logger.error(f"Decryption failed for session key {key}: {e}")
                    # SECURITY: Never return raw encrypted data, return None instead
                    return None
            
            return row.data

    @classmethod
    def clear(cls, key: str) -> None:
        """Remove the entry for the given key."""
        cls._ensure_table()
        with get_db_sync() as db:
            row = db.scalar(select(SessionData).where(SessionData.key == key))
            if row:
                db.delete(row)
                db.commit()
