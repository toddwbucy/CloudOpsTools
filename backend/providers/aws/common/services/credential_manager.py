import logging
import time
from typing import Dict, Optional, Tuple, TypedDict, cast, Any

import aiobotocore.session
from aiobotocore.client import AioBaseClient
import boto3  # Keep for synchronous fallback if absolutely needed, or remove if fully committed

# Define TypedDict for credential validation results
class CredentialValidationResult(TypedDict):
    valid: bool
    expiring_soon: bool
    time_remaining: Optional[int]


from backend.core.config import AWSCredentials, AWSEnvironment, settings

# For backward compatibility - aliasing AWSCredentials to CredentialSchema
CredentialSchema = AWSCredentials

# Configure environment-specific settings
ENV_CONFIGS = {
    "gov": {
        "region": "us-gov-west-1",
        "endpoint": "https://sts.us-gov-west-1.amazonaws.com",
    },
    "com": {
        "region": "us-east-1",
        "endpoint": "https://sts.us-east-1.amazonaws.com",
    },
}

logger = logging.getLogger(__name__)


class CredentialManager:
    """Service for managing AWS credentials (Async)"""

    def __init__(self, ttl_seconds: int = 2700):
        """Initialize the credential manager
        
        Args:
            ttl_seconds: Time-to-live for credentials in seconds
            Default: 2700 seconds (45 minutes)
        """
        self.ttl_seconds = ttl_seconds
        self._credentials_cache: Dict[str, CredentialSchema] = {}
        self._session = aiobotocore.session.get_session()

        # Load initial credentials from settings if available
        self._load_credentials_from_settings()

    def _load_credentials_from_settings(self) -> None:
        """Load initial credentials from application settings"""
        logger.debug("Loading credentials from application settings")

        # Check for available environments in settings
        available_envs = settings.get_available_environments()

        for env in available_envs:
            env_name = env.value
            logger.info(f"Found credentials for {env_name.upper()} in settings")

            # Get credentials from settings
            creds = settings.get_credentials(env)
            if creds:
                # Only create credentials if access_key and secret_key are not None
                if creds.access_key is not None and creds.secret_key is not None:
                    # Convert to CredentialSchema and store
                    schema_creds = CredentialSchema(
                        access_key=creds.access_key,
                        secret_key=creds.secret_key,
                        session_token=creds.session_token,
                        expiration=int(
                            time.time() + self.ttl_seconds
                        ),  # Set initial expiration as int
                        environment=AWSEnvironment(env_name),  # Convert to enum
                    )
                    self.store_credentials(schema_creds)

    def _get_env_config(self, environment: str) -> Dict[str, str]:
        """Get environment configuration"""
        environment = environment.lower()
        if environment not in ENV_CONFIGS:
            raise ValueError(f"Invalid environment: {environment}")
        return ENV_CONFIGS[environment]

    def _check_expiry(self, creds: Optional[CredentialSchema]) -> bool:
        """Check if credentials have expired"""
        if not creds:
            logger.debug("No credentials found to check expiry")
            return True

        current_time = time.time()

        # Handle case when expiration is None
        if creds.expiration is None:
            # Use the access_time if available, otherwise enforce 45-minute expiration
            if hasattr(creds, "access_time"):
                time_remaining = creds.access_time + self.ttl_seconds - current_time
                logger.debug(
                    f"No explicit expiration for {creds.environment} credentials. Using access_time + ttl. Time remaining: {time_remaining:.2f}s"
                )
            else:
                # Without expiration or access_time, credentials must be re-validated
                logger.debug(
                    f"No expiration or access_time for {creds.environment} credentials. Must be re-validated."
                )
                return True
        else:
            time_remaining = creds.expiration - current_time
            logger.debug(
                f"Checking expiry for {creds.environment} credentials. Time remaining: {time_remaining:.2f}s"
            )

        # Add warning if credentials are about to expire
        if 0 < time_remaining <= 300:  # 5 minutes
            logger.warning(
                f"Credentials for {creds.environment} will expire in {time_remaining:.2f} seconds"
            )

        is_expired = time_remaining <= 0
        if is_expired:
            logger.warning(f"Credentials for {creds.environment} have expired")

        return bool(is_expired)  # Ensure return type is strictly bool

    def store_credentials(self, credentials: CredentialSchema) -> None:
        """Store credentials for an environment"""
        env_name = credentials.environment.value if hasattr(credentials.environment, 'value') else str(credentials.environment)
        logger.info(
            f"Storing credentials for {env_name.upper()} environment"
        )

        # Add access_time for tracking when credentials were stored
        if not hasattr(credentials, "access_time"):
            credentials.access_time = time.time()

        # Ensure credentials have an expiration (default: 45 minutes from now)
        if credentials.expiration is None:
            credentials.expiration = int(time.time() + self.ttl_seconds)
            logger.info(
                f"Setting default 45-minute expiration for {env_name.upper()} credentials"
            )

        # Store with the string value of the enum, not the enum itself
        env_key = credentials.environment.value if hasattr(credentials.environment, 'value') else str(credentials.environment).lower()
        self._credentials_cache[env_key] = credentials
        logger.debug(f"Credentials stored for {env_key.upper()}")

    def get_credentials(self, environment: str) -> Optional[CredentialSchema]:
        """Get stored credentials if they exist and haven't expired"""
        environment = environment.lower()
        logger.debug(f"Getting credentials for {environment}. Cache keys: {list(self._credentials_cache.keys())}")
        creds = self._credentials_cache.get(environment)

        if self._check_expiry(creds):
            self.clear_credentials(environment)
            return None

        return creds

    async def validate_credentials(
        self,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None,
        environment: str = "com",
    ) -> Tuple[bool, str]:
        """Validate AWS credentials and store if valid (Async)."""
        environment = environment.lower()
        logger.info(f"Validating credentials for {environment.upper()} environment")

        # DEV MODE: Skip AWS validation and accept any credentials
        if settings.DEV_MODE:
            logger.warning("DEV MODE ENABLED: Bypassing AWS credential validation")
            return True, (
                f"DEV MODE: Credentials accepted for {environment.upper()} (not validated against AWS)"
            )

        try:
            env_config = self._get_env_config(environment)
            logger.debug(f"Using endpoint: {env_config['endpoint']}")

            # Always clear and validate new credentials when explicitly provided
            self.clear_credentials(environment)

            # Build a session with the supplied credentials and call STS
            # Note: aiobotocore sessions are created from the session factory
            session = aiobotocore.session.get_session()
            
            async with session.create_client(
                "sts", 
                region_name=env_config["region"], 
                endpoint_url=env_config["endpoint"],
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            ) as sts:
                response = await sts.get_caller_identity()

            # Use a conservative expiration window; if a session token is present,
            # treat as temporary credentials and set TTL, otherwise same TTL for simplicity.
            expiration = int(time.time() + self.ttl_seconds)

            # Store valid credentials
            credential_schema = CredentialSchema(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                expiration=expiration,
                environment=AWSEnvironment(environment),
            )
            self.store_credentials(credential_schema)

            # Also update the settings model if possible
            if environment == "com":
                settings.AWS_ACCESS_KEY_ID_COM = access_key
                settings.AWS_SECRET_ACCESS_KEY_COM = secret_key
                settings.AWS_SESSION_TOKEN_COM = session_token
            elif environment == "gov":
                settings.AWS_ACCESS_KEY_ID_GOV = access_key
                settings.AWS_SECRET_ACCESS_KEY_GOV = secret_key
                settings.AWS_SESSION_TOKEN_GOV = session_token

            logger.info(
                f"Successfully validated {environment.upper()} credentials for account: {response.get('Account', 'unknown')}"
            )
            return True, f"{environment.capitalize()} credentials validated successfully."

        except Exception as e:
            logger.error(
                f"Failed to validate {environment.upper()} credentials: {str(e)}"
            )
            return False, f"Credential validation failed: {str(e)}"

    def clear_credentials(self, environment: str) -> None:
        """Clear stored credentials for an environment"""
        environment = environment.lower()
        logger.info(f"Clearing credentials for {environment.upper()}")

        # Remove from in-memory cache
        if environment in self._credentials_cache:
            del self._credentials_cache[environment]

        # Also clear from application settings
        if environment == "com":
            settings.AWS_ACCESS_KEY_ID_COM = None
            settings.AWS_SECRET_ACCESS_KEY_COM = None
            settings.AWS_SESSION_TOKEN_COM = None
            logger.info("Cleared COM credentials from application settings")
        elif environment == "gov":
            settings.AWS_ACCESS_KEY_ID_GOV = None
            settings.AWS_SECRET_ACCESS_KEY_GOV = None
            settings.AWS_SESSION_TOKEN_GOV = None
            logger.info("Cleared GOV credentials from application settings")

    def create_session(self, environment: str) -> Optional[aiobotocore.session.AioSession]:
        """Create an aiobotocore session for an environment (Async-ready)"""
        # Note: aiobotocore sessions are synchronous to create, but clients are async context managers
        environment = environment.lower()
        creds = self.get_credentials(environment)

        # If no cached credentials, try to load from settings
        if not creds and (environment == "com" or environment == "gov"):
            # Try to get credentials from settings directly
            env_enum = (
                AWSEnvironment.COM if environment == "com" else AWSEnvironment.GOV
            )
            settings_creds = settings.get_credentials(env_enum)

            if (
                settings_creds
                and settings_creds.access_key is not None
                and settings_creds.secret_key is not None
            ):
                # Convert to CredentialSchema and cache
                creds = CredentialSchema(
                    access_key=settings_creds.access_key,
                    secret_key=settings_creds.secret_key,
                    session_token=settings_creds.session_token,
                    expiration=int(time.time() + self.ttl_seconds),
                    environment=AWSEnvironment(environment),
                )
                self.store_credentials(creds)

        if not creds:
            logger.error(f"No valid credentials found for {environment}")
            return None

        # Create session
        session = aiobotocore.session.get_session()
        
        # We can't set credentials on the session object directly in the same way as boto3
        # Instead, we'll use set_credentials method if available or rely on passing them to create_client
        session.set_credentials(
            creds.access_key,
            creds.secret_key,
            creds.session_token
        )
        
        return session

    def create_client(
        self, service: str, environment: str, region: Optional[str] = None
    ) -> Any:
        """
        Create an aiobotocore client context manager for a service and environment.
        
        Usage:
            async with credential_manager.create_client('s3', 'com') as client:
                await client.list_buckets()
        """
        environment = environment.lower()
        creds = self.get_credentials(environment)
        
        if not creds:
            # Try to load from settings as fallback (similar to create_session logic)
            self.create_session(environment)
            creds = self.get_credentials(environment)
            
        if not creds:
            logger.error(f"No valid credentials found for {environment}")
            return None

        env_config = self._get_env_config(environment)
        session = aiobotocore.session.get_session()
        
        return session.create_client(
            service,
            region_name=region or env_config["region"],
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.session_token,
        )

    def are_credentials_valid(self, environment: str) -> CredentialValidationResult:
        """Check if valid credentials exist for an environment"""
        environment = environment.lower()
        creds = self._credentials_cache.get(environment)
        result: CredentialValidationResult = {
            "valid": False,
            "expiring_soon": False,
            "time_remaining": None,
        }

        if not creds:
            return result

        # Check if credentials are expired
        if self._check_expiry(creds):
            return result

        # Calculate time remaining
        if creds.expiration:
            time_remaining = creds.expiration - time.time()
            result["time_remaining"] = max(0, int(time_remaining))

            # Check if credentials are about to expire
            if 0 < time_remaining <= 300:  # 5 minutes
                result["expiring_soon"] = True

            # Check if credentials are valid
            if time_remaining > 0:
                result["valid"] = True
        else:
            # For credentials without expiration, use access_time
            if hasattr(creds, "access_time"):
                time_remaining = creds.access_time + self.ttl_seconds - time.time()
                result["time_remaining"] = max(0, int(time_remaining))

                # Check if credentials are about to expire
                if 0 < time_remaining <= 300:  # 5 minutes
                    result["expiring_soon"] = True

                # Check if credentials are valid
                if time_remaining > 0:
                    result["valid"] = True

        return result

    def list_active_environments(self) -> Dict[str, CredentialValidationResult]:
        """List environments and their credential validity with metadata"""
        result = {}

        # Check all known environments
        for env in ENV_CONFIGS.keys():
            result[env] = self.are_credentials_valid(env)

        return result

    async def refresh_credentials(
        self, environment: str, role_arn: Optional[str] = None
    ) -> Tuple[bool, str, Optional[CredentialSchema]]:
        """Request fresh temporary credentials for an environment via STS (Async)"""
        environment = environment.lower()
        logger.info(f"Refreshing credentials for {environment.upper()} environment")

        # Check if environment is valid
        try:
            env_config = self._get_env_config(environment)
        except ValueError as e:
            return False, str(e), None

        # Get existing credentials
        existing_creds = self.get_credentials(environment)
        if not existing_creds:
            return False, f"No valid base credentials found for {environment}", None

        try:
            session = aiobotocore.session.get_session()
            
            async with session.create_client(
                "sts",
                region_name=env_config["region"],
                endpoint_url=env_config["endpoint"],
                aws_access_key_id=existing_creds.access_key,
                aws_secret_access_key=existing_creds.secret_key,
                aws_session_token=existing_creds.session_token,
            ) as sts:

                if role_arn:
                    logger.info(
                        f"Assuming role {role_arn} for {environment.upper()} environment"
                    )
                    # Assume role to get fresh credentials
                    response = await sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"API-Refresh-{int(time.time())}",
                        DurationSeconds=3600,  # 1 hour
                    )

                    # Extract credentials
                    credentials = response["Credentials"]
                    fresh_creds = CredentialSchema(
                        access_key=credentials["AccessKeyId"],
                        secret_key=credentials["SecretAccessKey"],
                        session_token=credentials["SessionToken"],
                        expiration=int(time.time() + 3600),  # 1 hour
                        environment=AWSEnvironment(environment),
                    )

                else:
                    try:
                        # Try to get a session token (only works with long-term credentials)
                        logger.info(
                            f"Getting session token for {environment.upper()} environment"
                        )
                        response = await sts.get_session_token(DurationSeconds=3600)

                        # Extract credentials
                        credentials = response["Credentials"]
                        fresh_creds = CredentialSchema(
                            access_key=response["Credentials"]["AccessKeyId"],
                            secret_key=response["Credentials"]["SecretAccessKey"],
                            session_token=response["Credentials"]["SessionToken"],
                            expiration=int(time.time() + 3600),  # 1 hour
                            environment=AWSEnvironment(environment),
                        )
                    except Exception as e:
                        if "with session credentials" in str(e):
                            # The credentials are already temporary - can't refresh with GetSessionToken
                            return (
                                False,
                                "Cannot refresh temporary credentials without assuming a role. Temporary credentials must be refreshed through your identity provider (e.g., AWS SSO).",
                                existing_creds,
                            )
                        else:
                            # Some other error occurred
                            raise

            # Store the fresh credentials
            self.store_credentials(fresh_creds)

            return (
                True,
                f"Successfully refreshed credentials for {environment}",
                fresh_creds,
            )

        except Exception as e:
            logger.error(
                f"Failed to refresh {environment.upper()} credentials: {str(e)}"
            )
            return False, f"Failed to refresh credentials: {str(e)}", None
