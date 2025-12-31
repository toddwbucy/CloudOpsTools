import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.core.config import settings
from backend.core.limiter import limiter
from backend.db.base import Base
from backend.db.models import account as _model_account  # noqa: F401
from backend.db.models import change as _model_change  # noqa: F401
from backend.db.models import execution as _model_execution  # noqa: F401

# Ensure all models (including auxiliary storage) are registered before create_all
from backend.db.models import script as _model_script  # noqa: F401
from backend.db.models import session_store as _model_session_store  # noqa: F401
from backend.db.session import engine
from backend.web import home
from backend.web.aws import auth as aws_auth
from backend.web.aws import linux_qc_patching_post as linux_qc_patching_post_web

# script_runner removed - functionality moved to backend service
from backend.web.aws import linux_qc_patching_prep as linux_qc_patching_prep_web
from backend.web.aws import sft_fixer as sft_fixer_web

# Get the backend directory path
BACKEND_DIR = Path(__file__).parent

# Initialize structured logging
from backend.core.utils.logging_config import init_application_logging
init_application_logging()

logger = logging.getLogger("pcm_ops_tools.main")

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title="PCM-Ops Tools",
    description="Unified platform for cloud operations management",
    version="2.0.0",
)

# Attach limiter to app.state for access in route decorators
# This must be done before applying @limiter.limit() decorators
app.state.limiter = limiter

# Add global exception handler for rate limit exceeded errors
# This ensures consistent HTTP 429 responses with Retry-After headers
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

logger.info(
    "Rate limiting initialized with configuration: auth=%s, execution=%s, read=%s",
    settings.rate_limit_auth_endpoints,
    settings.rate_limit_execution_endpoints,
    settings.rate_limit_read_endpoints,
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="pcm-ops-session",
    max_age=1800,  # 30 minutes
    https_only=settings.ENVIRONMENT == "production",
    same_site="lax",  # Allow cookies in form submissions
)

# Configure CORS (restrict origins; credentials require explicit origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security headers middleware for XSS protection
from backend.core.security import SecurityHeadersMiddleware, CSRFProtectionMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFProtectionMiddleware, secret_key=settings.SECRET_KEY)

# Mount static files
app.mount("/static", StaticFiles(directory=str(BACKEND_DIR / "static")), name="static")

# Configure templates with custom globals
templates = Jinja2Templates(directory=str(BACKEND_DIR / "templates"))


# Add Flask-compatible template functions
def get_flashed_messages(with_categories=False):
    """Stub for Flask's get_flashed_messages - returns empty list"""
    if with_categories:
        return []  # Return empty list of tuples when categories requested
    return []


templates.env.globals["get_flashed_messages"] = get_flashed_messages

# Add CSRF token generation function to template globals
from backend.core.security import generate_csrf_token_for_template, get_current_nonce
templates.env.globals["csrf_token"] = generate_csrf_token_for_template
templates.env.globals["csp_nonce"] = get_current_nonce

# Import and include API routers
from backend.api import auth, scripts, tools, feature_flags

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scripts.router, prefix="/api/scripts", tags=["Scripts"])
app.include_router(tools.router, prefix="/api/tools", tags=["Tools"])
app.include_router(feature_flags.router, prefix="/api", tags=["Feature Flags"])

# Include web routers
app.include_router(home.router, tags=["Web"])
app.include_router(aws_auth.router, tags=["AWS Authentication Web"])
# Script Runner has been removed - functionality moved to backend-only service
# and exposed through specialized tools like Linux QC Patching
app.include_router(
    linux_qc_patching_prep_web.router, prefix="/aws/linux-qc-patching-prep", tags=["AWS Linux QC Patching Prep Web"]
)
app.include_router(
    linux_qc_patching_post_web.router, prefix="/aws/linux-qc-patching-post", tags=["AWS Linux QC Patching Post Web"]
)
app.include_router(
    sft_fixer_web.router, prefix="/aws/sft-fixer", tags=["AWS SFT Fixer Web"]
)

# Add redirects from old URLs to new URLs for backward compatibility
from fastapi.responses import RedirectResponse


@app.get("/aws/linux-patcher")
@app.get("/aws/linux-patcher/{path:path}")
async def redirect_old_linux_patcher(path: str = ""):
    """Redirect old Linux Patcher URLs to new Linux QC Patching Prep URLs"""
    new_url = f"/aws/linux-qc-patching-prep/{path}" if path else "/aws/linux-qc-patching-prep"
    return RedirectResponse(url=new_url, status_code=301)

@app.get("/aws/linux-qc-prep")
@app.get("/aws/linux-qc-prep/{path:path}")
async def redirect_old_qc_prep(path: str = ""):
    """Redirect old Linux QC Prep URLs to new Linux QC Patching Prep URLs"""
    new_url = f"/aws/linux-qc-patching-prep/{path}" if path else "/aws/linux-qc-patching-prep"
    return RedirectResponse(url=new_url, status_code=301)

@app.get("/aws/linux-qc-post")
@app.get("/aws/linux-qc-post/{path:path}")
async def redirect_old_qc_post(path: str = ""):
    """Redirect old Linux QC Post URLs to new Linux QC Patching Post URLs"""
    new_url = f"/aws/linux-qc-patching-post/{path}" if path else "/aws/linux-qc-patching-post"
    return RedirectResponse(url=new_url, status_code=301)

# Dynamically discover and include provider API routers
from backend.providers import discover_provider_routers

provider_info = discover_provider_routers(app)


def _check_storage_health() -> dict:
    """
    Check the health of the rate limiting storage backend.

    Returns dict with storage health status and details.
    """
    storage_type = "redis" if settings.redis_url else "memory"

    if storage_type == "memory":
        return {
            "type": "memory",
            "healthy": True,
            "message": "In-memory storage active",
        }

    # Check Redis connectivity if configured
    try:
        import redis

        # Parse Redis URL and test connection
        client = redis.from_url(settings.redis_url, socket_timeout=2)
        client.ping()
        return {
            "type": "redis",
            "healthy": True,
            "message": "Redis connection successful",
        }
    except ImportError:
        return {
            "type": "redis",
            "healthy": False,
            "message": "Redis client not installed",
        }
    except Exception as e:
        logger.warning("Redis health check failed: %s", str(e))
        return {
            "type": "redis",
            "healthy": False,
            "message": f"Redis connection failed: {str(e)}",
        }


# Health check endpoints
@app.get("/health")
def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/health")
def api_health_check():
    """
    Enhanced health check endpoint with detailed status information.
    
    Returns system health including database connectivity, rate limiting status,
    storage backend health, dependencies, and version info.
    """
    from backend.core.utils.database_helpers import check_database_health
    from backend.providers.aws.common.services.credential_manager import CredentialManager
    from datetime import datetime
    
    # Initialize health status
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.0.0",
        "environment": {
            "dev_mode": getattr(settings, 'DEV_MODE', False),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "services": {}
    }
    
    # Check database health
    try:
        db_health = check_database_health()
        health_status["services"]["database"] = {
            "status": db_health["status"],
            "type": db_health["database_type"],
            "connected": db_health["connected"],
            "table_count": db_health["table_count"],
            "last_error": db_health.get("last_error")
        }
        
        if db_health["status"] != "healthy":
            health_status["status"] = "degraded"
            
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status["services"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "unhealthy"
    
    # Check AWS credential manager (if available)
    try:
        credential_manager = CredentialManager.get_instance()
        # Basic availability check - don't validate actual credentials in health check
        health_status["services"]["aws_credential_manager"] = {
            "status": "healthy",
            "available": True
        }
    except Exception as e:
        logger.warning(f"AWS credential manager check failed: {e}")
        health_status["services"]["aws_credential_manager"] = {
            "status": "degraded",
            "available": False,
            "error": str(e)
        }
    
    # Check file system access (data directory)
    try:
        data_dir = Path("./data")
        data_dir.mkdir(exist_ok=True)
        test_file = data_dir / ".health_check"
        test_file.write_text("ok")
        test_file.unlink()  # Clean up test file
        
        health_status["services"]["filesystem"] = {
            "status": "healthy",
            "data_directory_writable": True
        }
    except Exception as e:
        logger.error(f"Filesystem health check failed: {e}")
        health_status["services"]["filesystem"] = {
            "status": "unhealthy",
            "data_directory_writable": False,
            "error": str(e)
        }
        health_status["status"] = "unhealthy"
    
    # Check rate limiting storage backend health
    storage_health = _check_storage_health()
    rate_limit_enabled = hasattr(app.state, "limiter") and app.state.limiter is not None
    rate_limit_status = "enabled" if rate_limit_enabled else "disabled"
    
    if rate_limit_enabled and not storage_health["healthy"]:
        rate_limit_status = "degraded"
        health_status["status"] = "degraded"
    
    health_status["services"]["rate_limiting"] = {
        "status": rate_limit_status,
        "storage": storage_health,
        "configuration": {
            "auth_endpoints": settings.rate_limit_auth_endpoints,
            "execution_endpoints": settings.rate_limit_execution_endpoints,
            "read_endpoints": settings.rate_limit_read_endpoints,
        },
        "endpoints_protected": {
            "auth": [
                "/api/auth/aws-credentials",
            ],
            "execution": [
                "/api/tools/{tool_id}/execute",
            ],
            "read": [
                "/api/tools/",
                "/api/tools/{tool_id}",
            ],
        },
    }
    
    # Set HTTP status code based on health
    from fastapi import Response
    if health_status["status"] == "healthy":
        Response.status_code = 200
    elif health_status["status"] == "degraded":
        Response.status_code = 200  # Still operational
    else:
        Response.status_code = 503  # Service unavailable
    
    return health_status


# Providers endpoint
@app.get("/api/providers")
def list_providers():
    """List all available providers and tools"""
    return {"providers": provider_info}