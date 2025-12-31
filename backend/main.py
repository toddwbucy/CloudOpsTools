"""CloudOpsTools Backend Application.

This module initializes the FastAPI application and registers all workflow routers
using the provider abstraction layer. Workflows are provider-agnostic and support
multiple cloud providers through a unified interface.

Example usage:
    # Start the server
    poetry run uvicorn backend.main:app --reload --host 0.0.0.0 --port 8500

    # Access API documentation
    http://localhost:8500/docs
    http://localhost:8500/redoc
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware

from backend.core.config import settings
from backend.core.limiter import limiter
from backend.web.workflows import auth, linux_qc_patching_prep, linux_qc_patching_post, sft_fixer

# Configure logger with CloudOpsTools namespace
logger = logging.getLogger("cloudopstools.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")

# =============================================================================
# Application Setup
# =============================================================================

app = FastAPI(
    title=f"{settings.APP_NAME} API",
    description="Provider-agnostic cloud operations tools for managing instances, "
    "executing scripts, and running QC workflows across AWS, Azure, and GCP.",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# =============================================================================
# Rate Limiting Setup
# =============================================================================

# Attach limiter to app.state for access in route decorators
app.state.limiter = limiter

# Add global exception handler for rate limit exceeded errors
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

logger.info(
    "Rate limiting initialized with configuration: auth=%s, execution=%s, read=%s",
    settings.rate_limit_auth_endpoints,
    settings.rate_limit_execution_endpoints,
    settings.rate_limit_read_endpoints,
)

# =============================================================================
# Middleware Configuration
# =============================================================================

# Session middleware for credential storage
# Use HTTPS-only cookies in production for security
is_production = settings.ENVIRONMENT.lower() == "production"
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="cloudopstools_session",
    max_age=settings.SESSION_LIFETIME_MINUTES * 60,
    same_site="strict" if is_production else "lax",
    https_only=is_production,
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Router Registration
# =============================================================================

# Authentication router - handles provider authentication and session management
app.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

# Linux QC Patching Prep router - pre-patching validation workflows
app.include_router(
    linux_qc_patching_prep.router,
    prefix="/linux-qc-prep",
    tags=["Linux QC Prep"],
)

# Linux QC Patching Post router - post-patching validation workflows
app.include_router(
    linux_qc_patching_post.router,
    prefix="/linux-qc-post",
    tags=["Linux QC Post"],
)

# SFT Fixer router - system fix tool and remediation workflows
app.include_router(
    sft_fixer.router,
    prefix="/sft-fixer",
    tags=["SFT Fixer"],
)

# Rate Limiting API routers - demonstration endpoints for rate limiting
from backend.api.auth import router as api_auth_router
from backend.api.tools import router as api_tools_router

app.include_router(api_auth_router, prefix="/api", tags=["Rate Limited API"])
app.include_router(api_tools_router, prefix="/api", tags=["Rate Limited API"])


# =============================================================================
# Root Endpoints
# =============================================================================


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint returning API information.

    Returns:
        Dictionary with API name, version, and documentation links.
    """
    return {
        "name": "CloudOpsTools API",
        "version": settings.VERSION,
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring and load balancers.

    Returns:
        Dictionary with health status.
    """
    return {
        "status": "healthy",
        "default_provider": settings.DEFAULT_PROVIDER,
    }
