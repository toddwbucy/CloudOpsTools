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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from backend.core.config import settings
from backend.web.workflows import auth, linux_qc_patching_prep, linux_qc_patching_post, sft_fixer

# =============================================================================
# Application Setup
# =============================================================================

app = FastAPI(
    title="CloudOpsTools API",
    description="Provider-agnostic cloud operations tools for managing instances, "
    "executing scripts, and running QC workflows across AWS, Azure, and GCP.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# =============================================================================
# Middleware Configuration
# =============================================================================

# Session middleware for credential storage
# In production, use a secure secret key from environment
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY if hasattr(settings, "SESSION_SECRET_KEY") else "dev-secret-key-change-in-production",
    session_cookie="cloudopstools_session",
    max_age=3600,  # 1 hour session lifetime
    same_site="lax",
    https_only=False,  # Set to True in production
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
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
        "version": "1.0.0",
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
