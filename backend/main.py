"""
CloudOpsTools FastAPI Application

Main entry point for the CloudOpsTools application.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from backend.core.config import settings

# Configure logger with CloudOpsTools namespace
logger = logging.getLogger("cloudopstools.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


# Create FastAPI application with CloudOpsTools branding
app = FastAPI(
    title=settings.APP_NAME,
    description="CloudOpsTools - Cloud Operations Management Tools",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add session middleware with CloudOpsTools session cookie
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="cloudopstools-session",
    max_age=1800,  # 30 minutes
    same_site="lax",
    https_only=False,
)


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.VERSION,
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.VERSION,
        "docs": "/docs",
    }
