"""Home page and general web routes"""

from datetime import datetime

from fastapi import APIRouter, Request

from backend.core.templates import templates

router = APIRouter()


@router.get("/")
async def index(request: Request):
    """Landing page"""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/cloud-service-uptime")
async def cloud_service_uptime(request: Request):
    """Cloud service uptime page"""
    return templates.TemplateResponse("cloud_service_uptime.html", {"request": request})


@router.get("/api/service-status")
async def service_status(request: Request):
    """Service status endpoint for HTMX"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return templates.TemplateResponse(
        "partials/service_status.html",
        {"request": request, "current_time": current_time},
    )


@router.get("/api/backend-status")
async def backend_status(request: Request):
    """Backend connection status for navbar"""
    # Since we're now integrated, backend is always "connected"
    return templates.TemplateResponse(
        "partials/backend_status.html", {"request": request}
    )


# Future provider preview pages
@router.get("/azure")
async def azure_preview(request: Request):
    """Azure preview page"""
    return templates.TemplateResponse("azure/auth.html", {"request": request})


@router.get("/gcp")
async def gcp_preview(request: Request):
    """Google Cloud preview page"""
    return templates.TemplateResponse("gcp/auth.html", {"request": request})


@router.get("/servicenow")
async def servicenow_preview(request: Request):
    """ServiceNow preview page"""
    return templates.TemplateResponse("servicenow/auth.html", {"request": request})
