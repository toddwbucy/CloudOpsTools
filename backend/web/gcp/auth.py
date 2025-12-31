"""Google Cloud authentication web routes"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from backend.core.templates import templates

router = APIRouter()


@router.get("/gcp")
async def gcp_preview(request: Request) -> HTMLResponse:
    """Google Cloud preview page"""
    return templates.TemplateResponse("gcp/auth.html", {"request": request})
