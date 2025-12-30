"""Azure authentication web routes"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from backend.core.templates import templates

router = APIRouter()


@router.get("/azure")
async def azure_preview(request: Request) -> HTMLResponse:
    """Azure preview page"""
    return templates.TemplateResponse("azure/auth.html", {"request": request})
