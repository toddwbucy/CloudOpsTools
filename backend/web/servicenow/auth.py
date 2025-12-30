"""ServiceNow authentication web routes"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from backend.core.templates import templates

router = APIRouter()


@router.get("/servicenow")
async def servicenow_preview(request: Request) -> HTMLResponse:
    """ServiceNow preview page"""
    return templates.TemplateResponse("servicenow/auth.html", {"request": request})
