#!/usr/bin/env python3
"""Run the PCM-Ops Tools application"""
import uvicorn

from backend.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
