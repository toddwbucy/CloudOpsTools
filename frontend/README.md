# Frontend Directory

## Purpose

This directory is reserved for the future development of a modern, Single Page Application (SPA) frontend (e.g., React, Vue, or Svelte).

## Current State

The current web interface is served directly by the FastAPI backend using **Jinja2 templates** and **HTMX**. You can find the existing frontend code in:

- Templates: `backend/templates/`
- Static Assets: `backend/static/`
- Web Routes: `backend/web/`

## Future Plans

When the project migrates to a decoupled frontend architecture:
1.  This directory will contain the source code for the frontend application.
2.  It will have its own build process (e.g., Vite, Webpack).
3.  The backend will serve primarily as a JSON API.
