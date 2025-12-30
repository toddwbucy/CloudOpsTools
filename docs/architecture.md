# PCM-Ops Tools Architecture

## Overview

PCM-Ops Tools is a unified multi-cloud operations platform built with FastAPI. It follows a modular, provider-based architecture designed for scalability, security, and maintainability.

## High-Level Architecture

```mermaid
graph TD
    User[User] -->|HTTPS| LB[Load Balancer]
    LB -->|Port 8500| App[FastAPI Application]
    
    subgraph "Backend (FastAPI)"
        App --> Middleware[Middleware Layer]
        Middleware --> Router[Router / Dispatcher]
        
        Router --> WebRoutes[Web Routes]
        Router --> APIRoutes[API Routes]
        
        WebRoutes --> Templates[Jinja2 Templates]
        APIRoutes --> Services[Business Logic Services]
        
        Services --> CredentialManager[Credential Manager]
        Services --> AsyncAWS[Async AWS Client (aiobotocore)]
        Services --> DB[(SQLite Database)]
    end
    
    AsyncAWS -->|Async API Calls| AWS[AWS Cloud]
```

## Core Components

### 1. Unified FastAPI Application
The application (`backend/main.py`) serves as the single entry point. It handles:
- **Middleware**: Session management, CORS, Security Headers, CSRF protection.
- **Routing**: Dynamic discovery and registration of provider modules.
- **Static Files**: Serving CSS/JS assets.
- **Templates**: Rendering server-side UI with Jinja2.

### 2. Provider-Based Modularity
The codebase is organized by cloud provider (`backend/providers/`), allowing for independent development and maintenance of tools.

Structure:
```
backend/providers/
└── aws/
    ├── common/           # Shared utilities (credentials, account management)
    └── script_runner/    # Specific tool module
        ├── api/          # FastAPI route handlers
        ├── services/     # Business logic
        ├── schemas/      # Pydantic models
        └── templates/    # Tool-specific UI templates
```

### 3. Asynchronous AWS Operations
To ensure high performance and non-blocking behavior, all AWS interactions are asynchronous.

- **Library**: `aiobotocore` is used for async AWS API calls.
- **Pattern**:
    - **CredentialManager**: Manages sessions and credentials.
    - **Service Layer**: Uses `async with session.create_client(...)` for resource management.
    - **API Layer**: `async def` endpoints `await` service methods.

### 4. Security Architecture
Security is built-in via a layered approach:
- **Transport**: HTTPS required (enforced by load balancer/proxy).
- **Session**: Server-side, encrypted session storage.
- **Authentication**: AWS credential validation (IAM/Keys).
- **Protection**: CSRF tokens for state-changing requests, strict Content Security Policy (CSP).

## Data Flow

### Request Lifecycle (AWS Operation)
1.  **User Request**: User initiates an action (e.g., "List Instances") via Web UI or API.
2.  **Middleware**: Validates session and CSRF token.
3.  **Route Handler**: `backend/providers/aws/script_runner/api/instances.py` receives the request.
4.  **Service Call**: Handler calls `EC2Manager.describe_instances()`.
5.  **Async AWS Call**: `EC2Manager` uses `aiobotocore` to call AWS EC2 API asynchronously.
6.  **Response**: AWS responds, data is processed, and returned to the user (JSON or HTML).

## Frontend Strategy
- **Current**: Server-side rendering with Jinja2 + HTMX for dynamic interactions.
- **Future**: Potential migration to a dedicated frontend framework (React/Vue) served from the `frontend/` directory. Currently, `frontend/` is reserved for this future development.
