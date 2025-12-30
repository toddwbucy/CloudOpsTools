# Providers

This directory contains provider-specific tools and services. Each provider is organized into its own directory with a consistent structure.

## Available Providers

- **AWS**: Amazon Web Services cloud provider tools
- **Linux**: Tools for Linux systems management
- **Azure**: (Planned) Microsoft Azure cloud provider tools
- **GCP**: (Planned) Google Cloud Platform tools
- **ServiceNow**: (Planned) ServiceNow CMDB integration

## Provider Structure

Each provider follows a similar structure:

```tree
provider_name/
├── common/            # Shared utilities for this provider
│   └── services/      # Common service implementations
├── tool_name/         # Individual tool directory
│   ├── api/           # API endpoints
│   ├── db/            # Database operations
│   │   └── seeds/     # Database seed scripts
│   ├── docs/          # Documentation
│   ├── schemas/       # Data models
│   ├── services/      # Service implementations
│   └── utils/         # Utility functions
└── README.md          # Provider documentation
```

## Provider Discovery

Providers and their tools are automatically discovered and registered with the FastAPI application using the following mechanism:

1. Each provider has an `__init__.py` file that dynamically imports all tools within it
2. Each tool has an `__init__.py` file that exposes `routers` listing available API endpoints
3. The main application automatically registers all endpoints with appropriate prefixes
4. The `/api/providers` endpoint lists all available providers and tools
