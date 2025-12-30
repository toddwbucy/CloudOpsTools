# AWS Provider

This directory contains tools and services for interacting with AWS cloud resources.

## Structure

```tree
aws/
├── common/            # Shared AWS utilities
│   └── services/      # Common AWS service implementations
│       ├── account_manager.py  # AWS account management
│       └── credential_manager.py  # AWS credential management
└── script_runner/     # AWS Script Runner tool
    ├── api/           # API endpoints
    ├── schemas/       # Data models
    ├── services/      # Service implementations
    └── utils/         # Utility functions
```

## Common Utilities

The `common` directory contains shared AWS utilities that can be used across multiple AWS tools:

- **credential_manager.py**: Manages AWS credentials, including validation, storage, and refresh
- **account_manager.py**: Handles AWS account information and operations

## Tools

### AWS Script Runner

The AWS Script Runner tool allows execution of scripts across multiple AWS accounts and regions. It includes features for:

- Automatic credential validation and refresh
- Organization structure traversal
- EC2 instance management
- SSM command execution
- Resilient execution handling with pausing/resuming when credentials expire

#### Endpoints

- `/tools/aws/script-runner/accounts` - AWS account management
- `/tools/aws/script-runner/executions` - Script execution handling
- `/tools/aws/script-runner/org` - AWS Organization operations
- `/tools/aws/script-runner/operations` - Long-running AWS operations
