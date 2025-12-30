# Linux Provider

This directory contains tools and services for interacting with Linux systems.

## Structure

```tree
linux/
└── disk_checker/      # Disk Checker tool
    ├── api/           # API endpoints (to be implemented)
    ├── db/            # Database operations
    │   └── seeds/     # Database seed scripts
    ├── schemas/       # Data models
    └── scripts/       # Linux shell scripts
        └── disk_checker.sh  # Disk information gathering script
```

## Tools

### Disk Checker

The Disk Checker tool provides comprehensive disk information gathering capabilities for Linux systems. It collects:

- Block device information
- UUIDs
- Disk space usage
- LVM configuration

The tool can output in both JSON and text formats, making it suitable for both human reading and automated processing.
