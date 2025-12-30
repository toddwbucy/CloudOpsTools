# ADR: Infrastructure Compatibility and Multi-OS Support Improvements

**Status**: Accepted  
**Date**: 2025-08-27  
**Deciders**: Development Team

## Context

The PCM-Ops Tools platform faced several infrastructure and compatibility challenges that hindered deployment and operation across different environments:

1. **Python Version Mismatch**: The setup script installed Python 3.12 while documentation stated Python 3.11+ requirement and the actual codebase worked with Python 3.11
2. **Limited OS Support**: Setup script only supported Ubuntu via deadsnakes PPA, failing on Debian-based distributions like BunsenLabs
3. **SQLite Compatibility Issues**: The application uses SQLite JSON operations (`func.json_extract()`) but didn't verify SQLite JSON1 extension support during setup
4. **Complex Setup Instructions**: Final setup output overwhelmed users with technical details rather than focusing on next steps

The application's database layer uses SQLite with JSON queries in critical components like the Linux QC Patching tool:
```python
func.json_extract(Execution.execution_metadata, '$.qc_step') == "step1_initial_qc"
func.cast(func.json_extract(Execution.execution_metadata, '$.change_id'), Integer)
```

These operations require SQLite compiled with JSON1 extension support, which isn't guaranteed across all systems.

## Decision

We implemented a comprehensive infrastructure compatibility improvement strategy:

### 1. Python Version Rationalization
- **Changed setup script** from Python 3.12 to Python 3.11 installation
- **Maintained forward compatibility** by supporting Python 3.11+ as documented
- **Aligned with project requirements** stated in README.md and actual usage patterns

### 2. Multi-OS Support Strategy
- **Ubuntu**: Continue using deadsnakes PPA for Python 3.11 installation
- **Debian/BunsenLabs**: Primary attempt via system repositories, fallback to system Python 3 if 3.11 unavailable
- **Compatibility validation**: Ensure system Python is 3.10+ minimum (for union type syntax support)
- **Enhanced error handling**: Clear feedback for unsupported operating systems

### 3. SQLite JSON Support Assurance
- **Automatic SQLite3 installation** with libsqlite3-dev for development headers
- **JSON functionality verification**: Test SQLite JSON1 extension during setup with actual JSON query
- **Graceful degradation**: Warning if JSON support unavailable rather than hard failure

### 4. User Experience Optimization
- **Simplified completion message** focusing on application startup commands
- **Clear next steps**: Emphasized `./start.sh` command and access URL
- **Removed technical noise**: Eliminated verbose Poetry environment details from user-facing output

## Technical Details

### OS Detection and Validation
```bash
# Detect OS using /etc/os-release
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
fi

# Validate supported OS
if [[ "$OS" != "ubuntu" && "$OS" != "debian" && "$OS" != "bunsenlabs" ]]; then
    echo "Unsupported operating system: $OS"
    exit 1
fi
```

### Python Installation Strategy
- **Ubuntu**: Uses deadsnakes PPA for guaranteed Python 3.11 availability
- **Debian/BunsenLabs**: Attempts system package installation, falls back to system Python 3 with version validation
- **Minimum version check**: Ensures Python 3.10+ for modern syntax compatibility

### SQLite JSON Support Verification
```bash
# Test actual JSON functionality
sqlite3 :memory: "SELECT json_extract('{\"test\": \"value\"}', '$.test');" 2>/dev/null | grep -q "value"
```

This test mirrors the application's actual JSON query patterns and ensures compatibility with code like:
```python
func.json_extract(Execution.execution_metadata, '$.qc_step')
```

## Consequences

### Positive Impacts

1. **Broader Platform Support**: Application now deploys successfully on Ubuntu, Debian, and BunsenLabs systems
2. **Database Reliability**: SQLite JSON operations guaranteed to work through setup-time verification
3. **Reduced Support Burden**: Clear OS support boundaries and better error messages
4. **Improved User Experience**: Streamlined setup completion with actionable next steps
5. **Version Alignment**: Consistent Python version requirements across documentation and implementation

### Trade-offs and Considerations

1. **Complexity Management**: Setup script now handles multiple OS variations and fallback scenarios
2. **Maintenance Overhead**: Need to maintain OS-specific installation paths
3. **Future Compatibility**: Must consider new OS support requests and Python version updates
4. **Dependency on System Packages**: Reliance on distribution-specific package availability

### Monitoring Requirements

1. **Setup Success Rates**: Track installation success across different OS environments
2. **SQLite Compatibility**: Monitor for JSON operation failures in production
3. **Python Version Usage**: Verify actual Python version compatibility in deployments

## Alternatives Considered

### 1. Docker-First Approach
**Rejected** because:
- Adds deployment complexity for users familiar with direct installation
- Doesn't address local development setup needs
- Current user base prefers direct system installation

### 2. Python Version Enforcement (3.12 Only)
**Rejected** because:
- Unnecessarily restrictive given 3.11+ compatibility
- Creates barriers for Debian/BunsenLabs users where 3.12 may not be available
- Documentation already promised 3.11+ support

### 3. SQLite JSON Operation Replacement
**Rejected** because:
- Would require significant database query refactoring
- JSON operations provide valuable functionality for metadata storage
- SQLite JSON support is widely available in modern distributions

### 4. OS Support Limitation (Ubuntu Only)
**Rejected** because:
- Limits adoption in Debian-based environments
- BunsenLabs is specifically requested by user community
- Minimal additional complexity for significant user benefit

## Implementation Notes

### Configuration Changes Required
- **pyproject.toml**: Should be updated to reflect `python = "^3.11"` to align with setup script
- **CI/CD pipelines**: Update to test against Python 3.11 as primary version
- **Documentation**: Already correct, no changes needed

### Rollback Strategy
If issues arise with multi-OS support:
1. Revert setup.sh to Ubuntu-only support
2. Document manual installation steps for other OS
3. Consider containerized deployment for non-Ubuntu systems

### Future Enhancements
1. **Extended OS Support**: CentOS/RHEL, Fedora, Alpine Linux support
2. **Python Version Auto-Detection**: Smart selection of best available Python version
3. **SQLite Version Requirements**: Explicit minimum version enforcement
4. **Setup Validation Suite**: Comprehensive post-installation testing

This ADR documents a significant infrastructure decision that improves platform compatibility, database reliability, and user experience while maintaining the application's core architecture and functionality.