# Specification: Complete Repository Rebranding to CloudOpsTools

## Overview

This task performs a comprehensive rebranding of the entire CloudOpsTools repository, removing all references to Rackspace, TxDIR, and PCM-Ops and replacing them with generic CloudOpsTools branding. The rebranding affects 55+ files across user-facing elements, configuration files, documentation, scripts, and infrastructure. This includes critical infrastructure changes such as session cookie names, database file paths, S3 bucket URLs, and localStorage keys that will impact existing users and deployments.

## Workflow Type

**Type**: feature

**Rationale**: This is a feature workflow because it involves systematic changes across the entire codebase to implement a new branding identity. While it doesn't add new functionality, it requires careful coordination of changes across multiple file types (Python, JavaScript, HTML, CSS, markdown, shell scripts) and infrastructure components (database, S3, session management). The scope is large enough to warrant a structured feature implementation approach with proper testing and rollback planning.

## Task Scope

### Services Involved
- **main** (primary) - Python/FastAPI backend application requiring configuration updates, session middleware changes, and code modifications

### This Task Will:
- [ ] Remove/replace 7 logo image files (4 Rackspace + 3 DIR logos)
- [ ] Update HTML templates (header, footer, partnership badges)
- [ ] Update CSS theme files with new color schemes and class names
- [ ] Update browser tab titles and meta tags
- [ ] Update pyproject.toml with new project name, description, and authors
- [ ] Update backend/core/config.py (APP_NAME constant, database URL)
- [ ] Update backend/main.py (API title, session cookie name from `pcm-ops-session` to `cloudopstools-session`)
- [ ] Update JavaScript theme switcher localStorage key from `pcm-ops-theme` to `cloudopstools-theme`
- [ ] Update S3 bucket URL reference in backend/web/aws/linux_qc_patching_prep.py
- [ ] Update database file name from `pcm_ops_tools.db` to `cloudopstools.db`
- [ ] Update 17 documentation files (README.md, CLAUDE.md, architecture docs, ADRs)
- [ ] Update 29 scripts and infrastructure files (shell scripts, Dockerfile, tests, monitoring)
- [ ] Create migration guide for existing installations

### Out of Scope:
- Actual AWS S3 bucket creation and data migration (requires AWS admin access - coordinate externally)
- Automated database migration scripts (manual rename process documented in migration guide)
- Backwards compatibility layer for old session cookies (users will be logged out)
- Data migration for existing user sessions and localStorage (acceptable loss)

## Service Context

### main

**Tech Stack:**
- Language: Python
- Framework: FastAPI
- ORM: SQLAlchemy
- Package Manager: Poetry
- Key directories: tests/, backend/

**Entry Point:** `backend/main.py`

**How to Run:**
```bash
poetry install
poetry run uvicorn backend.main:app --reload --port 8500
```

**Port:** 8500

**Database:** SQLite at `./data/pcm_ops_tools.db` (will be renamed to `cloudopstools.db`)

**API Documentation:** Available at http://localhost:8500/docs (OpenAPI/Swagger)

## Files to Modify

| File | Service | What to Change |
|------|---------|---------------|
| `pyproject.toml` | main | Update project name, description, authors, package name |
| `backend/core/config.py` | main | Update APP_NAME constant, DATABASE_URL, SQLITE_DATABASE_URI |
| Python modules (6 files) | main | Update logger names from `pcm_ops_tools.*` to `cloudopstools.*` pattern |
| `backend/main.py` | main | Update API title, session cookie name (lines 50-56) |
| `backend/static/js/theme-switcher.js` | main | Update localStorage key from `pcm-ops-theme` to `cloudopstools-theme` (lines 22, 31) |
| `backend/web/aws/linux_qc_patching_prep.py` | main | Update S3 bucket URL from `pcm-ops-tools.s3.us-gov-west-1.amazonaws.com` |
| `.env` | main | Update DATABASE_URL environment variable |
| `.env.example` | main | Update DATABASE_URL example value |
| `README.md` | main | Remove Rackspace/TxDIR/PCM-Ops references, update project description |
| `CLAUDE.md` | main | Update project name and context |
| `Dockerfile` | main | Update any labels, comments, or environment variables |
| HTML templates in `backend/templates/` | main | Update header, footer, partnership badges, page titles |
| CSS files in `backend/static/css/` | main | Update class names, color schemes, branding references |
| Logo files in `backend/static/images/` | main | Remove/replace Rackspace and DIR logo files |
| Shell scripts (29 files) | main | Update comments, output messages, configuration references |
| Documentation files (17 files) | main | Update all Rackspace/TxDIR/PCM-Ops references |

## Files to Reference

These files show patterns to follow:

| File | Pattern to Copy |
|------|----------------|
| `backend/main.py` | Session middleware configuration pattern (lines 50-56) |
| `backend/core/config.py` | Configuration constant pattern (APP_NAME, database URLs) |
| `backend/static/js/theme-switcher.js` | localStorage key usage pattern (lines 22, 31) |

## Patterns to Follow

### Session Middleware Configuration

From `backend/main.py` (lines 50-56):

```python
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="cloudopstools-session",  # Changed from pcm-ops-session
    max_age=1800,  # 30 minutes
    same_site="lax",
    https_only=False,
)
```

**Key Points:**
- Update the `session_cookie` parameter only
- Preserve all other middleware configuration
- This will invalidate all existing user sessions (acceptable impact)

### Configuration Constants

From `backend/core/config.py`:

```python
APP_NAME = "CloudOpsTools"  # Changed from PCM-Ops Tools
DATABASE_URL = "sqlite:///./data/cloudopstools.db"  # Changed from pcm_ops_tools.db
SQLITE_DATABASE_URI = "sqlite:///./data/cloudopstools.db"  # Changed from pcm_ops_tools.db
```

**Key Points:**
- Update APP_NAME to use consistent casing
- Update all database path references
- Maintain existing configuration structure

### LocalStorage Key Pattern

From `backend/static/js/theme-switcher.js` (lines 22, 31):

```javascript
const savedTheme = localStorage.getItem('cloudopstools-theme');  // Changed from pcm-ops-theme
localStorage.setItem('cloudopstools-theme', theme);  // Changed from pcm-ops-theme
```

**Key Points:**
- Update localStorage key consistently across all get/set operations
- User theme preferences will be reset (acceptable impact)

### Logger Name Pattern

From `backend/main.py` (line 36) and other Python modules:

```python
logger = logging.getLogger("cloudopstools.main")  # Changed from pcm_ops_tools.main
```

**Key Points:**
- Update logger names in all Python modules following the pattern `pcm_ops_tools.*` to `cloudopstools.*`
- Affects 6 files: backend/main.py, backend/core/utils/credential_helpers.py, backend/core/utils/logging_config.py, backend/db/init_db.py, backend/db/seeds/tool_disk_checker.py, backend/providers/aws/script_runner/api/executions_modular/tasks.py
- This is an internal logging identifier change with no functional impact
- Maintains consistency with overall rebranding effort

## Requirements

### Functional Requirements

1. **User-Facing Branding Update**
   - Description: Remove all visible Rackspace, TxDIR, and PCM-Ops branding from HTML templates, CSS, and images
   - Acceptance: No Rackspace/TxDIR logos visible, page titles show "CloudOpsTools", header/footer updated

2. **Configuration Consistency**
   - Description: Update all configuration files (pyproject.toml, config.py, main.py, .env) with new branding
   - Acceptance: APP_NAME is "CloudOpsTools", session cookie is "cloudopstools-session", database path uses "cloudopstools.db"

3. **Code Reference Updates**
   - Description: Update all code references including localStorage keys, S3 bucket URLs, and inline comments
   - Acceptance: Theme switcher uses "cloudopstools-theme" key, S3 URL updated in linux_qc_patching_prep.py

4. **Documentation Completeness**
   - Description: Update all 17 documentation files to remove old branding references
   - Acceptance: No mentions of Rackspace/TxDIR/PCM-Ops in README.md, CLAUDE.md, architecture docs, or ADRs

5. **Infrastructure Updates**
   - Description: Update 29 script and infrastructure files including shell scripts, Dockerfile, tests, monitoring
   - Acceptance: All scripts and infrastructure files reflect CloudOpsTools branding

6. **Migration Documentation**
   - Description: Create comprehensive migration guide for existing installations
   - Acceptance: Migration guide covers session invalidation, database rename, S3 bucket migration, and rollback procedures

### Edge Cases

1. **Active User Sessions** - All users will be logged out when session cookie name changes. This is acceptable; document in migration guide.

2. **Existing Database File** - Must preserve data during rename. Migration guide must include backup instructions and manual rename steps.

3. **S3 Bucket External Dependency** - Actual S3 bucket migration requires AWS admin access. Document that code changes are included but bucket creation/migration is external coordination.

4. **LocalStorage Theme Reset** - Users will lose their theme preference. This is acceptable; they will default to system theme.

5. **Rollback Scenario** - If issues arise post-deployment, rolling back code is straightforward, but database file will need manual rename back. Document rollback procedure.

6. **Case Sensitivity** - Ensure consistent casing across all changes (CloudOpsTools vs cloudopstools vs CLOUDOPSTOOLS). Use CloudOpsTools for display, cloudopstools for identifiers.

## Implementation Notes

### DO
- Follow the exact pattern in `backend/main.py` lines 50-56 for SessionMiddleware configuration
- Use consistent casing: "CloudOpsTools" for user-facing names, "cloudopstools" for file paths and identifiers
- Update ALL instances of each pattern (session cookie, localStorage key, database path, logger names) to avoid inconsistencies
- Update logger names in all 6 Python files that use `logging.getLogger("pcm_ops_tools.*")`
- Ensure SQLITE_DATABASE_URI includes the "sqlite:///" prefix for consistency with DATABASE_URL
- Create thorough migration guide covering all breaking changes
- Test theme switcher functionality after localStorage key change
- Verify all API routes still work after configuration changes
- Check that health endpoints (/api/health, /feature-flags/health) remain functional

### DON'T
- Don't rename the actual database file or S3 bucket in code changes (document manual procedures)
- Don't attempt to maintain backwards compatibility for session cookies (clean break is simpler)
- Don't modify SQLAlchemy model definitions unless they contain hardcoded branding strings
- Don't change functional logic - this is purely a branding update
- Don't skip updating any of the 55+ identified files
- Don't forget to update .env.example in addition to .env

## Development Environment

### Start Services

```bash
# Install dependencies
poetry install

# Start the FastAPI application
poetry run uvicorn backend.main:app --reload --port 8500
```

### Service URLs
- Main Application: http://localhost:8500
- API Documentation: http://localhost:8500/docs
- ReDoc Documentation: http://localhost:8500/redoc
- Health Check: http://localhost:8500/api/health

### Required Environment Variables

Update `.env` file with new database path:

```bash
DATABASE_URL=sqlite:///./data/cloudopstools.db
SECRET_KEY=your-secret-key
```

### Manual Infrastructure Changes

**Database Rename (requires downtime):**
```bash
# 1. Stop the application
# 2. Backup the database
cp ./data/pcm_ops_tools.db ./data/pcm_ops_tools.db.backup

# 3. Rename the database file
mv ./data/pcm_ops_tools.db ./data/cloudopstools.db

# 4. Update .env file with new DATABASE_URL
# 5. Restart the application
```

**S3 Bucket Migration (external coordination):**
- Requires AWS admin to create new bucket in us-gov-west-1 region
- Copy objects from old bucket to new bucket
- Update IAM policies and permissions
- Keep old bucket for rollback period
- Only 1 code reference in `backend/web/aws/linux_qc_patching_prep.py`

## Success Criteria

The task is complete when:

1. [ ] All 7 logo files removed/replaced (4 Rackspace + 3 DIR)
2. [ ] HTML templates updated (no Rackspace/TxDIR branding visible)
3. [ ] CSS files updated (class names and color schemes)
4. [ ] Browser tab titles and meta tags show "CloudOpsTools"
5. [ ] pyproject.toml updated (name, description, authors)
6. [ ] backend/core/config.py updated (APP_NAME, DATABASE_URL, SQLITE_DATABASE_URI with correct prefix)
7. [ ] backend/main.py updated (API title, session cookie name, logger name)
8. [ ] theme-switcher.js updated (localStorage key)
9. [ ] S3 bucket URL updated in linux_qc_patching_prep.py
10. [ ] All 17 documentation files updated
11. [ ] All 29 script/infrastructure files updated
12. [ ] Logger names updated in all 6 Python files (pcm_ops_tools.* → cloudopstools.*)
13. [ ] Migration guide created and complete
14. [ ] No console errors when accessing http://localhost:8500
15. [ ] Existing tests still pass (poetry run pytest)
16. [ ] New functionality verified via browser (theme switcher works, pages load correctly)
17. [ ] Health check endpoints return 200 OK
18. [ ] API documentation accessible at /docs

## QA Acceptance Criteria

**CRITICAL**: These criteria must be verified by the QA Agent before sign-off.

### Unit Tests
| Test | File | What to Verify |
|------|------|----------------|
| Configuration tests | `tests/test_config.py` | APP_NAME constant is "CloudOpsTools", DATABASE_URL and SQLITE_DATABASE_URI both contain "cloudopstools.db" with "sqlite:///" prefix |
| API tests | `tests/test_api.py` | All API endpoints still functional after branding changes |
| Theme tests | `tests/test_theme.js` (if exists) | LocalStorage key updated to "cloudopstools-theme" |

### Integration Tests
| Test | Services | What to Verify |
|------|----------|----------------|
| Session middleware | main | Session cookie name is "cloudopstools-session", sessions work correctly |
| Database connectivity | main | Application connects to renamed database file successfully |
| Static file serving | main | CSS, JS, and image files load correctly with new paths |

### End-to-End Tests
| Flow | Steps | Expected Outcome |
|------|-------|------------------|
| Home page load | 1. Navigate to http://localhost:8500/ 2. Check page title 3. Verify header/footer | Page title is "CloudOpsTools", no Rackspace/TxDIR logos visible |
| Theme switching | 1. Click theme toggle 2. Check localStorage 3. Refresh page | Theme persists using "cloudopstools-theme" key |
| API documentation | 1. Navigate to /docs 2. Check page title | Shows "CloudOpsTools API" or similar updated title |
| Health check | 1. Call /api/health 2. Call /feature-flags/health | Both return 200 OK with valid JSON |

### Browser Verification (Frontend)
| Page/Component | URL | Checks |
|----------------|-----|--------|
| Home page | `http://localhost:8500/` | No Rackspace/TxDIR logos, correct page title, header/footer updated |
| AWS tools page | `http://localhost:8500/aws` | Branding consistent across all tool pages |
| Cloud service uptime | `http://localhost:8500/cloud-service-uptime` | Page loads without errors, branding consistent |
| Theme switcher | All pages | Theme toggle works, persists across page loads |

### Database Verification
| Check | Query/Command | Expected |
|-------|---------------|----------|
| Database file exists | `ls -la ./data/cloudopstools.db` | File exists with recent modification time |
| Database connectivity | Start application and check logs | No database connection errors |
| Data preservation | Query existing tables (if any data exists) | All existing data preserved after rename |

### Configuration Verification
| Check | File | Expected |
|-------|------|----------|
| APP_NAME | `backend/core/config.py` | Value is "CloudOpsTools" |
| Database URL | `backend/core/config.py` | DATABASE_URL is "sqlite:///./data/cloudopstools.db" |
| SQLITE_DATABASE_URI | `backend/core/config.py` | Value is "sqlite:///./data/cloudopstools.db" (with prefix) |
| Session cookie | `backend/main.py` | SessionMiddleware uses "cloudopstools-session" |
| LocalStorage key | `backend/static/js/theme-switcher.js` | Uses "cloudopstools-theme" |
| Logger names | 6 Python files | Use "cloudopstools.*" pattern (not "pcm_ops_tools.*") |
| S3 bucket URL | `backend/web/aws/linux_qc_patching_prep.py` | Updated to new bucket URL |

### Documentation Verification
| Check | Files | Expected |
|-------|-------|----------|
| README.md | `README.md` | No mentions of Rackspace, TxDIR, or PCM-Ops |
| Architecture docs | `docs/architecture/*.md` | All branding references updated |
| ADRs | `docs/adr/*.md` | Historical references acceptable, but current references updated |
| Migration guide | `MIGRATION.md` or in docs/ | Complete guide covering all breaking changes |

### QA Sign-off Requirements
- [ ] All unit tests pass (pytest runs clean)
- [ ] All integration tests pass
- [ ] All E2E tests pass
- [ ] Browser verification complete (theme works, pages load, no errors)
- [ ] Database state verified (file renamed, connection works, data preserved if applicable)
- [ ] No regressions in existing functionality (all API routes work)
- [ ] Code follows established patterns (consistent casing, proper configuration)
- [ ] No security vulnerabilities introduced (session management unchanged except cookie name)
- [ ] Migration guide is complete and accurate
- [ ] All 55+ identified files have been updated
- [ ] No console errors in browser DevTools
- [ ] Health check endpoints return 200 OK
- [ ] API documentation loads correctly at /docs
