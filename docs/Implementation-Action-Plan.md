# Implementation Action Plan
## CodeRabbit Issues - Detailed Fix Strategy

**Date:** 2025-08-24  
**Total Issues:** 50+  
**Approach:** Risk-based prioritization with working state preservation

---

## Week 1: Critical Security Fixes 🔴

### Day 1-2: SECRET_KEY Fix (HIGHEST PRIORITY)

**Issue:** `backend/core/config.py:57` - Hardcoded SECRET_KEY
```python
# Current (INSECURE)
SECRET_KEY: str = "your-secret-key-here-change-in-production"

# Target (SECURE)
SECRET_KEY: str = os.getenv("SECRET_KEY") or (secrets.token_urlsafe(32) if DEBUG else RuntimeError("SECRET_KEY required"))
```

**Implementation Steps:**
1. Add `import os, secrets` to top of file
2. Update SECRET_KEY line with environment variable
3. Add fallback for dev mode only
4. Update .env.example with generation instructions
5. Test session functionality

**Testing Checklist:**
- [ ] Sessions still work with new key
- [ ] Dev mode generates temporary key
- [ ] Production fails fast without SECRET_KEY
- [ ] All authentication flows preserved

**Rollback Plan:** Keep old hardcoded key as commented fallback

---

### Day 3-4: XSS Prevention (3 locations)

#### XSS Fix 1: `backend/static/js/aws-utilities.js:110-122`
```javascript
// Current (VULNERABLE)
innerHTML = `<div>${instance_id}</div>`;

// Target (SAFE)
const div = document.createElement('div');
div.textContent = instance_id;
container.appendChild(div);
```

#### XSS Fix 2: `backend/static/js/sft-fixer.js:323-324`
```javascript
// Add local escapeHtml function
function escapeHtml(text) {
    if (window.Utils && window.Utils.escapeHtml) {
        return window.Utils.escapeHtml(text);
    }
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}
```

#### XSS Fix 3: `backend/static/js/linux-qc-patching-prep.js:165-180`
```javascript
// Replace innerHTML error display with safe DOM construction
```

**Testing Checklist:**
- [ ] UI renders identically
- [ ] No script injection possible
- [ ] All interactive elements work
- [ ] Feature flag allows rollback

---

### Day 5: CSRF & Credential Security

#### CSRF Protection: `backend/templates/aws/auth.html:391-392`
1. Add CSRF token generation to FastAPI
2. Add token to forms and AJAX requests  
3. Validate tokens in middleware
4. Update all form submissions

#### Credential Security: `backend/web/aws/auth.py:106-115`
1. Move credentials from session to secure server-side store
2. Use session references instead of direct storage
3. Add encryption at rest
4. Implement proper cleanup

**Testing Checklist:**
- [ ] All forms still submit
- [ ] CSRF attacks blocked
- [ ] Credentials flow preserved
- [ ] Sessions remain functional

---

## Week 2: Medium Risk Issues 🟡

### Day 1-3: Threading & Database Safety

#### Thread Safety: `backend/core/utils/session_store.py:30-40`
```python
# Current (UNSAFE)
_tables_initialized: bool = False

# Target (SAFE)
import threading
_tables_initialized = threading.Event()

# In function
if not _tables_initialized.is_set():
    with _tables_init_lock:
        if not _tables_initialized.is_set():
            Base.metadata.create_all(...)
            _tables_initialized.set()
```

#### Database Races: `backend/core/utils/session_store.py:46-57`
```python
# Add proper transaction locking
def set(cls, key: str, value: Any) -> None:
    cls._ensure_table()
    with get_db_sync() as db:
        try:
            # Use FOR UPDATE lock
            row = db.execute(
                select(SessionData)
                .where(SessionData.key == key)
                .with_for_update()
            ).scalar_one_or_none()
            
            if row:
                row.data = value
            else:
                row = SessionData(key=key, data=value)
                db.add(row)
            db.commit()
        except Exception:
            db.rollback()
            raise
```

#### Missing Imports: `backend/db/init_db.py:12-15`
```python
# Add explicit model imports
from backend.db.models import account, change, execution, script, session_store

# Or use importlib for dynamic import
import importlib
model_modules = ['account', 'change', 'execution', 'script', 'session_store']
for module_name in model_modules:
    importlib.import_module(f'backend.db.models.{module_name}')
```

**Load Testing Required:**
- Concurrent session operations
- Multiple database writes
- Thread safety under load

---

### Day 4-5: Error Handling & Memory Leaks

#### Exception Handling: Multiple Files
```python
# backend/providers/aws/script_runner/api/changes.py:184-186
instance = next((i for i in instances if i.instance_id == instance_id), None)
if instance is None:
    logger.error(f"Instance {instance_id} not found in {account_id}")
    raise HTTPException(status_code=404, detail=f"Instance not found: {instance_id}")
```

#### Memory Leaks: `backend/static/js/aws-execution.js:96-159`
```javascript
function stopExecutionPolling() {
    if (executionStatusInterval && typeof executionStatusInterval.stop === 'function') {
        executionStatusInterval.stop();
        executionStatusInterval = null;
    }
}

// Add cleanup on page unload
window.addEventListener('beforeunload', stopExecutionPolling);
```

---

## Week 3: Configuration Issues 🟠

### Day 1-2: Configuration Cleanup

#### CodeRabbit Config: `.coderabbit.yaml`
- Remove unsupported sections (lines 88-99, 114-128, 129-141)
- Fix auto_review structure (lines 24-25)
- Move path_instructions under reviews (line 28)
- Rename exclude_patterns to path_filters under reviews

#### Docker Security: `Dockerfile:10-19`
```dockerfile
# Replace Poetry installer with official image
FROM python:3.12-slim as builder

# Install Poetry via pip (more secure)
RUN pip install poetry==2.1.3
ENV PATH="/root/.local/bin:$PATH"
```

#### Version Alignment: `pyproject.toml`
- Fix python version mismatch (3.11 vs 3.12)
- Fix cryptography version (^45.0.6 doesn't exist)
- Align mypy python_version with project requirement

---

### Day 3-4: Database & Production Config

#### Database Connection: `backend/db/session.py:9-13`
```python
from sqlalchemy.engine import make_url

# Conditional SQLite args
def create_engine_with_args():
    url = make_url(settings.DATABASE_URL)
    connect_args = {}
    
    if url.drivername.startswith('sqlite'):
        connect_args['check_same_thread'] = False
    
    return create_engine(settings.DATABASE_URL, connect_args=connect_args)
```

#### Production Flags: `start.sh:146`
```bash
# Conditional reload flag
if [ "$ENV" = "development" ] || [ "$UVICORN_RELOAD" = "true" ]; then
    RELOAD_FLAG="--reload"
else
    RELOAD_FLAG=""
fi

uvicorn backend.main:app --host "$HOST" --port "$PORT" $RELOAD_FLAG
```

---

## Week 4: Cosmetic Issues 🟢

### Template Fixes (Low Risk)
- Fix HTML entities (`&amp;` for `&`)
- Fix missing table columns
- Update hardcoded text (30min -> 60min TTL)
- Fix link targets and navigation

### String/Casing Fixes
- PowerShell path casing consistency
- AWK command quoting fixes  
- URL and text corrections

### Code Quality
- Import organization
- Type hint improvements
- Docstring updates

---

## Testing Strategy by Week

### Week 1 Testing (Critical Security)
```bash
# After each fix:
1. Manual UI testing
2. Session functionality test  
3. Authentication flow test
4. XSS prevention test
5. CSRF protection test

# Regression testing:
poetry run pytest tests/security/
curl -X POST /api/auth/... # Test endpoints
```

### Week 2 Testing (Medium Risk)
```bash
# Load testing:
locust -f tests/load_test.py --users 50 --spawn-rate 5
python tests/concurrent_sessions.py
python tests/database_race_test.py

# Memory testing:
# Browser dev tools -> Memory tab
# Monitor for leaks during extended usage
```

### Week 3 Testing (Configuration)
```bash
# Build testing:
docker build -t pcm-ops-test .
docker run --rm pcm-ops-test python -c "import backend.main"

# Config validation:
poetry run mypy backend/
poetry run ruff check backend/
```

### Week 4 Testing (Cosmetic)
```bash
# Visual regression:
# Manual UI walkthrough
# Screenshot comparisons
# Accessibility testing
```

---

## Risk Mitigation

### Feature Flags Implementation
```python
# backend/core/config.py
class Settings(BaseSettings):
    # Feature flags for gradual rollout
    ENABLE_NEW_AUTH: bool = False
    ENABLE_XSS_PROTECTION: bool = False
    ENABLE_CSRF_TOKENS: bool = False
    ENABLE_SECURE_SESSIONS: bool = False
```

### Rollback Procedures

**For each critical fix:**
1. Tag current working state
2. Create feature branch
3. Implement fix with feature flag
4. Test thoroughly
5. Deploy with flag OFF
6. Enable flag gradually
7. Monitor for issues
8. Full rollback = disable flag + redeploy

### Monitoring During Rollout

**Week 1 Monitoring:**
- Session creation/validation rates
- Authentication failure rates  
- XSS attempt blocks (if detectable)
- CSRF token validation failures

**Week 2 Monitoring:**
- Database connection pool usage
- Session store performance
- Thread contention metrics
- Memory usage patterns

---

## Success Criteria

### Week 1 (Security)
- [ ] No hardcoded secrets in code
- [ ] All XSS vulnerabilities patched
- [ ] CSRF protection active on all forms
- [ ] Credentials securely stored
- [ ] All existing functionality preserved

### Week 2 (Stability)  
- [ ] No race conditions under load
- [ ] Proper error handling throughout
- [ ] No memory leaks in browser
- [ ] Database operations are atomic
- [ ] System stable with 50 concurrent users

### Week 3 (Configuration)
- [ ] Clean build pipeline
- [ ] Secure container image
- [ ] Proper environment separation
- [ ] All version conflicts resolved

### Week 4 (Polish)
- [ ] UI consistency maintained  
- [ ] No visual regressions
- [ ] Clean code quality metrics
- [ ] Documentation updated

This detailed plan ensures we address every CodeRabbit issue systematically while maintaining the working state of the application.