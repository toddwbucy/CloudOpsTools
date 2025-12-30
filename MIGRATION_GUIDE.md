# CloudOpsTools Migration Guide

This guide covers the migration from PCM-Ops Tools to CloudOpsTools, including all breaking changes, migration steps, and rollback procedures.

## Overview

The rebranding from PCM-Ops Tools to CloudOpsTools involves changes to:

- Session cookie names (breaking - users will be logged out)
- Database file paths (breaking - requires manual rename)
- S3 bucket URLs (breaking - requires external coordination)
- LocalStorage keys (breaking - user preferences reset)
- Configuration constants and branding

**Estimated Downtime:** 5-15 minutes for database rename operations

## Pre-Migration Checklist

Before starting the migration, verify:

- [ ] All administrators are notified of the maintenance window
- [ ] Current application is stopped
- [ ] Database backup has been created
- [ ] S3 bucket migration is coordinated with AWS admin (if applicable)
- [ ] Rollback plan is reviewed and understood
- [ ] Access to server/deployment environment is confirmed

---

## Breaking Changes

### 1. Session Cookie Invalidation

**Impact:** All active user sessions will be invalidated

**Details:**
- Old cookie name: `pcm-ops-session`
- New cookie name: `cloudopstools-session`

**User Experience:**
- All currently logged-in users will be logged out
- Users will need to re-authenticate after the migration
- No data loss occurs - only session state is affected

**Action Required:** None - this change is automatic. Communicate to users that they will need to log in again after the migration.

---

### 2. Database Rename

**Impact:** Application will not start if database is not renamed

**Details:**
- Old database path: `./data/pcm_ops_tools.db`
- New database path: `./data/cloudopstools.db`

**Migration Steps:**

```bash
# Step 1: Stop the application
# (Use your deployment method - systemctl, docker, etc.)

# Step 2: Create a backup of the current database
cp ./data/pcm_ops_tools.db ./data/pcm_ops_tools.db.backup.$(date +%Y%m%d_%H%M%S)

# Step 3: Verify the backup was created successfully
ls -la ./data/pcm_ops_tools.db.backup.*

# Step 4: Rename the database file
mv ./data/pcm_ops_tools.db ./data/cloudopstools.db

# Step 5: Verify the rename was successful
ls -la ./data/cloudopstools.db

# Step 6: Update environment variables (if using .env file)
# Change DATABASE_URL from:
#   DATABASE_URL=sqlite:///./data/pcm_ops_tools.db
# To:
#   DATABASE_URL=sqlite:///./data/cloudopstools.db
```

**Verification:**
```bash
# After starting the application, verify database connectivity
curl -s http://localhost:8500/api/health | grep -q '"status":"healthy"' && echo "Database OK" || echo "Database ERROR"
```

---

### 3. S3 Bucket Migration Coordination

**Impact:** File uploads/downloads may fail if bucket is not migrated

**Details:**
- Old bucket URL: `pcm-ops-tools.s3.us-gov-west-1.amazonaws.com`
- New bucket URL: `cloudopstools.s3.us-gov-west-1.amazonaws.com`

**Note:** Code changes reference the new bucket URL. The actual S3 bucket creation and data migration requires AWS administrator access.

**External Coordination Required:**

1. **Create New S3 Bucket**
   - Bucket name: `cloudopstools`
   - Region: `us-gov-west-1`
   - Apply same permissions/policies as old bucket

2. **Migrate Existing Objects**
   ```bash
   # AWS CLI command (requires admin credentials)
   aws s3 sync s3://pcm-ops-tools s3://cloudopstools --region us-gov-west-1
   ```

3. **Update IAM Policies**
   - Update any IAM policies referencing the old bucket name
   - Grant application role access to new bucket

4. **Retention Period**
   - Keep old bucket available for rollback period (recommended: 2 weeks)
   - After successful migration verification, old bucket can be archived/deleted

**If S3 Bucket Migration is Not Possible:**
- The application will still function for non-S3 features
- S3-dependent features will return errors until bucket is migrated
- Document this limitation if S3 migration is delayed

---

### 4. LocalStorage Key Changes

**Impact:** User theme preferences will be reset

**Details:**
- Old localStorage key: `pcm-ops-theme`
- New localStorage key: `cloudopstools-theme`

**User Experience:**
- Users' theme preference (light/dark mode) will reset to system default
- Users will need to re-select their preferred theme
- No other localStorage data is affected

**Action Required:** None - this change is automatic. Users will simply need to re-select their theme preference.

---

## Configuration Changes Summary

| Configuration | Old Value | New Value |
|--------------|-----------|-----------|
| APP_NAME | PCM-Ops Tools | CloudOpsTools |
| Session Cookie | pcm-ops-session | cloudopstools-session |
| Database File | pcm_ops_tools.db | cloudopstools.db |
| localStorage Key | pcm-ops-theme | cloudopstools-theme |
| S3 Bucket | pcm-ops-tools | cloudopstools |

---

## Step-by-Step Migration Procedure

### Phase 1: Preparation (Before Maintenance Window)

```bash
# 1. Pull the latest code with CloudOpsTools branding
git fetch origin
git checkout main
git pull origin main

# 2. Review changes
git log --oneline -10

# 3. Verify dependencies
poetry install

# 4. Run tests to ensure new code is working
poetry run pytest
```

### Phase 2: Migration (During Maintenance Window)

```bash
# 1. Stop the application
# Method depends on deployment (systemctl, docker, kubernetes, etc.)

# 2. Backup the database
cp ./data/pcm_ops_tools.db ./data/pcm_ops_tools.db.backup.$(date +%Y%m%d_%H%M%S)

# 3. Rename the database
mv ./data/pcm_ops_tools.db ./data/cloudopstools.db

# 4. Update .env file (if applicable)
sed -i 's/pcm_ops_tools\.db/cloudopstools.db/g' .env

# 5. Start the application
# Method depends on deployment
poetry run uvicorn backend.main:app --host 0.0.0.0 --port 8500
```

### Phase 3: Verification (After Migration)

```bash
# 1. Check application health
curl -s http://localhost:8500/api/health
# Expected: {"status":"healthy",...}

# 2. Check API documentation loads
curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/docs
# Expected: 200

# 3. Verify session cookie name in browser
# Open DevTools > Application > Cookies
# Should see: cloudopstools-session

# 4. Test theme switcher
# Toggle theme, refresh page, verify theme persists

# 5. Check browser console for errors
# Open DevTools > Console
# Should have no errors related to branding changes
```

---

## Rollback Procedures

### Scenario 1: Quick Rollback (Code Only)

If issues are discovered after deployment but database has not been modified:

```bash
# 1. Stop the application
# 2. Checkout previous version
git checkout <previous-commit-hash>

# 3. Reinstall dependencies
poetry install

# 4. Start the application
poetry run uvicorn backend.main:app --host 0.0.0.0 --port 8500
```

### Scenario 2: Full Rollback (Code + Database)

If database has been renamed and needs to be reverted:

```bash
# 1. Stop the application

# 2. Restore database from backup
mv ./data/cloudopstools.db ./data/cloudopstools.db.failed
cp ./data/pcm_ops_tools.db.backup.* ./data/pcm_ops_tools.db

# 3. Revert .env file
sed -i 's/cloudopstools\.db/pcm_ops_tools.db/g' .env

# 4. Checkout previous code version
git checkout <previous-commit-hash>

# 5. Reinstall dependencies
poetry install

# 6. Start the application
poetry run uvicorn backend.main:app --host 0.0.0.0 --port 8500

# 7. Verify rollback success
curl -s http://localhost:8500/api/health
```

### Scenario 3: S3 Bucket Rollback

If S3 bucket migration causes issues:

1. **Revert Code S3 URL:**
   ```bash
   # In backend/web/aws/linux_qc_patching_prep.py
   # Change bucket URL back to pcm-ops-tools
   ```

2. **Or use environment variable override (if implemented):**
   ```bash
   export S3_BUCKET_NAME=pcm-ops-tools
   ```

3. **Coordinate with AWS admin to pause/revert bucket changes**

### Rollback Verification Checklist

After any rollback, verify:

- [ ] Application starts without errors
- [ ] Health endpoint returns 200 OK
- [ ] API documentation loads at /docs
- [ ] Database queries work (check a sample API endpoint)
- [ ] No console errors in browser
- [ ] Theme switcher works
- [ ] User authentication works

---

## Post-Migration Tasks

### Immediate (Same Day)

- [ ] Communicate to users that login is required
- [ ] Monitor application logs for errors
- [ ] Verify all API endpoints are functional
- [ ] Check error rates in monitoring dashboard

### Short-Term (Within 1 Week)

- [ ] Remove database backup files after confirming stability
- [ ] Update any external documentation or runbooks
- [ ] Update monitoring alerts if they reference old names
- [ ] Archive or delete old S3 bucket (after 2-week retention)

### Long-Term

- [ ] Update CI/CD pipelines if they reference old names
- [ ] Update any external integrations
- [ ] Remove rollback documentation after 30 days of stability

---

## Troubleshooting

### Application Won't Start

**Symptom:** Application fails to start with database error

**Cause:** Database file not renamed or .env not updated

**Solution:**
```bash
# Check if database file exists
ls -la ./data/cloudopstools.db

# If not, rename it
mv ./data/pcm_ops_tools.db ./data/cloudopstools.db

# Check .env file
grep DATABASE_URL .env
# Should show: DATABASE_URL=sqlite:///./data/cloudopstools.db
```

### Session Not Persisting

**Symptom:** Users are logged out on every page load

**Cause:** Session middleware configuration issue

**Solution:**
```bash
# Verify session cookie in browser DevTools
# Should see: cloudopstools-session

# Check backend/main.py for correct session_cookie parameter
grep session_cookie backend/main.py
```

### Theme Not Persisting

**Symptom:** Theme resets on page refresh

**Cause:** localStorage key mismatch

**Solution:**
```bash
# Check theme-switcher.js for correct localStorage key
grep localStorage backend/static/js/theme-switcher.js
# Should show: cloudopstools-theme
```

### 500 Errors on S3 Operations

**Symptom:** File upload/download operations fail

**Cause:** S3 bucket not migrated or IAM permissions not updated

**Solution:**
1. Verify new S3 bucket exists
2. Check IAM policies grant access to new bucket
3. Temporarily revert S3 URL in code if external migration is delayed

---

## Support Contacts

For migration assistance, contact:

- **Technical Issues:** CloudOpsTools Team
- **AWS/S3 Migration:** AWS Administrator
- **User Access Issues:** System Administrator

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024 | Initial migration guide for PCM-Ops to CloudOpsTools rebranding |
