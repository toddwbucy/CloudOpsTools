# Rollback Procedures
## Emergency Recovery and Feature Rollback Guide

**Document Version:** 1.0  
**Date:** 2025-08-24  
**Purpose:** Provide clear procedures for rolling back changes when issues are detected

---

## 🚨 Quick Reference - Emergency Rollback

### **IMMEDIATE ACTIONS (30 seconds)**
```bash
# Method 1: Feature Flag Emergency Rollback (Fastest)
curl -X POST http://localhost:8500/api/feature-flags/emergency-rollback

# Method 2: Environment Variable Rollback
export FEATURE_FLAG_ROLLBACK_MODE_ENABLED=true
# Restart application

# Method 3: Git Rollback (if feature flags fail)
git checkout main
./stop.sh && ./start.sh
```

### **Emergency Contacts**
- **Primary:** Todd (Repository Owner)
- **Secondary:** Team Lead
- **Escalation:** Management approval authority

---

## 📋 Rollback Decision Matrix

### **When to Rollback Immediately**
- ❌ **Application won't start** (critical failure)
- ❌ **Users cannot authenticate** (authentication broken) 
- ❌ **Data corruption detected** (database issues)
- ❌ **Security vulnerability introduced** (immediate risk)
- ❌ **Performance degradation >50%** (user experience impact)

### **When to Disable Feature Flag**
- ⚠️ **Feature not working as expected** (functional issues)
- ⚠️ **Minor performance impact** (<25% degradation)
- ⚠️ **UI/UX issues** (cosmetic problems)
- ⚠️ **Limited user impact** (specific edge cases)

### **When to Investigate Before Rolling Back**
- 🔍 **Single user reports** (may be user-specific)
- 🔍 **Minor UI inconsistencies** (may be browser-specific)
- 🔍 **Performance questions** (may be infrastructure)

---

## 🎯 Phase-Specific Rollback Procedures

### **Phase 1: Security Fixes Rollback**

#### **SECRET_KEY Issue Rollback**
```bash
# Symptoms: Sessions broken, authentication failing
# Solution: Disable feature flag
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "new_secret_key_handling", "enabled": false}'

# Verify: Check session functionality
curl http://localhost:8500/api/health
```

#### **XSS Protection Rollback**
```bash
# Symptoms: UI not rendering, JavaScript errors
# Solution: Disable XSS protection feature flag
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "xss_protection_enabled", "enabled": false}'

# Clear browser cache and test UI
```

#### **CSRF Token Rollback**
```bash
# Symptoms: Forms not submitting, 403 errors
# Solution: Disable CSRF tokens
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "csrf_tokens_enabled", "enabled": false}'
```

#### **Credential Storage Rollback**
```bash
# Symptoms: Credential flow broken, AWS operations failing
# Solution: Rollback to session storage
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "secure_credential_storage", "enabled": false}'
```

### **Phase 2: Medium Risk Fixes Rollback**

#### **Threading Issues Rollback**
```bash
# Symptoms: Database errors, session corruption
# Solution: Disable thread safety features
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "thread_safe_sessions", "enabled": false}'

curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "atomic_session_updates", "enabled": false}'
```

#### **Error Handling Rollback**
```bash
# Symptoms: Unexpected errors, application crashes
# Solution: Rollback to original error handling
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "enhanced_error_handling", "enabled": false}'
```

#### **Pydantic v2 Rollback**
```bash
# Symptoms: API schema errors, validation failures
# Solution: Disable Pydantic v2 features
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "pydantic_v2_schemas", "enabled": false}'

# May require application restart for schema changes
./stop.sh && ./start.sh
```

### **Phase 3: Configuration Rollback**

#### **Database Connection Rollback**
```bash
# Symptoms: Database connection failures
# Solution: Rollback database configuration
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d '{"flag_name": "postgresql_support", "enabled": false}'

# Check database connectivity
poetry run python -c "from backend.db.session import engine; print('DB OK')"
```

---

## 🔄 Git-Based Rollback Procedures

### **Complete Application Rollback**
```bash
# When feature flags are not sufficient

# 1. Stop the application
./stop.sh

# 2. Create backup of current state
git stash push -m "Backup before rollback $(date)"

# 3. Rollback to last known good state
git checkout main  # or specific commit hash

# 4. Restart application  
./start.sh

# 5. Verify functionality
curl http://localhost:8500/api/health
```

### **Partial Rollback (Specific Files)**
```bash
# Rollback specific files while keeping others

# 1. List changed files
git diff --name-only main..HEAD

# 2. Rollback specific files
git checkout main -- backend/core/config.py  # Example
git checkout main -- backend/api/auth.py     # Example

# 3. Test and commit
git add . && git commit -m "Partial rollback: config and auth"
```

### **Database Rollback**
```bash
# If database changes need rollback

# 1. Stop application
./stop.sh

# 2. Backup current database
cp data/pcm_ops_tools.db data/pcm_ops_tools_backup_$(date +%Y%m%d_%H%M%S).db

# 3. Restore from backup (if available)
cp data/pcm_ops_tools_backup_YYYYMMDD_HHMMSS.db data/pcm_ops_tools.db

# 4. Or reinitialize database
rm data/pcm_ops_tools.db
poetry run python backend/db/init_db.py

# 5. Restart application
./start.sh
```

---

## 📊 Monitoring During Rollback

### **Health Check Endpoints**
```bash
# Application health
curl http://localhost:8500/api/health

# Feature flags health
curl http://localhost:8500/api/feature-flags/health

# Database connectivity
curl http://localhost:8500/api/providers

# AWS credential status
curl http://localhost:8500/api/auth/aws-check-credentials
```

### **Log Monitoring**
```bash
# Application logs
tail -f logs/pcm_ops_tools.log

# Feature flag activity
grep "Feature flag" logs/pcm_ops_tools.log | tail -20

# Error patterns
grep -i "error\|exception\|failed" logs/pcm_ops_tools.log | tail -10
```

### **Performance Monitoring**
```bash
# Response time check
time curl -s http://localhost:8500/api/health > /dev/null

# Memory usage
ps aux | grep python | grep backend.main

# Database size
ls -lh data/pcm_ops_tools.db
```

---

## 🧪 Rollback Testing Procedures

### **Pre-Rollback Testing**
```bash
# 1. Create test plan
echo "Testing rollback for: [FEATURE_NAME]" > rollback_test.log

# 2. Document current state
curl http://localhost:8500/api/feature-flags >> rollback_test.log

# 3. Test critical paths
curl http://localhost:8500/api/health >> rollback_test.log
curl http://localhost:8500/aws/tools >> rollback_test.log
```

### **Post-Rollback Verification**
```bash
# 1. Verify feature is disabled
curl http://localhost:8500/api/feature-flags/[FLAG_NAME]

# 2. Test critical functionality
./tests/critical_path_test.sh  # If available

# 3. Check logs for errors
grep -i "error" logs/pcm_ops_tools.log | tail -5

# 4. Performance verification  
time curl -s http://localhost:8500/api/health > /dev/null
```

---

## 📝 Rollback Communication Template

### **Internal Communication**
```
SUBJECT: [URGENT] PCM-Ops Tools Rollback - [FEATURE_NAME]

ISSUE: Brief description of the problem
IMPACT: Who/what is affected
ACTION: What was rolled back
STATUS: Current system status  
NEXT STEPS: What happens next

Time: [TIMESTAMP]
Duration: [XX minutes]
Affected Users: [Estimate]
```

### **Rollback Log Entry Template**
```
[TIMESTAMP] ROLLBACK INITIATED
Feature: [FEATURE_NAME]
Trigger: [REASON]
Method: [feature_flag/git/emergency]
Duration: [XX minutes]  
Verification: [success/partial/failed]
```

---

## 🔧 Rollback Automation Scripts

### **Quick Rollback Script**
```bash
#!/bin/bash
# quick-rollback.sh - Emergency rollback automation

FEATURE_NAME=$1
if [ -z "$FEATURE_NAME" ]; then
    echo "Usage: ./quick-rollback.sh <feature_flag_name>"
    exit 1
fi

echo "🚨 EMERGENCY ROLLBACK: $FEATURE_NAME"
echo "Time: $(date)"

# Disable the feature flag
curl -X POST http://localhost:8500/api/feature-flags/toggle \
  -H "Content-Type: application/json" \
  -d "{\"flag_name\": \"$FEATURE_NAME\", \"enabled\": false}"

# Verify rollback
sleep 2
STATUS=$(curl -s http://localhost:8500/api/feature-flags/$FEATURE_NAME | jq -r '.enabled')

if [ "$STATUS" = "false" ]; then
    echo "✅ ROLLBACK SUCCESSFUL"
    echo "Feature $FEATURE_NAME is now disabled"
else
    echo "❌ ROLLBACK FAILED" 
    echo "Manual intervention required"
    exit 1
fi

# Test critical functionality
echo "🧪 Testing critical paths..."
curl -s http://localhost:8500/api/health > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Application health check passed"
else
    echo "❌ Application health check failed"
    echo "Consider emergency application restart"
fi
```

Make the script executable:
```bash
chmod +x quick-rollback.sh
```

---

## 📚 Recovery Best Practices

### **Before Making Changes**
1. ✅ **Tag current state**: `git tag working-state-$(date +%Y%m%d)`
2. ✅ **Backup database**: Copy current database file
3. ✅ **Document change**: Record what you're changing
4. ✅ **Test plan ready**: Know how to verify the change
5. ✅ **Rollback plan ready**: Know exactly how to undo

### **During Rollback**
1. ⏱️ **Act quickly**: Time is critical
2. 📢 **Communicate**: Inform stakeholders immediately
3. 📊 **Monitor**: Watch logs and health checks
4. 🧪 **Verify**: Test that rollback actually worked
5. 📝 **Document**: Log what happened and why

### **After Rollback**
1. 🔍 **Root cause analysis**: Understand what went wrong
2. 🛠️ **Fix the issue**: Address the underlying problem
3. 🧪 **Test thoroughly**: Ensure fix works in staging
4. 📝 **Update procedures**: Improve rollback process
5. 📚 **Share learnings**: Help team avoid similar issues

---

## 🎯 Success Criteria

### **Rollback is Successful When:**
- [ ] Application starts and responds to health checks
- [ ] Critical user flows work (authentication, navigation)
- [ ] No new errors in logs
- [ ] Performance returns to acceptable levels
- [ ] Database integrity is maintained
- [ ] All stakeholders are informed

### **Rollback is Complete When:**
- [ ] Issue is documented with root cause
- [ ] Fix is planned and scheduled
- [ ] Monitoring is in place for similar issues
- [ ] Team is briefed on lessons learned
- [ ] Process improvements are identified

This document ensures that any team member can perform a safe, effective rollback when issues are detected during the implementation phases.