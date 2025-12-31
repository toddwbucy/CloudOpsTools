# Product Requirements Document (PRD)
## PCM-Ops Tools - Production Readiness Enhancement

**Document Version:** 1.1  
**Date:** 2025-08-24  
**Status:** Updated with CodeRabbit Findings  
**Review Inputs:** ✅ CodeRabbit analysis complete (50+ issues identified)

---

## Executive Summary

This PRD outlines the requirements and implementation strategy for transitioning PCM-Ops Tools from its current working state to a production-ready platform suitable for deployment on AWS Fargate. The document emphasizes maintaining system stability throughout the transition while addressing corporate security requirements.

### Key Principles
1. **Maintain Working State**: All changes must be backward compatible and tested
2. **Incremental Improvements**: Small, reversible changes with feature flags
3. **Security First**: Address security vulnerabilities before adding features
4. **Comprehensive Testing**: Each change must include tests before deployment
5. **Rollback Capability**: Every change must have a documented rollback procedure

---

## Current State Analysis

### Working Features (DO NOT BREAK)
- ✅ FastAPI application serving on port 8500
- ✅ AWS Script Runner with multi-account support
- ✅ Credential management for COM/GOV environments
- ✅ Session management with SQLite backend
- ✅ Web UI with Jinja2 templates
- ✅ Dynamic provider discovery system
- ✅ Linux QC Patching (Prep & Post)
- ✅ SFT Fixer tool
- ✅ Basic encryption for credentials

### Known Issues (From CodeRabbit Analysis - 50+ Issues)

#### 🔴 CRITICAL SECURITY ISSUES (5 issues)
- Hardcoded SECRET_KEY in config (immediate fix required)
- XSS vulnerabilities in JavaScript files (3 locations)
- Missing CSRF protection throughout application
- Credentials stored in session cookies (insecure)
- SFT enrollment token in plaintext environment variables

#### 🟡 MEDIUM RISK ISSUES (10 issues)  
- Thread safety issues in session store (race conditions)
- Database race conditions without proper locking
- Missing model imports causing table creation failures
- Unhandled exceptions that could crash application
- Memory leaks in JavaScript polling functions

#### 🟠 CONFIGURATION ISSUES (20 issues)
- Invalid CodeRabbit configuration sections
- Docker security issues with Poetry installer
- Environment variable mismatches and prod flags
- Database connection configuration problems
- Version alignment issues in pyproject.toml

#### 🟢 COSMETIC/MAINTENANCE ISSUES (15+ issues)
- Template inconsistencies and HTML issues
- String corrections and casing problems
- Import organization and code quality
- UI/UX improvements and accessibility fixes

#### 🔄 SYSTEMIC CODE QUALITY ISSUES (Additional)
- **Logging Inconsistency:** 15 `print()` statements should use proper logging
- **Pydantic v1 Legacy:** 18 schema classes still use old `Config` pattern
- **Code Duplication:** Repeated credential validation logic across files
- **Parameter Schema:** Potential issues with "required" property-level validation

**Detailed Analysis:** 
- CodeRabbit Issues: `/docs/CodeRabbit-Issues-Analysis.md`
- Systemic Improvements: `/docs/Systemic-Code-Improvements.md`

---

## Requirements

### Priority 1: Security Requirements (MUST HAVE)

#### 1.1 Authentication & Authorization
- **Requirement**: Implement enterprise authentication
- **Current State**: No authentication
- **Target State**: OAuth2/SAML integration with corporate SSO
- **Acceptance Criteria**:
  - [ ] Users must authenticate before accessing any functionality
  - [ ] Support for MFA
  - [ ] Session timeout after 30 minutes of inactivity
  - [ ] Audit logging of all authentication events

#### 1.2 Session Security
- **Requirement**: Harden session management
- **Current State**: Basic Starlette sessions
- **Target State**: Encrypted, secure sessions
- **Acceptance Criteria**:
  - [ ] HTTPOnly flag on all cookies
  - [ ] Secure flag for HTTPS environments
  - [ ] SameSite=Strict for CSRF protection
  - [ ] Session rotation on privilege changes

#### 1.3 Secrets Management
- **Requirement**: Externalize all secrets
- **Current State**: Hardcoded SECRET_KEY
- **Target State**: AWS Secrets Manager integration
- **Acceptance Criteria**:
  - [ ] No secrets in code or environment variables
  - [ ] Automatic secret rotation support
  - [ ] Encrypted secrets at rest and in transit

#### 1.4 CSRF Protection
- **Requirement**: Implement CSRF tokens
- **Current State**: TODO comments in templates
- **Target State**: All forms protected
- **Acceptance Criteria**:
  - [ ] CSRF tokens on all POST/PUT/DELETE operations
  - [ ] Token validation in middleware
  - [ ] Automatic token refresh

### Priority 2: Infrastructure Requirements (SHOULD HAVE)

#### 2.1 Database Migration
- **Requirement**: Production-grade database
- **Current State**: SQLite
- **Target State**: AWS RDS PostgreSQL
- **Migration Strategy**:
  1. Add PostgreSQL support alongside SQLite
  2. Implement data migration scripts
  3. Test in staging environment
  4. Gradual cutover with fallback option

#### 2.2 Logging & Monitoring
- **Requirement**: Centralized logging
- **Current State**: Basic file logging
- **Target State**: CloudWatch integration
- **Acceptance Criteria**:
  - [ ] Structured JSON logging
  - [ ] Correlation IDs for request tracking
  - [ ] No sensitive data in logs
  - [ ] Log aggregation and search capability

#### 2.3 Error Handling
- **Requirement**: Production error handling
- **Current State**: Stack traces exposed
- **Target State**: User-friendly error messages
- **Acceptance Criteria**:
  - [ ] Global exception handler
  - [ ] Custom error pages
  - [ ] Error tracking integration
  - [ ] No internal details exposed

### Priority 3: Deployment Requirements (NICE TO HAVE)

#### 3.1 Container Optimization
- **Requirement**: Production-ready container
- **Current State**: Basic Dockerfile
- **Target State**: Optimized for Fargate
- **Requirements**:
  - [ ] Multi-stage build
  - [ ] Non-root user
  - [ ] Security scanning
  - [ ] Minimal attack surface

#### 3.2 Configuration Management
- **Requirement**: Environment-specific configs
- **Current State**: .env files
- **Target State**: AWS Systems Manager
- **Requirements**:
  - [ ] Parameter Store integration
  - [ ] Environment separation
  - [ ] Configuration validation
  - [ ] Hot-reload capability

---

## Implementation Plan

### Phase 0: Preparation (Week 0)
- [x] Complete CodeRabbit review
- [ ] Consolidate all feedback  
- [ ] Create feature flag system
- [ ] Set up staging environment
- [ ] Establish rollback procedures

### Phase 1: Critical Security Fixes (Week 1)
**Goal**: Address 🔴 CRITICAL SECURITY ISSUES without breaking functionality

**Sprint 1.1: Immediate Security (Days 1-2)**
- [ ] Fix hardcoded SECRET_KEY (backend/core/config.py:57)
- [ ] Add environment variable fallback with dev mode
- [ ] Test session functionality after change
- **Rollback**: Keep old key as fallback

**Sprint 1.2: XSS Prevention (Days 3-4)** 
- [ ] Fix innerHTML XSS in aws-utilities.js:110-122
- [ ] Fix XSS in sft-fixer.js:323-324  
- [ ] Fix XSS in linux-qc-patching-prep.js:165-180
- [ ] Replace with safe DOM manipulation
- **Rollback**: Feature flag to use old rendering

**Sprint 1.3: CSRF & Credential Security (Day 5)**
- [ ] Add CSRF tokens to auth forms
- [ ] Move credentials from session to secure storage
- [ ] Migrate SFT token to AWS Secrets Manager
- **Rollback**: Feature flag for old credential flow

**Sprint 1.4: Logging Standardization (Day 5.5)**
- [ ] Replace 15 print() statements with proper logging
- [ ] Add logger imports to affected files
- [ ] Verify log output and levels
- **Rollback**: Simple commit revert (no functional impact)

### Phase 2: Medium Risk Issues (Week 2)
**Goal**: Address 🟡 MEDIUM RISK ISSUES that could cause runtime problems

**Sprint 2.1: Threading & Database Safety (Days 1-3)**
- [ ] Fix thread safety in session_store.py:30-40 (use threading.Event)
- [ ] Fix database race conditions in session_store.py:46-57 (proper transactions)
- [ ] Fix missing model imports in init_db.py:12-15
- [ ] Test with concurrent load
- **Rollback**: Keep old implementations with feature flag

**Sprint 2.2: Error Handling & Memory Leaks (Days 4-5)**
- [ ] Fix unhandled exceptions in changes.py:184-186, status.py:109-113  
- [ ] Fix JavaScript memory leaks in aws-execution.js:96-159
- [ ] Add proper cleanup functions
- [ ] Test browser performance under load
- **Rollback**: Original error handling patterns

**Sprint 2.3: Pydantic v2 Migration (Day 5.5)**
- [ ] Convert 18 Config classes to model_config = ConfigDict()
- [ ] Test API schema generation after each change
- [ ] Verify JSON serialization unchanged
- **Rollback**: Individual file reverts (low coupling)

### Phase 3: Configuration & Infrastructure (Week 3)
**Goal**: Address 🟠 CONFIGURATION ISSUES and prepare for deployment

**Sprint 3.1: Configuration Cleanup**
- [ ] Fix .coderabbit.yaml configuration issues
- [ ] Fix Docker Poetry installer security (use official image)
- [ ] Fix pyproject.toml version mismatches
- [ ] Fix database connection conditional logic
- **Rollback**: Original configurations

**Sprint 3.2: Production Preparation**  
- [ ] Remove --reload flag from production uvicorn
- [ ] Add PostgreSQL support alongside SQLite
- [ ] Implement structured logging
- [ ] Add health check improvements
- **Rollback**: Development configurations

**Sprint 3.3: Code Deduplication (Day 4.5)**
- [ ] Extract credential validation helper functions
- [ ] Refactor duplicate credential check logic
- [ ] Validate parameter schema contracts
- **Rollback**: Feature flag for old credential logic

### Phase 4: Cosmetic & Polish (Week 4)
**Goal**: Address 🟢 COSMETIC/MAINTENANCE ISSUES

**Sprint 4.1: Template & UI Improvements**
- [ ] Fix HTML template issues and inconsistencies
- [ ] Fix string casing and text corrections
- [ ] Improve accessibility and UI consistency  
- [ ] Clean up import organization
- **Rollback**: Original templates (low risk)

### Phase 5: Production Deployment (Week 5)
**Goal**: Deploy to AWS Fargate

**Sprint 5.1: Container & Deploy**
- [ ] Optimize Dockerfile with security fixes
- [ ] Create Fargate task definition
- [ ] Configure ALB and security groups
- [ ] Set up CI/CD pipeline
- **Rollback**: Blue-green deployment

### Phase 6: Testing & Documentation (Week 6)
**Goal**: Ensure quality and maintainability

**Sprint 6.1: Quality Assurance**
- [ ] Unit test coverage >80% 
- [ ] Integration test suite for all fixes
- [ ] Security testing for all vulnerabilities
- [ ] Load testing for concurrent issues
- [ ] Documentation updates for all changes

---

## Success Metrics

### Technical Metrics
- [ ] Zero downtime during migration
- [ ] <500ms API response time (p95)
- [ ] 99.9% uptime SLA
- [ ] Zero critical security vulnerabilities
- [ ] 80% test coverage

### Business Metrics
- [ ] All existing functionality preserved
- [ ] No user disruption
- [ ] Successful security audit
- [ ] Cost within budget
- [ ] On-time delivery

---

## Risk Management

### High-Risk Items
1. **Database Migration**
   - Risk: Data loss or corruption
   - Mitigation: Extensive testing, backup strategy, dual-write period

2. **Authentication Implementation**
   - Risk: Lock out existing users
   - Mitigation: Feature flag, gradual rollout, bypass mechanism

3. **Session Security Changes**
   - Risk: Break existing sessions
   - Mitigation: Grace period, session migration logic

### Dependencies
- CodeRabbit review completion
- AWS account access and permissions
- Security team approval
- Load testing environment

---

## Acceptance Criteria

### Definition of Done
- [ ] All tests passing
- [ ] Security scan clean
- [ ] Performance benchmarks met
- [ ] Documentation updated
- [ ] Rollback tested
- [ ] Code review approved
- [ ] Deployed to staging
- [ ] UAT sign-off

### Release Criteria
- [ ] Zero P1 bugs
- [ ] Security approval
- [ ] Operations runbook complete
- [ ] Monitoring configured
- [ ] Backup/restore tested

---

## Appendices

### A. Technical Debt Items
- Remove all console.log statements
- Remove all print() debug statements  
- Complete TODO items in code
- Refactor large functions
- Add missing type hints

### B. Future Enhancements (Out of Scope)
- Azure provider implementation
- GCP provider implementation
- ServiceNow integration
- Advanced RBAC
- Multi-region deployment

### C. Review Tracking
- [x] CodeRabbit review: ✅ Complete (50+ issues identified and categorized)
- [ ] Security review: Scheduled for Week 1 completion
- [ ] Architecture review: Scheduled for Week 2 completion  
- [ ] Management approval: Scheduled for Week 3 completion

### D. CodeRabbit Issue Summary
**Total Issues:** 50+
- 🔴 Critical Security: 5 issues (Week 1 priority)
- 🟡 Medium Risk: 10 issues (Week 2 priority)  
- 🟠 Configuration: 20 issues (Week 3 priority)
- 🟢 Cosmetic: 15+ issues (Week 4 priority)

**Detailed breakdown:** See `/docs/CodeRabbit-Issues-Analysis.md`

---

## Document History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-08-24 | System | Initial draft |
| 1.1 | 2025-08-24 | System | Updated with CodeRabbit findings (50+ issues) |

## Next Steps
1. ✅ CodeRabbit review results incorporated
2. ✅ Issues categorized by risk level  
3. ✅ Implementation plan updated with specific fixes
4. [ ] Set up feature flag system
5. [ ] Create staging environment
6. [ ] Begin Phase 1: Critical Security Fixes
7. [ ] Create detailed Jira tickets for each phase

---

**Note**: This is a living document. Updates will be made as reviews are completed and requirements are refined.