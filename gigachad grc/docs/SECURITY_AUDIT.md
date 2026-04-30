# Security Audit Report

**Audit Date:** December 14, 2025  
**Version:** 1.0.0-beta  
**Auditor:** Automated npm audit + manual review

---

## Executive Summary

This document summarizes the security audit findings for GigaChad GRC prior to public release. The audit covers dependency vulnerabilities, code security review recommendations, and remediation status.

### Vulnerability Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | ✅ None found |
| High | 0 | ✅ All fixed (upgraded @nestjs/cli, replaced xlsx with exceljs) |
| Moderate | 9 | ⚠️ Accepted risk / dev-only |
| Low | 0 | ✅ Acceptable |

---

## Dependency Audit Results

### Services Audited

| Service | Vulnerabilities | Critical/High |
|---------|-----------------|---------------|
| Root (monorepo) | 16 | 3 high |
| services/shared | 0 | 0 |
| services/controls | 8 | 2 high |
| services/frameworks | 9 | 3 high |
| services/policies | 8 | 2 high |
| services/tprm | 8 | 2 high |
| services/trust | 8 | 2 high |
| services/audit | 8 | 2 high |
| frontend | 9 | 1 high |

---

## High Severity Vulnerabilities

### 1. glob (10.2.0 - 10.4.5) - Command Injection ✅ FIXED

**Advisory:** [GHSA-5j98-mcp5-4vw2](https://github.com/advisories/GHSA-5j98-mcp5-4vw2)

**Affected Package:** `glob` via `@nestjs/cli`

**Description:** The glob CLI tool has a command injection vulnerability when using the `-c/--cmd` flag with `shell:true`.

**Status:** ✅ **RESOLVED**

**Resolution:**
- Upgraded `@nestjs/cli` from v10.x to v11.x across all 6 services
- The updated @nestjs/cli uses a patched version of glob
- Upgrade completed on 2025-12-14

**Original Risk Assessment:**
- This vulnerability affected the `glob` CLI binary, not the library API
- `@nestjs/cli` is a **development dependency** only, not included in production builds
- The CLI was never exposed to user input

---

### 2. xlsx (SheetJS) - Prototype Pollution & ReDoS ✅ FIXED

**Advisories:** 
- [GHSA-4r6h-8v6p-xvw6](https://github.com/advisories/GHSA-4r6h-8v6p-xvw6) - Prototype Pollution
- [GHSA-5pgg-2g8v-p4x9](https://github.com/advisories/GHSA-5pgg-2g8v-p4x9) - ReDoS

**Affected Package:** `xlsx` (SheetJS)

**Description:** The xlsx library has prototype pollution and ReDoS vulnerabilities when parsing malicious spreadsheet files.

**Status:** ✅ **RESOLVED**

**Resolution:**
- Replaced `xlsx` (SheetJS) with `exceljs` library
- Updated code in:
  - `services/frameworks/src/frameworks/frameworks.service.ts` - Excel import parsing
  - `frontend/src/lib/export.ts` - Excel export generation
  - `frontend/src/pages/EvidenceDetail.tsx` - Excel file preview
- Migration completed on 2025-12-14

**Why exceljs:**
- More actively maintained (regular releases)
- No known security vulnerabilities
- Full Excel read/write support
- Async API for better performance with large files

---

## Moderate Severity Vulnerabilities

### 3. esbuild (≤0.24.2) - Dev Server Cross-Origin Requests

**Advisory:** [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99)

**Affected Package:** `esbuild` via `vite`

**Risk Assessment:** ✅ **Not Applicable to Production**

**Justification:**
- This vulnerability only affects the development server
- Production builds do not include or run the dev server
- Vite/esbuild dev server is only used during local development
- Developers should use trusted networks during development

**Remediation:**
- No action required for production
- Developers should be aware not to run dev server on untrusted networks
- Upgrade to Vite 7.x when stable and compatible

---

### 4. @babel/runtime (<7.26.10) - RegExp Complexity

**Advisory:** [GHSA-968p-4wvh-cqc8](https://github.com/advisories/GHSA-968p-4wvh-cqc8)

**Affected Package:** `@babel/runtime` via `@okta/okta-auth-js` → `broadcast-channel`

**Risk Assessment:** ✅ **Low Impact**

**Justification:**
- Affects transpiled code with named capturing groups
- Only causes performance degradation (not security bypass)
- Triggered only in specific regex edge cases
- Dependency is in the Okta authentication library

**Remediation:**
- Can be fixed with `npm audit fix`
- Plan upgrade in next maintenance release

---

### 5. js-yaml (4.0.0 - 4.1.0) - Prototype Pollution

**Advisory:** [GHSA-mh29-5h37-fv8m](https://github.com/advisories/GHSA-mh29-5h37-fv8m)

**Affected Package:** `js-yaml` via `@nestjs/swagger`

**Risk Assessment:** 🟡 **Accepted Risk**

**Justification:**
- Prototype pollution requires specific YAML input using merge keys (`<<`)
- YAML parsing in the application is limited to:
  - OpenAPI/Swagger spec generation (not user-controlled)
  - Config-as-Code YAML files (admin-only, trusted input)
- No user-controlled YAML parsing paths

**Remediation Plan:**
- Track `@nestjs/swagger@11.x` for js-yaml update
- Ensure no user-controlled YAML parsing is added

---

### 6. tmp (≤0.2.3) - Symlink Directory Attack

**Advisory:** [GHSA-52f5-9888-hmc6](https://github.com/advisories/GHSA-52f5-9888-hmc6)

**Affected Package:** `tmp` via `inquirer` → `@nestjs/cli`

**Risk Assessment:** ✅ **Development Only**

**Justification:**
- `tmp` is used by `inquirer` in the NestJS CLI
- This is a development dependency only
- Not included in production Docker images
- The CLI's temp file usage is not exposed to user input

**Remediation:**
- Will be resolved when upgrading `@nestjs/cli`
- No user action required

---

## Code Security Review Findings

### Areas Reviewed

| Area | Status | Notes |
|------|--------|-------|
| Authentication (Keycloak) | ✅ Pass | JWT validation, session management secure |
| Authorization (RBAC) | ✅ Pass | Permission checks on all protected endpoints |
| Input Validation | ✅ Pass | DTOs with class-validator decorators |
| File Upload | ✅ Pass | Type validation, size limits, path sanitization |
| Database (Prisma) | ✅ Pass | No raw SQL queries exposed to user input |
| API Security | ✅ Pass | Rate limiting, CORS configuration |

### Security Controls in Place

1. **Authentication**
   - Keycloak-based OAuth 2.0/OIDC
   - JWT token validation on all API requests
   - Secure session handling

2. **Authorization**
   - Role-Based Access Control (RBAC)
   - Permission guards on all controllers
   - Multi-tenant isolation by organization ID

3. **Input Validation**
   - All DTOs use `class-validator` decorators
   - Request payload validation before processing
   - Type coercion and sanitization

4. **File Security**
   - File type validation (MIME type + extension)
   - File size limits enforced
   - Files stored in RustFS/S3 with unique keys
   - No direct filesystem access

5. **Database Security**
   - Prisma ORM prevents SQL injection
   - Parameterized queries throughout
   - Soft delete for audit trail

6. **API Security**
   - CORS configuration per environment
   - Rate limiting on authentication endpoints
   - Request logging for audit trail

---

## Secrets Audit

### Scan Results

No hardcoded secrets were found in the codebase. All sensitive values are:
- Loaded from environment variables
- Configured via `.env` files (excluded from git)
- Documented in `env.example` files with placeholder values

### Secret Management Recommendations

1. **Production Deployments:**
   - Use Docker secrets or external secret managers (Vault, AWS Secrets Manager)
   - Never commit `.env` files to version control
   - Rotate database passwords and API keys regularly

2. **Development:**
   - Use default development credentials from `env.development`
   - Never use production credentials in development

---

## Recommendations

### Immediate Actions (Pre-Release) ✅ COMPLETE

- [x] Document all vulnerabilities and risk acceptance
- [x] Verify no critical/high vulnerabilities in production code paths
- [x] Ensure security controls are documented
- [x] **Upgrade `@nestjs/cli` to v11.x** - Completed 2025-12-14
- [x] **Replace `xlsx` with `exceljs`** - Completed 2025-12-14

### Short-term (v1.1.0)

- [ ] Upgrade `@nestjs/swagger` to v11.x for js-yaml fix
- [ ] Run `npm audit fix` on safe upgrades
- [ ] Monitor for new vulnerability disclosures

### Medium-term (v1.2.0)

- [x] Add automated dependency scanning to CI/CD (Trivy in workflow)
- [x] Implement Trivy container scanning (already in CI workflow)
- [ ] Add SAST (Static Application Security Testing) tool
- [ ] Consider security.txt file for vulnerability disclosure

---

## Compliance Notes

### For SOC 2 / ISO 27001 Users

When deploying GigaChad GRC for your own compliance program, note that:

1. **Dependency vulnerabilities** should be reviewed against your organization's risk tolerance
2. **All high severity vulnerabilities have been remediated** as of 2025-12-14
3. **Regular updates** - Subscribe to GitHub releases for security patches

### Security Disclosure

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Use GitHub's private vulnerability reporting feature
3. Or email the maintainers directly

---

## Audit History

| Date | Version | Auditor | Summary |
|------|---------|---------|---------|
| 2025-12-14 | 1.0.0-beta | Automated + Manual | Initial pre-release audit |
| 2025-12-14 | 1.0.0-beta | Automated | Security fixes: upgraded @nestjs/cli v11, replaced xlsx with exceljs (0 high vulns remaining) |

---

*This document is part of GigaChad GRC's commitment to transparency. We believe in honest disclosure of security findings to help users make informed decisions.*

