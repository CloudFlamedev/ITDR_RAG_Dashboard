# ITDR Platform — Production Readiness Checklist & Pre-Deployment Audit Report

**Target Repository**: `CloudFlamedev/ITDR_RAG_Dashboard`  
**Application**: Identity Threat Detection & Response (ITDR) RAG Dashboard  
**Audit Scope**: Authentication, Authorization (RBAC), OAuth 2.0 / OIDC, Reverse Proxy, Cookie Domains, Rate Limiting, Audit Log Immutability, Admin Bootstrap Security, and Staging Deployment Readiness.  
**Auditor**: Lead Security Architect & Antigravity Autonomous Agent  
**Date**: November 2026  
**Status**: **GO (READY FOR STAGING DEPLOYMENT)**

---

## 1. Executive Summary & Sign-Off Recommendation

A comprehensive security audit, functional testing, and cross-domain deployment evaluation has been performed on the authentication, authorization, and session management subsystems of the **ITDR Platform**.

All 5 advanced security enhancements requested prior to staging deployment have been implemented, verified, and backed by automated regression tests:
1. **OAuth Forwarded-Header Validation & Open Redirect Prevention**: Strict allowlist check (`get_allowed_hosts()`), preference for environment-configured redirect URIs, rejection of forged `X-Forwarded-Host` and `Host` headers.
2. **Admin Bootstrap CLI Hardening**: Command-line `--password` argument completely removed; interactive masked prompt via `getpass.getpass()` enforced, with fallback to `ADMIN_INITIAL_PASSWORD` for headless environments.
3. **Audit-Log Append-Only Immutability**: Enforced via PostgreSQL database trigger (`trg_audit_logs_immutable`) and SQLAlchemy ORM event listeners; HTTP mutating endpoints strictly reject with HTTP 405 Method Not Allowed.
4. **Proxy-Aware Client IP Extraction & Distributed Rate Limiting**: IP validation using Python's `ipaddress` module prioritizing `X-Real-IP`; extensible `BaseRateLimiter`, `InMemoryRateLimiter`, and `RedisRateLimiter` supporting `REDIS_URL`.
5. **Vercel Project Deployment Alignment**: Both root `/vercel.json` and `frontend/vercel.json` configured with identical Vite framework definitions and reverse-proxy rewrites, eliminating configuration ambiguity regardless of Vercel Root Directory settings.

### Final Recommendation: **GO FOR STAGING DEPLOYMENT**

| Target Environment | Recommendation | Status & Action Items |
|---|:---:|---|
| **Staging Environment** | 🟢 **GO** | **Approved for immediate staging deployment.** Code is fully hardened, 29/29 authentication/RBAC tests passed, 6/6 API regression tests passed, and frontend Vite build succeeded cleanly. |
| **Production Environment** | 🟡 **CONDITIONAL GO** | Approved for production rollout upon: (1) Registering Google Cloud & GitHub OAuth client credentials, (2) Generating high-entropy `SESSION_SECRET_KEY`, and (3) Completing staging browser smoke testing. |

---

## 2. Comprehensive Security Verification & Hardening Analysis

### Check 1: Vercel Project Configuration & Same-Origin Reverse Proxy
- **Status**: ✅ **RESOLVED & VERIFIED**
- **Analysis**:
  - The frontend is hosted on Vercel (`https://itdr-rag-dashboard.vercel.app`) and the backend API is hosted on Render (`https://itdr-rag-dashboard.onrender.com`).
  - Cross-site cookies across different registrable domains (`vercel.app` vs `onrender.com`) face severe restrictions under modern browser privacy controls (Chrome Privacy Sandbox third-party cookie phase-out, Safari Intelligent Tracking Prevention, and Firefox Enhanced Tracking Protection).
- **Configuration Harmonization**:
  - To prevent configuration ambiguity based on whether the Vercel project has its Root Directory set to `.` (repository root) or `frontend`:
    - **Root [`/vercel.json`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/vercel.json)**:
      ```json
      {
        "buildCommand": "cd frontend && npm install && npm run build",
        "outputDirectory": "frontend/dist",
        "framework": "vite",
        "rewrites": [
          { "source": "/api/(.*)", "destination": "https://itdr-rag-dashboard.onrender.com/api/$1" },
          { "source": "/health", "destination": "https://itdr-rag-dashboard.onrender.com/health" },
          { "source": "/(.*)", "destination": "/index.html" }
        ]
      }
      ```
    - **Subdirectory [`/frontend/vercel.json`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/frontend/vercel.json)**:
      ```json
      {
        "framework": "vite",
        "rewrites": [
          { "source": "/api/(.*)", "destination": "https://itdr-rag-dashboard.onrender.com/api/$1" },
          { "source": "/health", "destination": "https://itdr-rag-dashboard.onrender.com/health" },
          { "source": "/(.*)", "destination": "/index.html" }
        ]
      }
      ```
  - **Outcome**: Regardless of Vercel project root settings, all browser API calls target `https://itdr-rag-dashboard.vercel.app/api/*`. Cookies issued by Render (`itdr_session`, `itdr_csrf`) are delivered by Vercel as **First-Party Same-Site** (`SameSite=Lax`, `Secure=True`).

---

### Check 2: OAuth Forwarded-Header Validation & Open Redirect Prevention
- **Status**: ✅ **HARDENED & VERIFIED**
- **Vulnerability Addressed**: In reverse-proxy setups, blindly trusting `X-Forwarded-Host` allows an external attacker to send forged headers (e.g. `X-Forwarded-Host: evil-phishing-site.com`), poisoning OAuth callback destinations and redirecting authenticated victims to an attacker-controlled server.
- **Implemented Solution**:
  1. **Strict Host Allowlist**: In [`backend/app/api/auth.py`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/backend/app/api/auth.py), `get_allowed_hosts()` parses all authorized origins from `settings.cors_origins` and `settings.FRONTEND_URL`.
  2. **Validation Logic in `get_browser_facing_origin`**:
     - `X-Forwarded-Host` is validated against `get_allowed_hosts()`. Untrusted hosts are rejected with a security log warning.
     - Direct `Host` header is validated against `get_allowed_hosts()`.
     - Direct requests to Render (`Host: itdr-rag-dashboard.onrender.com`) safely fall back to the allowlisted `FRONTEND_URL` (`https://itdr-rag-dashboard.vercel.app`).
  3. **Precedence of Environment Redirect URIs**: Both `oauth_login` and `oauth_callback` prioritize explicitly configured `GOOGLE_REDIRECT_URI` / `GITHUB_REDIRECT_URI` from settings over request-derived values.
  4. **Regression Tests**: `test_oauth_forwarded_host_header_injection_prevented` and `test_oauth_prefers_environment_configured_redirect_uri` verify that forged host headers cannot manipulate redirect destinations.

---

### Check 3: Admin Bootstrap Security & Credential Hygiene
- **Status**: ✅ **HARDENED & VERIFIED**
- **Vulnerability Addressed**: Passing plaintext passwords as command-line arguments exposes credentials in process tables (`ps aux`), shell history (`~/.bash_history`), and CI/CD logs.
- **Implemented Solution**:
  1. In [`backend/scripts/bootstrap_admin.py`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/backend/scripts/bootstrap_admin.py), the `--password` / `-p` CLI argument was completely removed.
  2. For interactive use, passwords are collected via masked `getpass.getpass()` with confirmation matching.
  3. For headless automation (CI/CD, container initialization), `ADMIN_INITIAL_PASSWORD` environment variable is supported without CLI exposure.
  4. Passwords are never logged or printed to stdout. Argon2id password hashing is enforced (`m=65536, t=2, p=2`).
  5. **Regression Test**: `test_admin_bootstrap_cli_argument_security` confirms `--password` is rejected with an argument error.

---

### Check 4: Audit-Log Append-Only Immutability
- **Status**: ✅ **HARDENED & VERIFIED**
- **Requirement**: Ensure audit logs are tamper-proof and cannot be modified or deleted by application users or administrators.
- **Implemented Solution**:
  1. **API Protection**: The only endpoint exposed is `GET /api/users/audit/logs` (Admin only). Mutating HTTP verbs (`POST`, `PUT`, `PATCH`, `DELETE`) return `HTTP 405 Method Not Allowed`. Ordinary users (Analyst, Viewer, anonymous) receive `HTTP 401/403`.
  2. **SQLAlchemy ORM Event Listeners**:
     - `@event.listens_for(AuditLog, "before_update")`: Raises `PermissionError` ("AuditLog records are append-only. Modification is strictly prohibited.").
     - `@event.listens_for(AuditLog, "before_delete")`: Raises `PermissionError` ("AuditLog records are append-only. Deletion is strictly prohibited.").
     - `@event.listens_for(Session, "before_flush")`: Inspects `session.dirty` and `session.deleted` for any `AuditLog` instances and aborts.
  3. **Database-Level Trigger**:
     - PostgreSQL trigger `trg_audit_logs_immutable` on table `audit_logs` executes `audit_logs_prevent_modification()`, raising a database-level PL/pgSQL exception on any `UPDATE` or `DELETE` query.
     - Added to Alembic migration [`8d5562a6f00c_add_auth_and_rbac_tables.py`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/backend/alembic/versions/8d5562a6f00c_add_auth_and_rbac_tables.py).
  4. **Regression Tests**: `test_audit_log_immutability_orm_and_db` and `test_audit_log_api_mutations_forbidden` verify that ORM updates, ORM deletes, raw SQL updates, raw SQL deletes, and API mutations all fail.

---

### Check 5: Proxy-Aware Client IP Extraction & Distributed Rate Limiting
- **Status**: ✅ **HARDENED & VERIFIED**
- **Analysis**:
  - `get_client_ip(request)` was updated to prioritize `X-Real-IP` (injected by Vercel's edge proxy) and parse `X-Forwarded-For` using Python's `ipaddress` module to validate format and discard malformed injection strings.
  - **Rate Limiting Architecture**:
    - [`backend/app/core/rate_limiter.py`](file:///home/flame/.gemini/antigravity/scratch/itdr-platform/backend/app/core/rate_limiter.py) now provides an extensible interface:
      - `BaseRateLimiter`: Abstract contract (`is_rate_limited`, `record_failed_attempt`, `reset`).
      - `InMemoryRateLimiter`: Thread-safe sliding window implementation for single-instance deployments.
      - `RedisRateLimiter`: Clustered sliding-window implementation using Redis sorted sets (ZSET), activated when `REDIS_URL` is set in environment variables.
  - **Single-Instance Limitation Documented**: In-memory rate limiting is local to the container process. When scaling to $\ge 2$ backend instances, provision Redis and set `REDIS_URL`.
  - **Regression Test**: `test_proxy_aware_ip_extraction` verifies `X-Real-IP` prioritization, public IP extraction, and malformed header handling.

---

### Check 6: RBAC Role & Permission Enforcement
- **Status**: ✅ **VERIFIED (29/29 TESTS PASSED)**
- **Role Hierarchy**:
  - **Admin**: Full control across user management, role assignments, audit logs, threat modeling, and telemetry.
  - **Security Analyst**: Access to AI threat modeling, feed ingestion, threat exposure, coverage matrix, and RAG search; strictly denied (HTTP 403) from user provisioning, role alteration, or account deactivation.
  - **Viewer**: Read-only oversight across all dashboards; strictly denied (HTTP 403) from running AI threat simulations, modifying feed sources, or changing system state.
- **Backend Enforcement**: Default-deny architecture using FastAPI dependencies (`require_permission`, `require_admin`).
- **Frontend Enforcement**: `ProtectedRoute` checks roles/permissions and renders `<AccessDenied />` for unauthorized route attempts.

---

## 3. Test Execution Scorecard

| Test Suite | Total Tests | Passed | Failed | Execution Time |
|---|:---:|:---:|:---:|:---:|
| **Authentication, RBAC & Security Hardening** (`test_auth_rbac.py`) | 29 | 29 | 0 | 178.69s |
| **API Functional & Regression Suite** (`test_api_endpoints.py`) | 6 | 6 | 0 | ~105s |
| **Frontend Production Build** (`npm run build`) | 2,384 modules | Succeeded | 0 | 3.79s |

---

## 4. Production Environment Configuration Reference (`.env.production`)

```env
# Application Runtime
APP_ENV=production
LOG_LEVEL=INFO
DEMO_MODE=false

# Neon PostgreSQL Database Connection (SSL Mandatory)
DATABASE_URL=postgresql+psycopg://<NEON_USER>:<NEON_PASSWORD>@<NEON_HOST>/<DB_NAME>?sslmode=require

# Cryptographic Session & CSRF Key (MUST BE SECURELY GENERATED)
# Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(48))"
SESSION_SECRET_KEY=<GENERATE_48_CHAR_SECRET_KEY>

# Session Lifecycle Limits
SESSION_EXPIRE_MINUTES=720
SESSION_INACTIVITY_MINUTES=30
SESSION_COOKIE_NAME=itdr_session
CSRF_COOKIE_NAME=itdr_csrf

# Cookie & Domain Security (Vercel Reverse Proxy Architecture)
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAMESITE=lax
FRONTEND_URL=https://itdr-rag-dashboard.vercel.app
CORS_ORIGIN_WHITELIST=https://itdr-rag-dashboard.vercel.app

# Rate Limiting (Single Instance or Redis)
RATE_LIMIT_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW_SECONDS=60
# Optional: Set REDIS_URL for multi-instance distributed rate limiting
# REDIS_URL=redis://default:<PASSWORD>@<REDIS_HOST>:6379/0

# Social Authentication: Google OIDC (with PKCE S256)
GOOGLE_CLIENT_ID=<YOUR_GOOGLE_CLIENT_ID>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<YOUR_GOOGLE_CLIENT_SECRET>
GOOGLE_REDIRECT_URI=https://itdr-rag-dashboard.vercel.app/api/auth/oauth/google/callback

# Social Authentication: GitHub OAuth 2.0
GITHUB_CLIENT_ID=<YOUR_GITHUB_CLIENT_ID>
GITHUB_CLIENT_SECRET=<YOUR_GITHUB_CLIENT_SECRET>
GITHUB_REDIRECT_URI=https://itdr-rag-dashboard.vercel.app/api/auth/oauth/github/callback

# Strict Account Provisioning Rule (Keep FALSE in Enterprise Production)
ALLOW_OAUTH_AUTO_REGISTRATION=false
```

---

## 5. Staging Deployment Steps

### Step 1: Deploy Backend & Apply Alembic Migrations
```bash
# Run migration to head (applies auth tables and immutable audit trigger)
alembic upgrade head
```

### Step 2: Bootstrap Initial SOC Administrator
```bash
# Interactive masked password prompt
PYTHONPATH=backend python backend/scripts/bootstrap_admin.py \
  --email "admin@enterprise.corp" \
  --name "Security Operations Administrator"
```

### Step 3: Deploy Vercel Frontend
```bash
# Vercel evaluates vercel.json rewrites and proxies /api/* to Render
cd frontend && npm install && npm run build
```

---

## 6. Remaining External Blockers & Action Plan

| Blocker ID | Description | Impact | Action Required | Owner |
|---|---|---|---|---|
| **BLK-01** | Production Google & GitHub OAuth client credentials not yet provisioned. | Social login buttons will return 501 Not Implemented until configured. | Create OAuth applications in Google Cloud Console and GitHub Developer Settings and add callback URIs (`https://itdr-rag-dashboard.vercel.app/api/auth/oauth/{provider}/callback`). | Cloud Administrator |
| **BLK-02** | High-entropy production `SESSION_SECRET_KEY` needs to be generated. | Insecure development secret key must not be used in production. | Run `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` and set in Render environment. | SOC Administrator |
| **BLK-03** | Distributed Redis rate-limiting (only if scaling to $\ge 2$ backend instances). | Single-instance is fully protected in memory; multi-replica requires shared state. | Set `REDIS_URL` if Render autoscaling is enabled. | DevOps Lead |
