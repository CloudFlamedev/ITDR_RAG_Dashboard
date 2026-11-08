# ITDR Platform — Authentication, Authorization & Public Registration Architecture

This document details the enterprise security model, session management, Role-Based Access Control (RBAC), OAuth 2.0 / OpenID Connect flows, public self-registration, email verification, multi-tenant report isolation, and usage bounds implemented in the **Identity Threat Detection & Response (ITDR) Platform**.

---

## 1. High-Level Security Architecture

The ITDR platform implements a **defense-in-depth, zero-trust security perimeter**:
- **Default-Deny Access Policy**: All API endpoints (except `/health` and `/`) require cryptographic authentication and fine-grained RBAC authorization.
- **Server-Managed Session Store**: Stateful sessions persisted in Neon PostgreSQL (`user_sessions` table). Session identifiers transmitted in `HttpOnly`, `Secure`, `SameSite=Lax` cookies; only their SHA-256 hashes are stored in the database.
- **Argon2id Password Hashing**: Passwords hashed using standard Argon2id parameters (`m=65536`, `t=2`, `p=2`), with constant-time verification against timing attacks.
- **Public Self-Registration**: Public portfolio demo visitors can self-register at `/register` and explore the application. Accounts are automatically restricted to the bounded `Demo Analyst` role to prevent privilege escalation.
- **Email Verification**: Cryptographic 32-byte URL-safe verification tokens (stored as SHA-256 hashes in `email_verification_tokens`) with 30-minute expiration. Unverified accounts cannot log in (HTTP 403) and are offered a rate-limited resend flow.
- **Public Social Sign-Up**: Google OIDC (with RFC 7636 PKCE S256) and GitHub OAuth 2.0 automatically provision new visitor accounts with `Demo Analyst` role and verified status.
- **Multi-Tenant Report Isolation**: User threat analysis reports are attributed to `created_by_user_id`. Visitors can only view their own reports and shared demo reports; other users' reports return HTTP 404. SOC Administrators retain full visibility.
- **Usage Limits & Quotas**: Maximum advisory input size (`MAX_ADVISORY_CHARS=15000`), daily GenAI threat modeling quota (`DAILY_ANALYSIS_LIMIT=5` per 24 hours returning HTTP 429), and RAG search rate limiting.
- **HMAC CSRF Defense**: Double-submit cookie + signed HMAC-SHA256 CSRF tokens required on all state-changing HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Audit-Log Immutability**: All security events recorded to an append-only PostgreSQL table protected by a native database trigger and ORM listeners.

```
                           +---------------------------+
                           |  Client Browser / SOC UI  |
                           +-------------+-------------+
                                         |
                  1. Credentials / OAuth | 2. HttpOnly Cookie (itdr_session)
                     + CSRF Header       |    + X-CSRF-Token Header
                                         v
                         +-------------------------------+
                         | FastAPI Gateway / Middlewares |
                         | - Exact CORS Origin Whitelist |
                         | - Rate Limiter (Sliding Window|
                         | - MAX_ADVISORY_CHARS Limit    |
                         +---------------+---------------+
                                         |
                       [get_current_user_and_session]
                                         |
          +------------------------------+------------------------------+
          |                              |                              |
          v                              v                              v
+-------------------+          +-------------------+          +-------------------+
|  Argon2id Verify  |          | Session Validate  |          |  CSRF Signature   |
| (Constant-Time)   |          |  (PostgreSQL DB)  |          | (HMAC-SHA256)     |
+-------------------+          +-------------------+          +-------------------+
                                         |
                                  [RBAC Evaluation]
                                         |
                  +----------------------+----------------------+
                  |                      |                      |
                  v                      v                      v
          +---------------+      +---------------+      +---------------+
          |     Admin     |      |Sec. Analyst   |      | Demo Analyst  |
          | (Full Control)|      | (Analyze/Read)|      | (Bounded Demo)|
          +---------------+      +---------------+      +---------------+
```

---

## 2. Authentication Methods

### A. Traditional Email & Password (Argon2id)
- **Password Hasher**: Memory-hard Argon2id configured with 64MB RAM cost and 2 iterations to resist GPU-based brute-force cracking.
- **Password Complexity Validation**: Enforced via Pydantic model validators:
  - Minimum 8 characters, maximum 128 characters
  - At least 1 uppercase letter (`[A-Z]`)
  - At least 1 lowercase letter (`[a-z]`)
  - At least 1 digit (`\d`)
  - At least 1 special character (`[!@#$%^&*(),.?":{}|<>\-_+=]`)
  - Matching `password` and `confirm_password` fields
- **Timing Attack Defense**: When an unknown email address is supplied, the server performs a dummy Argon2id calculation against a pre-computed hash to ensure constant response times.
- **Rate Limiting**: In-memory sliding window limiter (`LoginRateLimiter`) blocks repeated failed attempts (default: 5 failures within 60 seconds). When tripped, returns `HTTP 429 Too Many Requests` with a `Retry-After` header.

### B. Public Self-Registration & Immediate Access Flow
- **Endpoint**: `POST /api/auth/register`
- **Role Assignment**: Automatically assigns `Demo Analyst` role. Public registration payloads attempting to specify `role` or `roles` are strictly ignored.
- **Immediate Login**: Accounts are provisioned with `is_active=True` and `is_verified=False` (not falsely represented as provider-verified).
- **No Mandatory Email Verification**: Visitors can log in immediately upon registration without depending on SMTP email delivery.
- **Rate Limiting**: `registration_rate_limiter` restricts registration to 5 attempts per minute per IP address (`HTTP 429`).
- **Activation Flow**:
  1. User registers via `/register` with full name, email, password, and password confirmation.
  2. Input fields and password complexity rules are validated via Pydantic.
  3. Password is securely hashed using Argon2id.
  4. User is created in PostgreSQL with active status and assigned the `Demo Analyst` role.
  5. The frontend displays `"Your account has been created successfully. You can now log in."` and redirects the user to `/login`.
  6. The user logs in immediately using their email and password; session cookies and CSRF tokens are established.
- **Optional Verification**: Optional token verification remains supported for visitors desiring full verification status via `POST /api/auth/verify-email`.

### C. Social Single Sign-On (Google OIDC & GitHub OAuth 2.0)
- **Google OpenID Connect**:
  - Implements **RFC 7636 PKCE (S256)**: Verifier stored in short-lived HttpOnly cookie (`itdr_pkce_verifier`).
  - Scopes: `openid email profile`. Validates Google JWT ID Token.
- **GitHub OAuth 2.0**:
  - Scopes: `read:user user:email`. Fetches primary verified email via `/user/emails`.
- **Anti-CSRF State Protection**: Tamper-proof signed state token (`provider.nonce.timestamp.hmac`) validated against cookie and signature before code exchange.
- **Public Auto-Registration**: When `ALLOW_OAUTH_AUTO_REGISTRATION=true`, unregistered social visitors are automatically provisioned as `Demo Analyst` with `is_verified=True`.
- **Existing User Linking**: Social accounts matching an existing user's verified email automatically link the external identity to the existing account.

---

## 3. Role-Based Access Control (RBAC) Matrix

Permissions are fine-grained strings mapped to roles via `role_permissions` join table:

| Permission Key | Description | Admin | Security Analyst | Viewer | Demo Analyst |
|---|---|:---:|:---:|:---:|:---:|
| `dashboard:read` | View Screen 1 Identity Resilience & Screen 3 Threat Exposure | ✅ | ✅ | ✅ | ✅ |
| `matrix:read` | View Screen 2 ITDR Coverage Matrix & TTP Details | ✅ | ✅ | ✅ | ✅ |
| `feeds:read` | View Screen 5 Bulletins & Screen 7 Completed Reports | ✅ | ✅ | ✅ | ✅ |
| `threats:read` | View Screen 4 Threat Scenarios & Persisted Analysis Reports | ✅ | ✅ | ✅ | ✅ |
| `rag:read` | View RAG Retrieval Diagnostics & Health telemetry | ✅ | ✅ | ✅ | ✅ |
| `threats:analyze`| Execute LangGraph GenAI Threat Modeling Pipeline | ✅ | ✅ | ❌ | ✅ *(5/day quota)* |
| `rag:search` | Perform raw semantic vector search over ATT&CK/D3FEND | ✅ | ✅ | ❌ | ✅ *(30/min limit)* |
| `feeds:ingest` | Ingest custom CTI bulletins and threat feeds | ✅ | ✅ | ❌ | ❌ |
| `system:status` | View backend system telemetry and database health | ✅ | ❌ | ❌ | ❌ |
| `users:manage` | Provision, update, deactivate users and view audit logs | ✅ | ❌ | ❌ | ❌ |

---

## 4. Multi-Tenant Data Isolation Architecture

To prevent public visitors from viewing each other's custom threat analysis reports and threat intelligence feeds:
- **Ownership Column**: `created_by_user_id` added to `threat_analysis_reports` and `threat_feeds`.
- **Query Scoping in `list_reports`**:
  ```python
  if not current_user.has_role("Admin"):
      query = query.filter(
          (ThreatAnalysisReport.created_by_user_id == current_user.id) |
          (ThreatAnalysisReport.created_by_user_id.is_(None)) |
          (ThreatAnalysisReport.is_demo.is_(True))
      )
  ```
- **Detail Protection in `get_report_detail`**:
  ```python
  if not current_user.has_role("Admin"):
      is_owner = (rep.created_by_user_id == current_user.id)
      is_demo_rep = (rep.created_by_user_id is None or rep.is_demo)
      if not is_owner and not is_demo_rep:
          raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
  ```
- **Query Scoping in `get_bulletins`**:
  ```python
  if not current_user.has_role("Admin"):
      query = query.filter(
          (ThreatFeed.created_by_user_id == current_user.id) |
          (ThreatFeed.created_by_user_id.is_(None)) |
          (ThreatFeed.is_demo.is_(True))
      )
  ```
- **Detail Protection in `get_bulletin_detail`**:
  ```python
  if not current_user.has_role("Admin"):
      is_owner = (b.created_by_user_id == current_user.id)
      is_shared = (b.created_by_user_id is None or b.is_demo)
      if not is_owner and not is_shared:
          raise HTTPException(status_code=404, detail=f"Bulletin {bulletin_id} not found")
  ```
- **Shared Demo Data**: Records with `is_demo=True` or `created_by_user_id IS NULL` remain visible to all authenticated analysts as shared portfolio examples.
- **Admin Visibility**: SOC Administrators bypass tenant filtering to oversee all platform reports and feeds.

---

## 5. Usage Bounds & Abuse Prevention

To protect LLM token budgets (xAI Grok) and compute resources in a public portfolio setting:
1. **Advisory Input Size**: Maximum character limit of 15,000 characters (`MAX_ADVISORY_CHARS`). Submissions exceeding this limit return `HTTP 400 Bad Request`.
2. **Emergency Kill Switch**: `PUBLIC_LLM_ANALYSIS_ENABLED` flag in `config.py`. When set to `False`, public/non-admin threat analysis requests return `HTTP 503 Service Unavailable`, instantly halting external LLM execution without taking down the platform. Administrators retain bypass capability.
3. **Global Daily Capacity Limit**: `GLOBAL_DAILY_ANALYSIS_LIMIT` (default: 100 analyses/day platform-wide). Prevents rogue botnets from exhausting platform API credits.
4. **Per-User Daily Quota & Atomic Pre-Reservation**: Non-admins are limited to 5 threat analyses per 24 hours (`DAILY_ANALYSIS_LIMIT`). Tripping the quota returns `HTTP 429 Too Many Requests` with a `Retry-After: 86400` header and records an audit log entry. To prevent concurrent requests from bypassing the quota (TOCTOU), the backend performs an **atomic pre-reservation** write to `threat_analysis_reports` with status `"Processing"` inside a database transaction *before* dispatching to LangGraph.
5. **Registration Rate Limiting**: `registration_rate_limiter` limits self-registration to 5 attempts per minute per IP address (`HTTP 429`).
6. **Email Verification Brute-Force Defense**: `verification_rate_limiter` limits verification token submissions to 10 attempts per minute per IP address (`HTTP 429`).
7. **RAG Vector Search Rate Limit**: Non-admins are limited to 30 semantic searches per minute (`HTTP 429`).
8. **Resend Email Rate Limit**: Verification email requests enforce a 60-second cooldown per address.

---

## 6. Audit Trail & Immutability

Security events recorded via `AuthService.log_audit_event`:
- `user_registered`: Self-registration recorded with assigned role
- `email_verified`: Account verification event
- `verification_email_resent`: Resend request recorded
- `login_success` / `login_failed_bad_password` / `login_rejected_unverified_email`
- `analysis_quota_exceeded`: Rate/quota breach recorded with user ID and count
- `google_user_auto_provisioned` / `github_user_auto_provisioned`: Social auto-provisioning
- `session_created` / `session_revoked` / `all_sessions_revoked`

Database-level immutability is guaranteed by trigger `trg_audit_logs_immutable` and SQLAlchemy session listeners. Any attempt to modify or delete audit log records raises a database exception.

---

## 7. Automated Test Coverage Summary

Total automated tests passing: **65 / 65 tests (100% Pass Rate)**

| Test Suite | File | Tests | Execution Time | Result |
|---|---|:---:|:---:|:---:|
| Public Registration & Social Auth | `test_public_registration_and_social.py` | 30 | ~275s | 🟢 **30/30 PASS** |
| Core Authentication & RBAC Hardening | `test_auth_rbac.py` | 29 | 196.83s | 🟢 **29/29 PASS** |
| API Regression & Business Logic | `test_api_endpoints.py` | 6 | 154.69s | 🟢 **6/6 PASS** |
| Frontend Production Build | Vite 5.4.21 | 2,386 modules | 3.98s | 🟢 **0 ERRORS** |

