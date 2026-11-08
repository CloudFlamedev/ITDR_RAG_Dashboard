# ITDR Platform — Authentication & Authorization (RBAC) Architecture

This document details the enterprise security model, session management, Role-Based Access Control (RBAC), OAuth 2.0 / OpenID Connect flows, and administrative provisioning implemented in the **Identity Threat Detection & Response (ITDR) Platform**.

---

## 1. High-Level Security Architecture

The ITDR platform implements a **defense-in-depth, zero-trust security perimeter**:
- **Default-Deny Access Policy**: All API endpoints (except `/health` and `/`) require cryptographic authentication and RBAC authorization.
- **Server-Managed Session Store**: Stateful sessions persisted in Neon PostgreSQL (`user_sessions` table). Session identifiers transmitted in `HttpOnly`, `Secure`, `SameSite=Lax` cookies; only their SHA-256 hashes are stored in the database.
- **Argon2id Password Hashing**: Passwords hashed using standard Argon2id parameters (`m=65536`, `t=2`, `p=2`), with constant-time verification against timing attacks.
- **OAuth 2.0 & OIDC**: Social single sign-on with Google (OpenID Connect with RFC 7636 PKCE S256) and GitHub OAuth 2.0 with verified primary email enforcement.
- **Account Linking & Provisioning**: Strict anti-account takeover rules. Self-registration is disabled; new accounts must be provisioned by a SOC Administrator.
- **HMAC CSRF Defense**: Double-submit cookie + signed HMAC-SHA256 CSRF tokens required on all state-changing HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Sliding Inactivity & Absolute Expiration**: Sessions automatically terminate after 30 minutes of inactivity or 12 hours absolute maximum age.

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
          |     Admin     |      |Sec. Analyst   |      |    Viewer     |
          | (Full Control)|      | (Analyze/Read)|      |  (Read-Only)  |
          +---------------+      +---------------+      +---------------+
```

---

## 2. Authentication Methods

### A. Traditional Email & Password (Argon2id)
- **Password Hasher**: Memory-hard Argon2id configured with 64MB RAM cost and 2 iterations to resist GPU-based brute-force cracking.
- **Timing Attack Defense**: When an unknown email address is supplied, the server performs a dummy Argon2id calculation against a pre-computed hash to ensure constant response times.
- **Rate Limiting**: In-memory sliding window limiter (`LoginRateLimiter`) blocks repeated failed attempts (default: 5 failures within 15 minutes). When tripped, returns `HTTP 429 Too Many Requests` with a `Retry-After` header.

### B. Social Login (Google OIDC & GitHub OAuth 2.0)
- **Google OIDC with PKCE (RFC 7636)**:
  - Generates 32-byte URL-safe `code_verifier` and derives `code_challenge` using SHA-256 (`S256`).
  - Exchanges authorization code for Google ID token.
  - Verifies Google's cryptographic RSA signature dynamically using Google's public JWKS certificates (`https://www.googleapis.com/oauth2/v3/certs`), matching `iss`, `aud`, expiration, and verified email status.
- **GitHub OAuth 2.0**:
  - Exchanges authorization code for access token.
  - Directly queries GitHub's `/user` and `/user/emails` endpoints to resolve the user's verified primary email.
- **Anti-CSRF State Parameter**:
  - State token format: `provider.nonce.timestamp.hmac`.
  - Cryptographically signed with `SESSION_SECRET_KEY` and cached in a short-lived cookie (`itdr_oauth_state`). Mismatched or expired state parameters are rejected immediately.

### C. Account Linking Rules
1. **Self-Registration Disabled**: When an unknown identity signs in via Google or GitHub, the system verifies `ALLOW_OAUTH_AUTO_REGISTRATION`. When `False` (enterprise default), login is rejected with `HTTP 403 Forbidden` directing the user to contact their SOC administrator.
2. **Deterministic Email Match**: If an administrator has provisioned an account for `analyst@enterprise.corp`, a subsequent verified Google/GitHub login for that exact verified email address automatically links the provider identity (`AuthIdentity` record).
3. **No Unverified Emails**: Email addresses flagged as unverified by Google or GitHub are discarded and rejected.

---

## 3. Session Management

Sessions are managed server-side and persisted in the PostgreSQL `user_sessions` table:

| Column | Type | Description |
|---|---|---|
| `id` | `UUID` | Unique session identifier (used to key CSRF tokens). |
| `user_id` | `Integer` | Foreign key referencing `users.id`. |
| `session_token_hash` | `String(64)` | Deterministic SHA-256 hash of the 43-character URL-safe raw token. |
| `created_at` | `DateTime` | Session creation timestamp. |
| `last_activity_at` | `DateTime` | Sliding activity marker (sliding inactivity window: 30 minutes). |
| `expires_at` | `DateTime` | Absolute expiration timestamp (default: 720 minutes / 12 hours). |
| `revoked_at` | `DateTime` | Revocation timestamp populated on logout or account deactivation. |
| `ip_address` | `String(45)` | Client IP address for audit and geolocation detection. |
| `user_agent` | `String(500)` | Client browser User-Agent telemetry. |

### Cookie Attributes
- `Name`: `itdr_session`
- `HttpOnly`: `True` (prevents XSS token exfiltration)
- `Secure`: `True` in production HTTPS environments
- `SameSite`: `Lax` (protects against cross-site request forgery while preserving top-level navigation)
- `Path`: `/`

---

## 4. Role-Based Access Control (RBAC)

The platform supports 3 primary roles and 10 granular permissions:

| Permission Key | Description | Admin | Security Analyst | Viewer |
|---|---|:---:|:---:|:---:|
| `dashboard:read` | View Identity Resilience Overview & Posture Reports | ✅ | ✅ | ✅ |
| `matrix:read` | Inspect ITDR Coverage Matrix & TTP Drawer | ✅ | ✅ | ✅ |
| `feeds:read` | View Threat Feeds & Ingested CTI Bulletins | ✅ | ✅ | ✅ |
| `threats:read` | Access Threat Samples & View Completed Reports | ✅ | ✅ | ✅ |
| `rag:read` | Read-only access to RAG knowledge base & health | ✅ | ✅ | ✅ |
| `threats:analyze` | Execute 11-node LangGraph GenAI Threat Modeling workflow | ✅ | ✅ | ❌ |
| `feeds:ingest` | Ingest external CTI advisories & custom threat feeds | ✅ | ✅ | ❌ |
| `rag:search` | Perform dense vector / hybrid semantic searches | ✅ | ✅ | ❌ |
| `system:status` | Access full subsystem health telemetry (Neon, pgvector, Grok) | ✅ | ❌ | ❌ |
| `users:manage` | Provision, deactivate, update roles, and review audit logs | ✅ | ❌ | ❌ |

---

## 5. Administrative Provisioning & Bootstrap CLI

### Bootstrapping the Initial Administrator
To provision or promote the initial Administrator account (passwords are securely prompted via masked input):
```bash
# In backend virtualenv
PYTHONPATH=backend python backend/scripts/bootstrap_admin.py \
  --email "admin@enterprise.corp" \
  --name "Lead SOC Administrator"
```
Or in headless CI/CD automation:
```bash
ADMIN_INITIAL_PASSWORD="GenerateStrongPassword123!" \
PYTHONPATH=backend python backend/scripts/bootstrap_admin.py \
  --email "admin@enterprise.corp" \
  --name "Lead SOC Administrator"
```

### Administrative Endpoints
- `GET /api/users`: Search and list provisioned users.
- `POST /api/users`: Provision a new user account with Argon2id password.
- `GET /api/users/{id}`: Inspect user account details.
- `PATCH /api/users/{id}`: Update name, password, or active status.
- `PATCH /api/users/{id}/roles`: Assign or update user roles.
- `DELETE /api/users/{id}`: Deactivate user and immediately revoke all active sessions.
- `GET /api/users/roles/all`: List available system roles and permissions.
- `GET /api/users/audit/logs`: Filter and inspect immutable security audit events (read-only; mutating HTTP methods return HTTP 405).

---

## 6. Immutable Security Audit Logging

Audit logs are strictly **append-only** and tamper-proof:
- **Database Trigger**: PostgreSQL trigger `trg_audit_logs_immutable` enforces append-only rules at the database engine level, rejecting any `UPDATE` or `DELETE` statements.
- **ORM Event Listeners**: SQLAlchemy event listeners prevent modifications or deletions before flush.
- **API Guardrails**: The `/api/users/audit/logs` endpoint only implements `GET`. `POST`, `PUT`, `PATCH`, and `DELETE` requests are rejected with `HTTP 405 Method Not Allowed`.
- Recorded security events include:
  - `login_success`, `login_failed_bad_password`, `login_failed_unknown_user`, `login_throttled`
  - `session_created`, `session_revoked`, `all_sessions_revoked`
  - `user_created`, `user_updated`, `user_roles_updated`, `user_deactivated`
  - `google_login_success`, `github_login_success`, `google_account_linked`, `github_account_linked`

---

## 7. Configuration Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SESSION_SECRET_KEY` | *(Generated random 32-byte secret)* | Signs CSRF tokens and OAuth state tokens. |
| `SESSION_EXPIRE_MINUTES` | `720` (12 hours) | Absolute session expiration limit. |
| `SESSION_INACTIVITY_MINUTES` | `30` (30 mins) | Sliding inactivity timeout limit. |
| `SESSION_COOKIE_NAME` | `itdr_session` | Name of the session cookie. |
| `CSRF_COOKIE_NAME` | `itdr_csrf` | Name of the CSRF token cookie. |
| `SESSION_COOKIE_SECURE` | `False` (dev) / `True` (prod) | Requires HTTPS for cookies. |
| `SESSION_COOKIE_SAMESITE` | `lax` | SameSite cookie policy. |
| `CORS_ORIGIN_WHITELIST` | `http://localhost:5173,...` | Allowed frontend origins (no wildcards allowed). |
| `RATE_LIMIT_LOGIN_ATTEMPTS` | `5` | Maximum failed attempts allowed in window. |
| `RATE_LIMIT_WINDOW_SECONDS` | `900` (15 mins) | Sliding rate-limiting window duration. |
| `ALLOW_OAUTH_AUTO_REGISTRATION` | `False` | Whether unknown social logins can auto-create Viewer accounts. |
| `GOOGLE_CLIENT_ID` | `""` | Google Cloud OAuth Client ID. |
| `GOOGLE_CLIENT_SECRET` | `""` | Google Cloud OAuth Client Secret. |
| `GOOGLE_REDIRECT_URI` | `http://localhost:8000/api/auth/oauth/google/callback` | Exact registered Google callback URI. |
| `GITHUB_CLIENT_ID` | `""` | GitHub OAuth App Client ID. |
| `GITHUB_CLIENT_SECRET` | `""` | GitHub OAuth App Client Secret. |
| `GITHUB_REDIRECT_URI` | `http://localhost:8000/api/auth/oauth/github/callback` | Exact registered GitHub callback URI. |
