# ITDR Platform — API Security Matrix

This document provides a comprehensive inventory of all endpoints registered in the **ITDR Platform API**, their security classification, required RBAC roles/permissions, CSRF enforcement, and authentication mechanisms.

---

## 1. Classification Definitions

| Classification | Meaning |
|---|---|
| **Public** | Unrestricted access without authentication cookies or tokens. Reserved for container liveness and initial OAuth handshakes. |
| **Authenticated** | Requires a valid, active server-side session (`itdr_session` cookie or `Authorization: Bearer <token>`). |
| **Permission-Restricted** | Requires an authenticated session whose user account holds the specific granular RBAC permission (or the `Admin` role). |

---

## 2. API Endpoint Inventory

| HTTP Method | Endpoint Route | Security Classification | Required Role / Permission | CSRF Defense | Description & Security Notes |
|:---:|:---|:---:|:---:|:---:|:---|
| `GET` | `/` | **Public** | None | N/A | Service discovery and API root metadata. |
| `GET` | `/health` | **Public** | None | N/A | High-frequency container orchestrator liveness probe. Intentionally unauthenticated. |
| `GET` | `/docs` | **Environment Gated** | None (Dev only) | N/A | Swagger UI documentation. **Disabled in production** (`APP_ENV=production`). |
| `GET` | `/redoc` | **Environment Gated** | None (Dev only) | N/A | ReDoc UI documentation. **Disabled in production** (`APP_ENV=production`). |
| `GET` | `/openapi.json` | **Environment Gated** | None (Dev only) | N/A | OpenAPI JSON schema discovery. **Disabled in production** (`APP_ENV=production`). |
| `POST` | `/api/auth/login` | **Public** | None | N/A | Email + Argon2id password login. Issues HttpOnly session cookie. Rate-limited (sliding window). |
| `POST` | `/api/auth/logout` | **Authenticated** | Any valid session | Exempt | Revokes active session in PostgreSQL and clears cookies. |
| `GET` | `/api/auth/me` | **Authenticated** | Any valid session | Exempt | Returns authenticated user profile, roles, and fresh CSRF token. |
| `GET` | `/api/auth/csrf` | **Authenticated** | Any valid session | Exempt | Generates/refreshes HMAC-SHA256 CSRF token for the session. |
| `GET` | `/api/auth/oauth/{provider}/login` | **Public** | None | N/A | Initiates OAuth code flow with signed state cookie and PKCE S256 code challenge. |
| `GET` | `/api/auth/oauth/{provider}/callback` | **Public** | None | N/A | Validates OAuth state, exchanges code with Google/GitHub, matches verified email, and establishes session. |
| `GET` | `/api/system/status` | **Permission-Restricted** | `system:status` (Admin) | Exempt | Multi-subsystem telemetry (Neon latency, pgvector status, Grok/HF readiness, index volume). |
| `GET` | `/api/reports/identity-resilience` | **Permission-Restricted** | `dashboard:read` | Exempt | Screen 1: Coverage ring, tactic exposure bars, and resilience quadrant data. |
| `GET` | `/api/reports/threat-exposure` | **Permission-Restricted** | `dashboard:read` | Exempt | Screen 3: Sighted TTP metrics and phase groupings. |
| `GET` | `/api/reports/threat-scenarios` | **Permission-Restricted** | `dashboard:read` | Exempt | Screen 4: 2D detection vs. mitigation quadrant data. |
| `GET` | `/api/coverage-matrix` | **Permission-Restricted** | `matrix:read` | Exempt | Screen 2: ITDR coverage matrix, tool toggles, and tactic columns. |
| `GET` | `/api/coverage-matrix/ttp-detail` | **Permission-Restricted** | `matrix:read` | Exempt | Screen 2: Detailed drawer modal with mapped rules and D3FEND countermeasures. |
| `GET` | `/api/identity/bulletins` | **Permission-Restricted** | `feeds:read` | Exempt | Screen 5: Searchable CTI bulletins and ingested advisories. |
| `GET` | `/api/identity/feeds` | **Permission-Restricted** | `feeds:read` | Exempt | Screen 5: Active feed connectors telemetry. |
| `POST` | `/api/twin/feeds/ingest` | **Permission-Restricted** | `feeds:ingest` (Admin, Analyst) | **Enforced** (`X-CSRF-Token`) | Screen 5: Ingest custom threat bulletin. Enforces strict SSRF validation and regex TTP extraction. |
| `GET` | `/api/threats/samples` | **Permission-Restricted** | `threats:read` | Exempt | Screen 6: Pre-loaded curated threat intelligence samples. |
| `POST` | `/api/threats/analyze` | **Permission-Restricted** | `threats:analyze` (Admin, Analyst) | **Enforced** (`X-CSRF-Token`) | Screen 6: Executes 11-node LangGraph GenAI threat modeling workflow. **Forbidden to Viewers**. |
| `GET` | `/api/threats/reports` | **Permission-Restricted** | `threats:read` | Exempt | Screen 7: Completed threat intelligence reports list. |
| `GET` | `/api/threats/reports/{report_id}` | **Permission-Restricted** | `threats:read` | Exempt | Screen 7: Detailed threat report with grounded citations and execution trace steps. |
| `POST` | `/api/rag/search` | **Permission-Restricted** | `rag:search` (Admin, Analyst) | Exempt / Body | Direct hybrid vector retrieval against PostgreSQL `rag_documents`. |
| `GET` | `/api/rag/health` | **Permission-Restricted** | `rag:read` | Exempt | RAG pipeline diagnostics, embedding connectivity, and vector index health. |
| `GET` | `/api/users` | **Permission-Restricted** | `users:manage` (Admin) | Exempt | Admin user management: list provisioned identities with roles and status. |
| `POST` | `/api/users` | **Permission-Restricted** | `users:manage` (Admin) | **Enforced** (`X-CSRF-Token`) | Admin user provisioning: creates user with Argon2id password hash and assigned roles. |
| `GET` | `/api/users/{user_id}` | **Permission-Restricted** | `users:manage` (Admin) | Exempt | Inspect individual user account details. |
| `PATCH` | `/api/users/{user_id}` | **Permission-Restricted** | `users:manage` (Admin) | **Enforced** (`X-CSRF-Token`) | Update user profile, password, or active status. Deactivating revokes all user sessions. |
| `PATCH` | `/api/users/{user_id}/roles` | **Permission-Restricted** | `users:manage` (Admin) | **Enforced** (`X-CSRF-Token`) | Update assigned RBAC roles for a user. |
| `DELETE` | `/api/users/{user_id}` | **Permission-Restricted** | `users:manage` (Admin) | **Enforced** (`X-CSRF-Token`) | Soft deactivation: revokes all user sessions and flags account inactive. |
| `GET` | `/api/users/roles/all` | **Permission-Restricted** | `users:manage` (Admin) | Exempt | List system roles and their assigned permissions. |
| `GET` | `/api/users/audit/logs` | **Permission-Restricted** | `users:manage` (Admin) | Exempt | Inspect immutable security audit trail logs. |

---

## 3. RBAC Role Access by HTTP Route Category

| Route Category | Admin | Security Analyst | Viewer |
|:---|:---:|:---:|:---:|
| **Public Endpoints** (`/`, `/health`, `/api/auth/login`, OAuth flows) | ✅ | ✅ | ✅ |
| **Session Operations** (`/api/auth/me`, `/api/auth/logout`, `/api/auth/csrf`) | ✅ | ✅ | ✅ |
| **Posture Dashboards** (`/api/reports/*`, `/api/coverage-matrix*`) | ✅ | ✅ | ✅ |
| **Intelligence Feeds (Read)** (`/api/identity/bulletins`, `/api/identity/feeds`) | ✅ | ✅ | ✅ |
| **Threat Reports (Read)** (`/api/threats/reports*`, `/api/threats/samples`) | ✅ | ✅ | ✅ |
| **RAG Knowledge Base (Read)** (`/api/rag/health`) | ✅ | ✅ | ✅ |
| **CTI Ingestion** (`/api/twin/feeds/ingest`) | ✅ | ✅ | ❌ *(403 Forbidden)* |
| **GenAI Threat Analysis** (`/api/threats/analyze`) | ✅ | ✅ | ❌ *(403 Forbidden)* |
| **RAG Semantic Search** (`/api/rag/search`) | ✅ | ✅ | ❌ *(403 Forbidden)* |
| **System Telemetry** (`/api/system/status`) | ✅ | ❌ *(403 Forbidden)* | ❌ *(403 Forbidden)* |
| **User Administration & Audit** (`/api/users*`) | ✅ | ❌ *(403 Forbidden)* | ❌ *(403 Forbidden)* |

---

## 4. CSRF Protection Enforcement Rules

- **Exempt Methods**: Safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) do not modify state and are exempt.
- **Enforced Methods**: Mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) authenticated via browser cookies require the `X-CSRF-Token` header.
- **Signature Verification**: CSRF tokens are signed with `SESSION_SECRET_KEY` using HMAC-SHA256 and tied to the active `session_id`. Tokens are expired after 24 hours.
- **Bearer Token Bypass**: Non-browser API clients authenticating via explicit `Authorization: Bearer <token>` headers are exempt from CSRF checks as they are not vulnerable to browser ambient-credential CSRF attacks.
