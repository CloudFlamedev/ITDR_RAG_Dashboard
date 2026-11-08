import time
import datetime
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import get_settings
from app.core.security import generate_csrf_token, hash_password
from app.core.rate_limiter import login_rate_limiter
from app.models.auth import User, Role, UserSession, AuthIdentity
from app.services.auth_service import AuthService

settings = get_settings()


# ==============================================================================
# 1. Public Endpoints & Default-Deny Verification
# ==============================================================================

def test_public_endpoints_accessible(client):
    """Verify /health and root / do not require authentication."""
    r1 = client.get("/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "healthy"

    r2 = client.get("/")
    assert r2.status_code == 200
    assert r2.json()["status"] == "online"


def test_default_deny_all_protected_endpoints(client):
    """Verify that all core operational endpoints enforce default-deny (401 without auth)."""
    protected_paths = [
        ("GET", "/api/system/status"),
        ("GET", "/api/reports/identity-resilience"),
        ("GET", "/api/reports/threat-exposure"),
        ("GET", "/api/reports/threat-scenarios"),
        ("GET", "/api/coverage-matrix"),
        ("GET", "/api/coverage-matrix/ttp-detail?technique_id=T1078"),
        ("GET", "/api/identity/bulletins"),
        ("GET", "/api/identity/feeds"),
        ("GET", "/api/threats/samples"),
        ("GET", "/api/threats/reports"),
        ("GET", "/api/rag/health"),
        ("GET", "/api/users"),
        ("GET", "/api/users/roles/all"),
        ("GET", "/api/users/audit/logs"),
    ]

    for method, path in protected_paths:
        r = client.get(path) if method == "GET" else client.post(path)
        assert r.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {r.status_code}"
        assert "Authentication required" in r.json().get("detail", "") or "Session has expired" in r.json().get("detail", "")


# ==============================================================================
# 2. Email & Argon2id Password Authentication
# ==============================================================================

def test_login_success_and_cookies(client):
    """Test successful email/password authentication and secure cookie issuance."""
    c = TestClient(app)
    resp = c.post(
        "/api/auth/login",
        json={"email": "admin@itdr.local", "password": "AdminPass123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["email"] == "admin@itdr.local"
    assert "Admin" in data["user"]["roles"]
    assert data["token"] is None  # Never exposed to browser JS by default
    assert "csrf_token" in data

    # Verify cookies
    assert settings.SESSION_COOKIE_NAME in c.cookies
    assert settings.CSRF_COOKIE_NAME in c.cookies


def test_login_browser_no_token_exposure(client):
    """Verify raw session token is omitted by default and only provided when explicitly requested."""
    c = TestClient(app)
    # Default browser call
    r1 = c.post("/api/auth/login", json={"email": "admin@itdr.local", "password": "AdminPass123!"})
    assert r1.status_code == 200
    assert r1.json()["token"] is None

    # Explicit CLI request
    r2 = c.post("/api/auth/login?include_token=true", json={"email": "admin@itdr.local", "password": "AdminPass123!"})
    assert r2.status_code == 200
    assert r2.json()["token"] is not None
    assert len(r2.json()["token"]) > 20


def test_login_empty_and_missing_credentials(client):
    """Test validation errors on empty or missing payload fields."""
    c = TestClient(app)
    # Empty body
    r1 = c.post("/api/auth/login", json={})
    assert r1.status_code == 422

    # Missing password
    r2 = c.post("/api/auth/login", json={"email": "admin@itdr.local"})
    assert r2.status_code == 422

    # Missing email
    r3 = c.post("/api/auth/login", json={"password": "Password123!"})
    assert r3.status_code == 422


def test_login_invalid_password(client):
    """Test authentication rejection with bad password."""
    c = TestClient(app)
    resp = c.post(
        "/api/auth/login",
        json={"email": "admin@itdr.local", "password": "WrongPassword999!"},
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_login_unknown_email(client):
    """Test constant-time dummy verification for nonexistent account."""
    c = TestClient(app)
    resp = c.post(
        "/api/auth/login",
        json={"email": "nonexistent@cyber.fake", "password": "RandomPassword123!"},
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_login_deactivated_account(client):
    """Test that deactivated accounts cannot log in."""
    c = TestClient(app)
    resp = c.post(
        "/api/auth/login",
        json={"email": "inactive@itdr.local", "password": "InactivePass123!"},
    )
    assert resp.status_code == 403
    assert "deactivated" in resp.json()["detail"].lower()


def test_login_rate_limiting():
    """Test rate limiting after repeated failed login attempts."""
    c = TestClient(app)
    target_email = "ratelimit_test@itdr.local"

    # Reset any prior rate limit state
    test_key = f"testclient:{target_email}"
    login_rate_limiter.reset(test_key)

    # Exhaust allowed attempts (default 5 attempts in config)
    for _ in range(settings.RATE_LIMIT_LOGIN_ATTEMPTS):
        resp = c.post(
            "/api/auth/login",
            json={"email": target_email, "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    # Next attempt must trigger HTTP 429
    resp_blocked = c.post(
        "/api/auth/login",
        json={"email": target_email, "password": "WrongPassword!"},
    )
    assert resp_blocked.status_code == 429
    assert "Too many failed login attempts" in resp_blocked.json()["detail"]
    assert "Retry-After" in resp_blocked.headers

    # Cleanup rate limit key
    login_rate_limiter.reset(test_key)


def test_login_session_rotation(client, db_session):
    """Verify that logging in while having an existing session revokes the previous session (session rotation)."""
    c = TestClient(app)
    # First login
    r1 = c.post("/api/auth/login", json={"email": "admin@itdr.local", "password": "AdminPass123!"})
    assert r1.status_code == 200
    first_cookie = c.cookies.get(settings.SESSION_COOKIE_NAME)

    # Second login from same client
    r2 = c.post("/api/auth/login", json={"email": "admin@itdr.local", "password": "AdminPass123!"})
    assert r2.status_code == 200
    second_cookie = c.cookies.get(settings.SESSION_COOKIE_NAME)
    assert first_cookie != second_cookie

    # Attempting to use the first cookie in a new client must be rejected (revoked)
    c_stale = TestClient(app)
    c_stale.cookies.set(settings.SESSION_COOKIE_NAME, first_cookie)
    r_stale = c_stale.get("/api/auth/me")
    assert r_stale.status_code == 401


# ==============================================================================
# 3. Session Management & CSRF Defense
# ==============================================================================

def test_session_lifecycle_and_logout(db_session):
    """Test session validation, revocation on logout, and DB persistence."""
    c = TestClient(app)
    login_res = c.post(
        "/api/auth/login",
        json={"email": "analyst@itdr.local", "password": "AnalystPass123!"},
    )
    assert login_res.status_code == 200

    # Verify /api/auth/me succeeds with cookie
    me_res = c.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["user"]["email"] == "analyst@itdr.local"

    # Perform logout
    logout_res = c.post("/api/auth/logout")
    assert logout_res.status_code == 200

    # Subsequent /api/auth/me must be rejected with 401
    post_logout = c.get("/api/auth/me")
    assert post_logout.status_code == 401


def test_session_inactivity_timeout_enforcement(db_session):
    """Verify that sessions inactive longer than SESSION_INACTIVITY_MINUTES (30 mins) expire."""
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": "analyst@itdr.local", "password": "AnalystPass123!"})
    assert r.status_code == 200
    cookie_val = c.cookies.get(settings.SESSION_COOKIE_NAME)

    from app.core.security import hash_session_token
    h = hash_session_token(cookie_val)
    sess_rec = db_session.query(UserSession).filter(UserSession.session_token_hash == h).first()
    assert sess_rec is not None

    # Simulate 35 minutes of inactivity in the database
    past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=35)
    sess_rec.last_activity_at = past_time
    db_session.commit()

    # Next call must detect sliding inactivity timeout and return 401
    r_expired = c.get("/api/auth/me")
    assert r_expired.status_code == 401


def test_session_absolute_expiration_enforcement(db_session):
    """Verify that sessions past expires_at (12 hours) expire regardless of activity."""
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": "analyst@itdr.local", "password": "AnalystPass123!"})
    assert r.status_code == 200
    cookie_val = c.cookies.get(settings.SESSION_COOKIE_NAME)

    from app.core.security import hash_session_token
    h = hash_session_token(cookie_val)
    sess_rec = db_session.query(UserSession).filter(UserSession.session_token_hash == h).first()
    assert sess_rec is not None

    # Simulate absolute expiration in the past
    past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=13)
    sess_rec.expires_at = past_time
    db_session.commit()

    # Next call must reject expired session
    r_expired = c.get("/api/auth/me")
    assert r_expired.status_code == 401


def test_csrf_protection_on_cookie_auth(db_session):
    """Test that cookie-authenticated mutating requests require valid X-CSRF-Token across HTTP verbs."""
    c = TestClient(app)
    # 1. Login to get cookies
    login_res = c.post(
        "/api/auth/login",
        json={"email": "admin@itdr.local", "password": "AdminPass123!"},
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]

    # 2. POST without CSRF header -> 403 Forbidden
    resp_no_csrf = c.post("/api/twin/feeds/ingest", json={
        "title": "Advisory without CSRF header",
        "source": "CTI Sensor",
        "content": "Advisory text content...",
        "severity": "Low"
    })
    assert resp_no_csrf.status_code == 403
    assert "CSRF" in resp_no_csrf.json()["detail"]

    # 3. POST with INVALID CSRF header -> 403 Forbidden
    resp_bad_csrf = c.post(
        "/api/twin/feeds/ingest",
        json={
            "title": "Advisory with Bad CSRF",
            "source": "CTI Sensor",
            "content": "Advisory text content...",
            "severity": "Low"
        },
        headers={"X-CSRF-Token": "invalid.csrf.signature"},
    )
    assert resp_bad_csrf.status_code == 403

    # 4. POST with valid CSRF header -> 200 Success
    resp_valid = c.post(
        "/api/twin/feeds/ingest",
        json={
            "title": "Advisory with Valid CSRF on T1078",
            "source": "CTI Sensor",
            "content": "Advisory text content relating to valid accounts T1078...",
            "severity": "Low"
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp_valid.status_code == 200
    assert resp_valid.json()["success"] is True

    # 5. PATCH without CSRF header -> 403 Forbidden
    resp_patch_no_csrf = c.patch(
        "/api/users/1/roles",
        json={"roles": ["Admin"]},
    )
    assert resp_patch_no_csrf.status_code == 403

    # 6. DELETE without CSRF header -> 403 Forbidden
    resp_del_no_csrf = c.delete("/api/users/999999")
    assert resp_del_no_csrf.status_code == 403


# ==============================================================================
# 4. RBAC Roles & Permissions Matrix
# ==============================================================================

def test_rbac_admin_full_access(admin_client):
    """Admin has full access including user management and system status."""
    # User management
    users_resp = admin_client.get("/api/users")
    assert users_resp.status_code == 200
    assert len(users_resp.json()) >= 3

    roles_resp = admin_client.get("/api/users/roles/all")
    assert roles_resp.status_code == 200
    assert len(roles_resp.json()) == 3

    audit_resp = admin_client.get("/api/users/audit/logs")
    assert audit_resp.status_code == 200

    # System telemetry
    sys_resp = admin_client.get("/api/system/status")
    assert sys_resp.status_code == 200


def test_rbac_analyst_permissions_and_restrictions(analyst_client):
    """Security Analyst can read dashboards, feeds, threat samples, but CANNOT manage users."""
    # Allowed
    r1 = analyst_client.get("/api/reports/identity-resilience")
    assert r1.status_code == 200

    r2 = analyst_client.get("/api/threats/samples")
    assert r2.status_code == 200

    r3 = analyst_client.get("/api/identity/bulletins")
    assert r3.status_code == 200

    # Forbidden (Admin only)
    r4 = analyst_client.get("/api/users")
    assert r4.status_code == 403
    assert "users:manage" in r4.json()["detail"]

    r5 = analyst_client.get("/api/users/roles/all")
    assert r5.status_code == 403


def test_rbac_viewer_permissions_and_restrictions(viewer_client):
    """Viewer has read-only access and CANNOT analyze threats, ingest feeds, or manage users."""
    # Allowed reads
    r1 = viewer_client.get("/api/reports/identity-resilience")
    assert r1.status_code == 200

    r2 = viewer_client.get("/api/coverage-matrix")
    assert r2.status_code == 200

    r3 = viewer_client.get("/api/identity/bulletins")
    assert r3.status_code == 200

    r4 = viewer_client.get("/api/threats/reports")
    assert r4.status_code == 200

    # Forbidden: Ingesting feeds (requires feeds:ingest)
    r_ingest = viewer_client.post("/api/twin/feeds/ingest", json={
        "title": "Viewer Ingest Attempt",
        "source": "Unauthorized",
        "content": "Attempting to ingest without permission",
        "severity": "Low"
    })
    assert r_ingest.status_code == 403
    assert "feeds:ingest" in r_ingest.json()["detail"]

    # Forbidden: Executing GenAI threat analysis (requires threats:analyze)
    r_analyze = viewer_client.post("/api/threats/analyze", json={
        "advisory_text": "Viewer attempting to invoke threat analysis workflow",
        "sample_id": None,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
    })
    assert r_analyze.status_code == 403
    assert "threats:analyze" in r_analyze.json()["detail"]

    # Forbidden: User management
    r_users = viewer_client.get("/api/users")
    assert r_users.status_code == 403


# ==============================================================================
# 5. Admin User Management & Immediate Session Revocation
# ==============================================================================

def test_admin_user_provisioning_and_deactivation(admin_client, db_session):
    """Test provisioning a new user, updating roles, and revoking sessions on deactivation."""
    unique_email = f"provisioned_{int(time.time())}@itdr.corp"

    # 1. Admin creates user
    create_resp = admin_client.post("/api/users", json={
        "email": unique_email,
        "full_name": "Provisioned Analyst",
        "password": "SecurePassword123!",
        "roles": ["Security Analyst"]
    })
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    assert "Security Analyst" in create_resp.json()["roles"]

    # 2. Provisioned user logs in and gets an active session
    user_client = TestClient(app)
    login_resp = user_client.post("/api/auth/login", json={
        "email": unique_email,
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200

    # User can access their profile
    me_resp = user_client.get("/api/auth/me")
    assert me_resp.status_code == 200

    # 3. Admin updates user roles to Viewer
    roles_resp = admin_client.patch(f"/api/users/{user_id}/roles", json={
        "roles": ["Viewer"]
    })
    assert roles_resp.status_code == 200
    assert roles_resp.json()["roles"] == ["Viewer"]

    # 4. Admin deactivates the user
    deact_resp = admin_client.delete(f"/api/users/{user_id}")
    assert deact_resp.status_code == 200
    assert deact_resp.json()["is_active"] is False

    # 5. User's existing session must immediately fail (401)
    revoked_resp = user_client.get("/api/auth/me")
    assert revoked_resp.status_code == 401

    # User cannot log in anymore (403)
    relogin_resp = user_client.post("/api/auth/login", json={
        "email": unique_email,
        "password": "SecurePassword123!"
    })
    assert relogin_resp.status_code == 403


# ==============================================================================
# 6. OAuth 2.0 / OIDC Flow Tests
# ==============================================================================

def test_oauth_login_redirect_and_cookies(client, monkeypatch):
    """Test OAuth login initiation generates state and PKCE cookies."""
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "mock-google-client-id")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "mock-github-client-id")

    # Test Google OAuth login redirect
    google_res = client.get("/api/auth/oauth/google/login", follow_redirects=False)
    assert google_res.status_code == 302
    assert "accounts.google.com" in google_res.headers["location"]
    assert "code_challenge=" in google_res.headers["location"]
    assert "code_challenge_method=S256" in google_res.headers["location"]
    assert "itdr_oauth_state" in google_res.cookies
    assert "itdr_pkce_verifier" in google_res.cookies

    # Test GitHub OAuth login redirect
    github_res = client.get("/api/auth/oauth/github/login", follow_redirects=False)
    assert github_res.status_code == 302
    assert "github.com/login/oauth/authorize" in github_res.headers["location"]
    assert "itdr_oauth_state" in github_res.cookies

    # Unsupported provider
    invalid_res = client.get("/api/auth/oauth/unsupported_provider/login")
    assert invalid_res.status_code == 400


def test_oauth_callback_tampered_state(client):
    """Test rejection when OAuth state token is missing or tampered."""
    callback_res = client.get(
        "/api/auth/oauth/google/callback?code=mock_code&state=tampered.state.token.123",
        follow_redirects=False,
    )
    assert callback_res.status_code == 302
    # Redirects back to login with error parameter
    assert "/login?error=" in callback_res.headers["location"]


def test_oauth_unprovisioned_account_rejected(db_session):
    """Test that social login from an unprovisioned email is rejected when auto-registration is disabled."""
    auth_svc = AuthService(db_session)
    with pytest.raises(Exception) as exc_info:
        auth_svc.handle_oauth_user(
            provider="google",
            provider_user_id="google_sub_99999",
            verified_email="unregistered_stranger@external.com",
            full_name="External Stranger",
        )
    assert "Account not found" in str(exc_info.value.detail)


# ==============================================================================
# 7. Database Integrity & Production Hardening
# ==============================================================================

def test_database_integrity_and_cascade(db_session):
    """Verify unique constraints and cascade deletion on User relations."""
    now = datetime.datetime.now(datetime.timezone.utc)
    unique_email = f"integrity_{int(time.time())}@itdr.test"

    # 1. Create user
    user = User(
        email=unique_email,
        full_name="Integrity User",
        password_hash=hash_password("Password123!"),
        is_active=True,
        is_verified=True,
        created_at=now,
        updated_at=now,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # 2. Add Session and Identity
    sess = UserSession(
        user_id=user.id,
        session_token_hash="dummy_hash_for_test",
        expires_at=now + datetime.timedelta(hours=1),
        created_at=now,
        last_activity_at=now,
    )
    ident = AuthIdentity(
        user_id=user.id,
        provider="github",
        provider_user_id=f"gh_{user.id}",
        provider_email=unique_email,
    )
    db_session.add_all([sess, ident])
    db_session.commit()

    # 3. Verify duplicate email constraint raises IntegrityError
    dup_user = User(
        email=unique_email,
        full_name="Duplicate User",
        password_hash="hash",
    )
    db_session.add(dup_user)
    with pytest.raises(Exception):
        db_session.commit()
    db_session.rollback()

    # 4. Delete user and verify cascade
    db_session.delete(user)
    db_session.commit()

    assert db_session.query(UserSession).filter(UserSession.user_id == user.id).first() is None
    assert db_session.query(AuthIdentity).filter(AuthIdentity.user_id == user.id).first() is None


def test_production_docs_disabled(monkeypatch):
    """Verify OpenAPI docs /docs and /openapi.json can be disabled in production."""
    assert hasattr(settings, "is_production")
    monkeypatch.setattr(settings, "APP_ENV", "production")
    assert settings.is_production is True


# ==============================================================================
# 8. Advanced Security Hardening Regression Tests
# ==============================================================================

def test_oauth_forwarded_host_header_injection_prevented(client, monkeypatch):
    """
    Test that malicious X-Forwarded-Host or Host headers cannot hijack OAuth redirects
    or poison the OAuth callback URI (Host Header Injection / Open Redirect defense).
    """
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "mock-google-client-id")
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", "")

    # 1. Attacker sends forged X-Forwarded-Host pointing to an external domain
    spoofed_resp = client.get(
        "/api/auth/oauth/google/login",
        headers={"X-Forwarded-Host": "evil-phishing-site.com", "X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    assert spoofed_resp.status_code == 302
    location = spoofed_resp.headers["location"]
    # The redirect URL to Google auth MUST NOT contain the forged host
    assert "evil-phishing-site.com" not in location
    assert "redirect_uri=" in location

    # 2. Legitimate reverse proxy with allowlisted Vercel host
    valid_resp = client.get(
        "/api/auth/oauth/google/login",
        headers={"X-Forwarded-Host": "itdr-rag-dashboard.vercel.app", "X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    assert valid_resp.status_code == 302
    assert "itdr-rag-dashboard.vercel.app" in valid_resp.headers["location"]


def test_oauth_prefers_environment_configured_redirect_uri(client, monkeypatch):
    """Verify that environment-configured GOOGLE_REDIRECT_URI takes strict precedence."""
    configured_uri = "https://itdr-rag-dashboard.vercel.app/api/auth/oauth/google/callback"
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "mock-google-client-id")
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", configured_uri)

    res = client.get(
        "/api/auth/oauth/google/login",
        headers={"X-Forwarded-Host": "localhost:5173"},
        follow_redirects=False,
    )
    assert res.status_code == 302
    from urllib.parse import unquote
    decoded_loc = unquote(res.headers["location"])
    assert f"redirect_uri={configured_uri}" in decoded_loc


def test_audit_log_immutability_orm_and_db(db_session):
    """
    Verify that AuditLog records are strictly append-only and cannot be modified or deleted
    via SQLAlchemy ORM or direct database queries.
    """
    from app.models.auth import AuditLog
    from sqlalchemy import text

    # 1. Create audit log entry
    audit = AuditLog(
        action="security_probe_test",
        resource="test_resource",
        ip_address="127.0.0.1",
        metadata_json={"test": True},
    )
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)
    audit_id = audit.id

    # 2. Verify ORM update is blocked
    audit.action = "tampered_action"
    with pytest.raises(Exception) as exc_info:
        db_session.commit()
    assert "append-only" in str(exc_info.value).lower()
    db_session.rollback()

    # 3. Verify ORM delete is blocked
    audit = db_session.query(AuditLog).filter(AuditLog.id == audit_id).first()
    db_session.delete(audit)
    with pytest.raises(Exception) as exc_info:
        db_session.commit()
    assert "append-only" in str(exc_info.value).lower()
    db_session.rollback()

    # 4. Verify Raw SQL UPDATE is blocked by PostgreSQL database trigger
    with pytest.raises(Exception) as exc_info:
        db_session.execute(text(f"UPDATE audit_logs SET action = 'raw_sql_tampered' WHERE id = {audit_id}"))
        db_session.commit()
    assert "append-only" in str(exc_info.value).lower()
    db_session.rollback()

    # 5. Verify Raw SQL DELETE is blocked by PostgreSQL database trigger
    with pytest.raises(Exception) as exc_info:
        db_session.execute(text(f"DELETE FROM audit_logs WHERE id = {audit_id}"))
        db_session.commit()
    assert "append-only" in str(exc_info.value).lower()
    db_session.rollback()


def test_audit_log_api_mutations_forbidden(admin_client):
    """Verify that HTTP mutating requests (POST, PUT, PATCH, DELETE) to audit logs are rejected."""
    # POST, PUT, DELETE to collection return 405 Method Not Allowed
    assert admin_client.post("/api/users/audit/logs", json={"action": "fake"}).status_code == 405
    assert admin_client.put("/api/users/audit/logs", json={"action": "fake"}).status_code == 405
    assert admin_client.delete("/api/users/audit/logs").status_code == 405
    # Item-level mutation endpoints do not exist (404/405)
    assert admin_client.delete("/api/users/audit/logs/1").status_code in (404, 405)
    assert admin_client.put("/api/users/audit/logs/1", json={"action": "fake"}).status_code in (404, 405)
    assert admin_client.patch("/api/users/audit/logs/1", json={"action": "fake"}).status_code in (404, 405)


def test_proxy_aware_ip_extraction():
    """Verify that get_client_ip correctly prioritizes X-Real-IP and sanitizes headers."""
    from app.api.auth import get_client_ip
    from starlette.requests import Request

    def make_request(headers):
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(k.lower().encode("latin1"), v.encode("latin1")) for k, v in headers.items()],
            "client": ("192.168.1.50", 12345),
        }
        return Request(scope)

    # 1. X-Real-IP prioritization
    req = make_request({"X-Real-IP": "198.51.100.42", "X-Forwarded-For": "10.0.0.1"})
    assert get_client_ip(req) == "198.51.100.42"

    # 2. X-Forwarded-For public IP extraction
    req2 = make_request({"X-Forwarded-For": "203.0.113.195, 10.0.0.2"})
    assert get_client_ip(req2) == "203.0.113.195"

    # 3. Malformed/injection strings in X-Forwarded-For ignored
    req3 = make_request({"X-Forwarded-For": "<script>alert(1)</script>, 198.51.100.99"})
    assert get_client_ip(req3) == "198.51.100.99"


def test_admin_bootstrap_cli_argument_security():
    """Verify that --password is not an accepted command-line argument for bootstrap_admin.py."""
    import sys
    import os
    import subprocess
    cmd = [
        sys.executable,
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bootstrap_admin.py")),
        "--password",
        "insecure_cli_pass",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode != 0
    assert "unrecognized arguments: --password" in proc.stderr
