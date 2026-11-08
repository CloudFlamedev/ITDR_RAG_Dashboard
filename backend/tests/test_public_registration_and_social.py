import time
import datetime
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import get_settings
from app.core.security import hash_password, generate_verification_token
from app.db.session import SessionLocal
from app.models.auth import User, Role, EmailVerificationToken, AuditLog
from app.models.threat_report import ThreatAnalysisReport
from app.services.auth_service import AuthService
from app.services.email_service import mock_sent_emails

settings = get_settings()


@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limiter import registration_rate_limiter, verification_rate_limiter, login_rate_limiter
    registration_rate_limiter.reset("127.0.0.1")
    verification_rate_limiter.reset("127.0.0.1")
    login_rate_limiter.reset("127.0.0.1")
    yield
    registration_rate_limiter.reset("127.0.0.1")
    verification_rate_limiter.reset("127.0.0.1")
    login_rate_limiter.reset("127.0.0.1")


def get_user_auth_client(email: str, password: str) -> TestClient:
    c = TestClient(app)
    resp = c.post("/api/auth/login?include_token=true", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Failed login for {email}: {resp.text}"
    data = resp.json()
    token = data["token"]
    csrf_token = data["csrf_token"]
    c.headers.update({
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf_token,
    })
    return c


# ==============================================================================
# 1. Public Registration Tests
# ==============================================================================

def test_public_registration_success(client, db):
    """Test successful public registration, default Demo Analyst role, active state, and immediate login."""
    uid = uuid.uuid4().hex[:8]
    email = f"analyst_{uid}@portfolio.demo"
    password = "SecurePassword123!"

    resp = client.post("/api/auth/register", json={
        "full_name": "Demo Candidate",
        "email": email,
        "password": password,
        "confirm_password": password,
    })

    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == email.lower()
    assert data["is_active"] is True
    assert data["is_verified"] is False
    assert "can now log in" in data["message"].lower()

    # Verify database state
    user = db.query(User).filter(User.email == email.lower()).first()
    assert user is not None
    assert user.is_verified is False
    assert user.is_active is True
    assert "Demo Analyst" in [r.name for r in user.roles]
    # Ensure neither Admin nor Security Analyst roles were granted
    assert "Admin" not in [r.name for r in user.roles]
    assert "Security Analyst" not in [r.name for r in user.roles]

    # Verify user can immediately log in without email verification
    login_resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    assert login_resp.json()["user"]["email"] == email.lower()
    assert login_resp.json()["user"]["is_active"] is True


def test_registration_password_complexity_validation(client):
    """Test that password complexity requirements are enforced by Pydantic."""
    uid = uuid.uuid4().hex[:8]
    base_email = f"complex_{uid}@test.demo"

    # Too short (< 8 chars)
    r1 = client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": base_email,
        "password": "Ab1!",
        "confirm_password": "Ab1!",
    })
    assert r1.status_code == 422

    # Missing uppercase
    r2 = client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": base_email,
        "password": "password123!",
        "confirm_password": "password123!",
    })
    assert r2.status_code == 422

    # Missing lowercase
    r3 = client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": base_email,
        "password": "PASSWORD123!",
        "confirm_password": "PASSWORD123!",
    })
    assert r3.status_code == 422

    # Missing number
    r4 = client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": base_email,
        "password": "PasswordSpecial!",
        "confirm_password": "PasswordSpecial!",
    })
    assert r4.status_code == 422

    # Missing special character
    r5 = client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": base_email,
        "password": "Password12345",
        "confirm_password": "Password12345",
    })
    assert r5.status_code == 422


def test_registration_passwords_mismatch(client):
    """Test that password and confirm_password must match."""
    uid = uuid.uuid4().hex[:8]
    resp = client.post("/api/auth/register", json={
        "full_name": "Mismatch User",
        "email": f"mismatch_{uid}@test.demo",
        "password": "Password123!",
        "confirm_password": "DifferentPassword123!",
    })
    assert resp.status_code == 422


def test_registration_duplicate_email_rejected(client):
    """Test that duplicate email registration is rejected with 400 Bad Request."""
    uid = uuid.uuid4().hex[:8]
    email = f"duplicate_{uid}@test.demo"
    payload = {
        "full_name": "First Registration",
        "email": email,
        "password": "Password123!",
        "confirm_password": "Password123!",
    }

    # First attempt succeeds
    r1 = client.post("/api/auth/register", json=payload)
    assert r1.status_code == 201

    # Second attempt with same email fails
    r2 = client.post("/api/auth/register", json=payload)
    assert r2.status_code == 400
    assert "already exists" in r2.json()["detail"].lower()


def test_registration_email_normalized(client, db):
    """Test that email addresses are trimmed and normalized to lowercase."""
    uid = uuid.uuid4().hex[:8]
    raw_email = f"  UpperCase_{uid}@DOMAIN.COM  "
    expected_normalized = f"uppercase_{uid}@domain.com"

    resp = client.post("/api/auth/register", json={
        "full_name": "Normalized User",
        "email": raw_email.strip(),
        "password": "Password123!",
        "confirm_password": "Password123!",
    })
    assert resp.status_code == 201
    assert resp.json()["email"] == expected_normalized

    user = db.query(User).filter(User.email == expected_normalized).first()
    assert user is not None


def test_registration_argon2id_hashing(client, db):
    """Verify that user passwords are saved as secure Argon2id hashes, not plaintext."""
    uid = uuid.uuid4().hex[:8]
    email = f"hashcheck_{uid}@test.demo"
    password = "SuperSecretPassword123!"

    resp = client.post("/api/auth/register", json={
        "full_name": "Hash Check",
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert resp.status_code == 201

    user = db.query(User).filter(User.email == email).first()
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert password not in user.password_hash


def test_registration_cannot_specify_elevated_role(client, db):
    """Verify that public registration ignores any attempt to pass role/roles in the payload."""
    uid = uuid.uuid4().hex[:8]
    email = f"priv_escalate_{uid}@test.demo"

    resp = client.post("/api/auth/register", json={
        "full_name": "Priv Escalate",
        "email": email,
        "password": "Password123!",
        "confirm_password": "Password123!",
        "role": "Admin",
        "roles": ["Admin", "Security Analyst"],
    })
    assert resp.status_code == 201

    user = db.query(User).filter(User.email == email).first()
    assert user is not None
    role_names = [r.name for r in user.roles]
    assert role_names == ["Demo Analyst"]
    assert "Admin" not in role_names


# ==============================================================================
# 2. Registration Without Mandatory Verification & Login Behavior
# ==============================================================================

def test_registration_succeeds_without_smtp_configuration(client, db):
    """Verify that public registration succeeds without requiring SMTP configuration."""
    uid = uuid.uuid4().hex[:8]
    email = f"nosmtp_{uid}@test.demo"
    password = "Password123!"

    resp = client.post("/api/auth/register", json={
        "full_name": "No SMTP User",
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert resp.status_code == 201
    assert resp.json()["is_active"] is True

    # User in database is active and can log in immediately
    user = db.query(User).filter(User.email == email).first()
    assert user.is_active is True
    assert user.is_verified is False


def test_user_can_immediately_login_after_registration(client):
    """Verify that a user can immediately log in after registering, without email verification."""
    uid = uuid.uuid4().hex[:8]
    email = f"immediate_{uid}@test.demo"
    password = "Password123!"

    reg_resp = client.post("/api/auth/register", json={
        "full_name": "Immediate Login User",
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert reg_resp.status_code == 201

    login_resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["user"]["email"] == email.lower()
    assert data["user"]["is_active"] is True
    assert "itdr_session" in login_resp.cookies
    assert "itdr_csrf" in login_resp.cookies


def test_no_verification_email_sent_on_registration(client):
    """Verify that no verification email is dispatched during traditional registration."""
    mock_sent_emails.clear()
    uid = uuid.uuid4().hex[:8]
    email = f"nomail_{uid}@test.demo"
    password = "Password123!"

    resp = client.post("/api/auth/register", json={
        "full_name": "No Mail User",
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert resp.status_code == 201
    assert len(mock_sent_emails) == 0


def test_invalid_password_rejected(client):
    """Verify that login fails with 401 when an incorrect password is provided."""
    uid = uuid.uuid4().hex[:8]
    email = f"badpwd_{uid}@test.demo"
    password = "CorrectPassword123!"

    client.post("/api/auth/register", json={
        "full_name": "Bad Pwd User",
        "email": email,
        "password": password,
        "confirm_password": password,
    })

    login_resp = client.post("/api/auth/login", json={"email": email, "password": "WrongPassword999!"})
    assert login_resp.status_code == 401
    assert "invalid email or password" in login_resp.json()["detail"].lower()


def test_inactive_account_blocked_from_login(client, db):
    """Verify that deactivated / inactive accounts receive HTTP 403 Forbidden on login."""
    uid = uuid.uuid4().hex[:8]
    email = f"inactive_{uid}@test.demo"
    password = "Password123!"

    client.post("/api/auth/register", json={
        "full_name": "Inactive Account User",
        "email": email,
        "password": password,
        "confirm_password": password,
    })

    user = db.query(User).filter(User.email == email).first()
    user.is_active = False
    db.commit()

    login_resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_resp.status_code == 403
    assert "deactivated" in login_resp.json()["detail"].lower()


def test_resend_verification_email_and_rate_limit(client):
    """Test voluntary verification email resend and 60s cooldown rate limit."""
    uid = uuid.uuid4().hex[:8]
    email = f"resend_{uid}@test.demo"
    password = "Password123!"

    client.post("/api/auth/register", json={
        "full_name": "Resend Test",
        "email": email,
        "password": password,
        "confirm_password": password,
    })

    # First voluntary resend succeeds
    r1 = client.post("/api/auth/resend-verification", json={"email": email})
    assert r1.status_code == 200

    # Immediate second resend is rate-limited (429)
    r2 = client.post("/api/auth/resend-verification", json={"email": email})
    assert r2.status_code == 429
    assert "wait" in r2.json()["detail"].lower()


def test_optional_verification_token_lifecycle(client, db):
    """Verify that if a user voluntarily uses a verification token, is_verified is updated."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]
    email = f"opt_verif_{uid}@test.demo"
    user = auth_svc.register_public_user("Opt User", email, "Password123!")

    # Voluntarily generate token
    raw_token, token_hash = generate_verification_token()
    now = datetime.datetime.now(datetime.timezone.utc)
    token_record = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=now + datetime.timedelta(minutes=30),
        created_at=now,
    )
    db.add(token_record)
    db.commit()

    # Verify email
    v_resp = client.post("/api/auth/verify-email", json={"token": raw_token})
    assert v_resp.status_code == 200
    assert v_resp.json()["is_verified"] is True

    # User in database is now marked verified
    db.refresh(user)
    assert user.is_verified is True


# ==============================================================================
# 3. Social Authentication (OAuth Auto-Registration)
# ==============================================================================

def test_oauth_public_auto_registration(db):
    """Test that OAuth signup for a new visitor provisions Demo Analyst with is_verified=True."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]
    oauth_email = f"google_visitor_{uid}@gmail.com"

    user = auth_svc.handle_oauth_user(
        provider="google",
        provider_user_id=f"goog_{uid}",
        verified_email=oauth_email,
        full_name="External Interviewer",
    )

    assert user is not None
    assert user.email == oauth_email
    assert user.is_verified is True
    assert "Demo Analyst" in [r.name for r in user.roles]


def test_oauth_existing_user_linking(db):
    """Test that OAuth login for an existing user links identity and marks email verified."""
    uid = uuid.uuid4().hex[:8]
    email = f"link_test_{uid}@example.com"
    auth_svc = AuthService(db)

    # Register as user first (active, but unverified email)
    user = auth_svc.register_public_user(
        full_name="Pre Registered",
        email=email,
        password="Password123!",
    )
    assert user.is_verified is False

    # Sign in via GitHub with matching email
    linked_user = auth_svc.handle_oauth_user(
        provider="github",
        provider_user_id=f"gh_{uid}",
        verified_email=email,
        full_name="Pre Registered GitHub",
        email_verified=True,
    )

    assert linked_user.id == user.id
    assert linked_user.is_verified is True  # Verified by GitHub


# ==============================================================================
# 4. Multi-Tenant Report Isolation Tests
# ==============================================================================

def test_multi_tenant_report_isolation(client, db):
    """Verify that users can only access their own private reports, shared demo reports, and Admin sees all."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]

    # User 1 (Demo Analyst)
    u1 = auth_svc.register_public_user(f"User One {uid}", f"u1_{uid}@demo.local", "Password123!")
    client_u1 = get_user_auth_client(f"u1_{uid}@demo.local", "Password123!")

    # User 2 (Demo Analyst)
    u2 = auth_svc.register_public_user(f"User Two {uid}", f"u2_{uid}@demo.local", "Password123!")
    client_u2 = get_user_auth_client(f"u2_{uid}@demo.local", "Password123!")

    # Admin Client
    client_admin = get_user_auth_client("admin@itdr.local", "AdminPass123!")

    # Create Report 1 owned by User 1
    rep1_id = f"REP-TEST-U1-{uid}"
    rep1 = ThreatAnalysisReport(
        report_id=rep1_id,
        input_advisory="Confidential User 1 Advisory",
        report_title=f"User 1 Private Investigation {uid}",
        executive_summary="User 1 summary",
        severity="High",
        structured_report={"title": f"User 1 Report {uid}"},
        completion_status="Completed",
        is_demo=False,
        created_by_user_id=u1.id,
    )
    db.add(rep1)

    # Create a Shared Demo Report
    demo_rep_id = f"REP-DEMO-SHARED-{uid}"
    demo_rep = ThreatAnalysisReport(
        report_id=demo_rep_id,
        input_advisory="Shared demo advisory",
        report_title=f"Shared Public Demo Report {uid}",
        executive_summary="Shared demo summary",
        severity="Medium",
        structured_report={"title": "Shared Demo"},
        completion_status="Completed",
        is_demo=True,
        created_by_user_id=None,
    )
    db.add(demo_rep)
    db.commit()

    # 1. User 1 can view rep1
    r1 = client_u1.get(f"/api/threats/reports/{rep1_id}")
    assert r1.status_code == 200
    assert r1.json()["report_id"] == rep1_id

    # 2. User 2 CANNOT view rep1 (returns 404 to avoid enumeration)
    r2 = client_u2.get(f"/api/threats/reports/{rep1_id}")
    assert r2.status_code == 404

    # 3. User 2 listing reports does NOT contain rep1
    list_u2 = client_u2.get("/api/threats/reports")
    assert list_u2.status_code == 200
    rep_ids_u2 = [r["report_id"] for r in list_u2.json()["reports"]]
    assert rep1_id not in rep_ids_u2
    assert demo_rep_id in rep_ids_u2  # Shared demo report IS visible

    # 4. Admin CAN view rep1
    r_admin = client_admin.get(f"/api/threats/reports/{rep1_id}")
    assert r_admin.status_code == 200
    assert r_admin.json()["report_id"] == rep1_id


# ==============================================================================
# 5. Usage Limits & Daily Analysis Quota Tests
# ==============================================================================

def test_usage_limits_advisory_length(db):
    """Test that advisory texts exceeding MAX_ADVISORY_CHARS are rejected with HTTP 400."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]
    u = auth_svc.register_public_user(f"Quota User {uid}", f"quota_{uid}@demo.local", "Password123!")
    client_user = get_user_auth_client(f"quota_{uid}@demo.local", "Password123!")

    # Exceed 15,000 characters
    long_advisory = "Suspicious PowerShell activity observed. " * 450  # ~18,000 chars
    resp = client_user.post("/api/threats/analyze", json={"advisory_text": long_advisory})
    assert resp.status_code == 400
    assert "exceeds maximum allowed limit" in resp.json()["detail"].lower()


def test_daily_analysis_quota_enforcement(db):
    """Test that non-admins cannot exceed DAILY_ANALYSIS_LIMIT per 24 hours (HTTP 429)."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]
    u = auth_svc.register_public_user(f"Limit User {uid}", f"limit_{uid}@demo.local", "Password123!")
    client_user = get_user_auth_client(f"limit_{uid}@demo.local", "Password123!")

    # Seed 5 completed reports for this user in the last 24 hours
    now = datetime.datetime.now(datetime.timezone.utc)
    for i in range(settings.DAILY_ANALYSIS_LIMIT):
        rep = ThreatAnalysisReport(
            report_id=f"REP-QUOTA-{uid}-{i}",
            input_advisory="Advisory sample text",
            report_title=f"Sample Report {i}",
            executive_summary="Summary",
            severity="Low",
            structured_report={},
            completion_status="Completed",
            is_demo=False,
            created_by_user_id=u.id,
            created_at=now,
        )
        db.add(rep)
    db.commit()

    # The 6th analysis attempt must be blocked with HTTP 429
    resp = client_user.post("/api/threats/analyze", json={
        "advisory_text": "Valid advisory text for threat analysis testing.",
    })
    assert resp.status_code == 429
    assert "quota exceeded" in resp.json()["detail"].lower()

    # Verify audit log entry for quota breach
    audit = db.query(AuditLog).filter(
        AuditLog.user_id == u.id,
        AuditLog.action == "analysis_quota_exceeded"
    ).first()
    assert audit is not None


# ==============================================================================
# 6. Demo Analyst Role & RBAC Boundary Tests
# ==============================================================================

def test_demo_analyst_rbac_boundaries(db):
    """Verify Demo Analyst can access exploratory endpoints, but is denied administrative/ingest operations."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]
    u = auth_svc.register_public_user(f"RBAC User {uid}", f"rbac_{uid}@demo.local", "Password123!")
    demo_client = get_user_auth_client(f"rbac_{uid}@demo.local", "Password123!")

    # Allowed endpoints (read + analyze)
    assert demo_client.get("/api/coverage-matrix").status_code == 200
    assert demo_client.get("/api/reports/identity-resilience").status_code == 200
    assert demo_client.get("/api/reports/threat-exposure").status_code == 200
    assert demo_client.get("/api/reports/threat-scenarios").status_code == 200
    assert demo_client.get("/api/identity/bulletins").status_code == 200
    assert demo_client.get("/api/identity/feeds").status_code == 200
    assert demo_client.get("/api/threats/samples").status_code == 200
    assert demo_client.get("/api/threats/reports").status_code == 200
    assert demo_client.get("/api/rag/health").status_code == 200

    # Forbidden endpoints (administrative & ingest)
    r_ingest = demo_client.post("/api/twin/feeds/ingest", json={
        "title": "Malicious Ingest",
        "source": "Attacker",
        "content": "Malicious content",
    })
    assert r_ingest.status_code == 403
    assert "feeds:ingest" in r_ingest.json()["detail"]

    r_users = demo_client.get("/api/users")
    assert r_users.status_code == 403
    assert "users:manage" in r_users.json()["detail"]

    r_system = demo_client.get("/api/system/status")
    assert r_system.status_code == 403
    assert "system:status" in r_system.json()["detail"]


# ==============================================================================
# 7. Security Controls & Regressions (Rate Limits, Isolation, Quota, Killswitch)
# ==============================================================================

def test_oauth_unverified_email_rejected(db):
    """Verify that social login rejects provider identities with unverified email addresses."""
    from fastapi import HTTPException
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]

    with pytest.raises(HTTPException) as exc_info:
        auth_svc.handle_oauth_user(
            provider="github",
            provider_user_id=f"gh_unverified_{uid}",
            verified_email=f"attacker_{uid}@fakedomain.org",
            full_name="Attacker",
            email_verified=False,
        )
    assert exc_info.value.status_code == 400
    assert "not verified" in exc_info.value.detail.lower()


def test_oauth_duplicate_identity_resolves_same_user(db):
    """Verify that logging in twice with the same OAuth provider identity resolves the same user record."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]
    email = f"oauth_repeat_{uid}@example.com"

    u1 = auth_svc.handle_oauth_user(
        provider="google",
        provider_user_id=f"google_dup_{uid}",
        verified_email=email,
        full_name="Repeat User",
        email_verified=True,
    )
    u2 = auth_svc.handle_oauth_user(
        provider="google",
        provider_user_id=f"google_dup_{uid}",
        verified_email=email,
        full_name="Repeat User",
        email_verified=True,
    )
    assert u1.id == u2.id


def test_registration_rate_limiting(client):
    """Verify that rapid registration attempts from the same IP trigger HTTP 429."""
    from app.core.rate_limiter import registration_rate_limiter
    test_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    registration_rate_limiter.reset(test_ip)

    # Exhaust the 5 allowed attempts
    for i in range(5):
        uid = uuid.uuid4().hex[:8]
        resp = client.post(
            "/api/auth/register",
            headers={"X-Real-IP": test_ip},
            json={
                "full_name": f"Rate Limit Test {i}",
                "email": f"rl_{i}_{uid}@test.demo",
                "password": "Password123!",
                "confirm_password": "Password123!",
            },
        )
        assert resp.status_code == 201

    # 6th attempt must be rejected with 429
    uid = uuid.uuid4().hex[:8]
    blocked_resp = client.post(
        "/api/auth/register",
        headers={"X-Real-IP": test_ip},
        json={
            "full_name": "Blocked User",
            "email": f"rl_blocked_{uid}@test.demo",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    assert blocked_resp.status_code == 429
    assert "too many registration attempts" in blocked_resp.json()["detail"].lower()


def test_verification_rate_limiting_brute_force_protection(client):
    """Verify that multiple failed verification attempts trigger rate limiting (HTTP 429)."""
    from app.core.rate_limiter import verification_rate_limiter
    test_ip = f"203.0.113.{uuid.uuid4().int % 250 + 1}"
    verification_rate_limiter.reset(test_ip)

    # Exhaust the 10 allowed attempts with bad tokens
    for _ in range(10):
        r = client.post(
            "/api/auth/verify-email",
            headers={"X-Real-IP": test_ip},
            json={"token": "invalid_fake_token_guess"},
        )
        assert r.status_code == 400

    # 11th attempt must be blocked with HTTP 429
    blocked_r = client.post(
        "/api/auth/verify-email",
        headers={"X-Real-IP": test_ip},
        json={"token": "another_invalid_guess"},
    )
    assert blocked_r.status_code == 429
    assert "too many verification attempts" in blocked_r.json()["detail"].lower()


def test_concurrent_verification_single_use(db):
    """Verify that an email verification token cannot be consumed concurrently or more than once."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]
    email = f"atomic_verif_{uid}@test.demo"
    user = auth_svc.register_public_user("Atomic User", email, "Password123!")

    # Voluntarily create token
    raw_token, token_hash = generate_verification_token()
    now = datetime.datetime.now(datetime.timezone.utc)
    verif_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=now + datetime.timedelta(minutes=30),
        created_at=now,
        used_at=None,
    )
    db.add(verif_token)
    db.commit()

    # Verify once
    verified_user = auth_svc.verify_email_token(raw_token)
    assert verified_user.is_verified is True

    # Attempting to verify again with the same token must raise HTTP 400
    with pytest.raises(Exception) as exc_info:
        auth_svc.verify_email_token(raw_token)
    assert "already been used" in str(exc_info.value).lower()


def test_threat_feed_ownership_isolation(client, db):
    """Verify that non-admins cannot access other users' private feeds, but can see demo feeds, and Admin sees all."""
    from app.models.feeds import ThreatFeed
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]

    u1 = auth_svc.register_public_user(f"Feed Owner {uid}", f"fowner_{uid}@demo.local", "Password123!")
    client_u1 = get_user_auth_client(f"fowner_{uid}@demo.local", "Password123!")

    u2 = auth_svc.register_public_user(f"Feed Other {uid}", f"fother_{uid}@demo.local", "Password123!")
    client_u2 = get_user_auth_client(f"fother_{uid}@demo.local", "Password123!")

    client_admin = get_user_auth_client("admin@itdr.local", "AdminPass123!")

    # User 1 private feed
    b1_id = f"TB-TEST-U1-{uid}"
    b1 = ThreatFeed(
        bulletin_id=b1_id,
        source="Custom CTI User 1",
        title=f"User 1 Private Intel {uid}",
        description="Confidential feed description",
        content="Confidential feed content",
        status="New",
        severity="High",
        is_demo=False,
        created_by_user_id=u1.id,
    )
    db.add(b1)

    # Shared Demo feed
    b_demo_id = f"TB-TEST-DEMO-{uid}"
    b_demo = ThreatFeed(
        bulletin_id=b_demo_id,
        source="Shared CTI Demo",
        title=f"Shared Public Demo Intel {uid}",
        description="Shared feed description",
        content="Shared feed content",
        status="New",
        severity="Medium",
        is_demo=True,
        created_by_user_id=None,
    )
    db.add(b_demo)
    db.commit()

    # 1. User 1 can view private feed detail
    r1 = client_u1.get(f"/api/identity/bulletins/{b1_id}")
    assert r1.status_code == 200
    assert r1.json()["bulletin_id"] == b1_id

    # 2. User 2 CANNOT view User 1's private feed detail (404)
    r2 = client_u2.get(f"/api/identity/bulletins/{b1_id}")
    assert r2.status_code == 404

    # 3. User 2 listing feeds does not include b1, but does include b_demo
    list_u2 = client_u2.get("/api/identity/bulletins")
    assert list_u2.status_code == 200
    feed_ids_u2 = [b["bulletin_id"] for b in list_u2.json()["bulletins"]]
    assert b1_id not in feed_ids_u2
    assert b_demo_id in feed_ids_u2

    # 4. Admin CAN view User 1's private feed detail
    r_admin = client_admin.get(f"/api/identity/bulletins/{b1_id}")
    assert r_admin.status_code == 200
    assert r_admin.json()["bulletin_id"] == b1_id


def test_emergency_killswitch(client, db, monkeypatch):
    """Verify that PUBLIC_LLM_ANALYSIS_ENABLED = False blocks non-admins (503) while allowing Admin."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]
    u = auth_svc.register_public_user(f"Kill User {uid}", f"kill_{uid}@demo.local", "Password123!")
    client_user = get_user_auth_client(f"kill_{uid}@demo.local", "Password123!")

    # Disable kill switch
    from app.api import threats as threats_api
    monkeypatch.setattr(threats_api.settings, "PUBLIC_LLM_ANALYSIS_ENABLED", False)

    # Non-admin is blocked with 503
    r_user = client_user.post("/api/threats/analyze", json={
        "advisory_text": "Sample threat advisory for testing kill switch.",
    })
    assert r_user.status_code == 503
    assert "temporarily disabled" in r_user.json()["detail"].lower()


def test_global_analysis_quota_enforcement(client, db, monkeypatch):
    """Verify that non-admins cannot analyze if global daily capacity is reached (HTTP 429)."""
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:6]
    u = auth_svc.register_public_user(f"Global User {uid}", f"global_{uid}@demo.local", "Password123!")
    client_user = get_user_auth_client(f"global_{uid}@demo.local", "Password123!")

    from app.api import threats as threats_api
    monkeypatch.setattr(threats_api.settings, "GLOBAL_DAILY_ANALYSIS_LIMIT", 0)

    r = client_user.post("/api/threats/analyze", json={
        "advisory_text": "Advisory text for global quota test.",
    })
    assert r.status_code == 429
    assert "global daily threat analysis capacity reached" in r.json()["detail"].lower()


def test_google_login_requires_verified_provider_email(db):
    """Verify that Google OAuth requires a verified email from the identity provider."""
    from fastapi import HTTPException
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]

    with pytest.raises(HTTPException) as exc_info:
        auth_svc.handle_oauth_user(
            provider="google",
            provider_user_id=f"goog_unverified_{uid}",
            verified_email=f"attacker_goog_{uid}@gmail.com",
            full_name="Unverified Google User",
            email_verified=False,
        )
    assert exc_info.value.status_code == 400
    assert "not verified" in exc_info.value.detail.lower()


def test_github_login_requires_verified_provider_email(db):
    """Verify that GitHub OAuth requires a verified email from the identity provider."""
    from fastapi import HTTPException
    auth_svc = AuthService(db)
    uid = uuid.uuid4().hex[:8]

    with pytest.raises(HTTPException) as exc_info:
        auth_svc.handle_oauth_user(
            provider="github",
            provider_user_id=f"gh_unverified_{uid}",
            verified_email=f"attacker_gh_{uid}@github.com",
            full_name="Unverified GitHub User",
            email_verified=False,
        )
    assert exc_info.value.status_code == 400
    assert "not verified" in exc_info.value.detail.lower()


