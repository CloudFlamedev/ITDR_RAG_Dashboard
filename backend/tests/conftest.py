import pytest
import os
import sys
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import SessionLocal
from app.main import app
from app.models.auth import User, Role
from app.core.security import hash_password, generate_csrf_token
from app.services.auth_service import AuthService
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def db_session():
    """Provides a database session for tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session")
def setup_test_users(db_session):
    """Ensure standard test users exist for all 3 RBAC roles and an inactive user."""
    admin_role = db_session.query(Role).filter(Role.name == "Admin").first()
    analyst_role = db_session.query(Role).filter(Role.name == "Security Analyst").first()
    viewer_role = db_session.query(Role).filter(Role.name == "Viewer").first()

    users_data = [
        ("admin@itdr.local", "Test Admin", "AdminPass123!", [admin_role], True),
        ("analyst@itdr.local", "Test Analyst", "AnalystPass123!", [analyst_role], True),
        ("viewer@itdr.local", "Test Viewer", "ViewerPass123!", [viewer_role], True),
        ("inactive@itdr.local", "Test Inactive", "InactivePass123!", [viewer_role], False),
    ]

    now = datetime.datetime.now(datetime.timezone.utc)
    for email, name, pwd, roles, active in users_data:
        user = db_session.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                full_name=name,
                password_hash=hash_password(pwd),
                is_active=active,
                is_verified=True,
                created_at=now,
                updated_at=now,
                roles=[r for r in roles if r],
            )
            db_session.add(user)
        else:
            user.password_hash = hash_password(pwd)
            user.is_active = active
            user.roles = [r for r in roles if r]
    db_session.commit()


@pytest.fixture(scope="session")
def client(setup_test_users):
    """Unauthenticated FastAPI TestClient instance."""
    with TestClient(app) as c:
        yield c


def _get_authenticated_client(email: str, password: str) -> TestClient:
    c = TestClient(app)
    resp = c.post("/api/auth/login?include_token=true", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    token = resp.json().get("token")
    csrf_token = resp.json().get("csrf_token")
    # Provide both Bearer header and CSRF token for effortless test execution
    c.headers.update({
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf_token,
    })
    return c


@pytest.fixture(scope="session")
def admin_client(setup_test_users):
    """Client authenticated as Administrator."""
    return _get_authenticated_client("admin@itdr.local", "AdminPass123!")


@pytest.fixture(scope="session")
def analyst_client(setup_test_users):
    """Client authenticated as Security Analyst."""
    return _get_authenticated_client("analyst@itdr.local", "AnalystPass123!")


@pytest.fixture(scope="session")
def viewer_client(setup_test_users):
    """Client authenticated as Viewer."""
    return _get_authenticated_client("viewer@itdr.local", "ViewerPass123!")
