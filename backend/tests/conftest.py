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


@pytest.fixture
def db(db_session):
    """Alias fixture for db_session."""
    return db_session


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


def _generate_grounded_mock_llm_response(*args, **kwargs):
    from langchain_core.messages import AIMessage
    import json
    import re

    messages = args[0] if args else kwargs.get("messages") or kwargs.get("input", [])
    prompt_text = ""
    if isinstance(messages, list):
        for m in messages:
            if getattr(m, "type", "") == "human" or getattr(m, "role", "") == "user":
                prompt_text = getattr(m, "content", "")
                break
        if not prompt_text and messages:
            last = messages[-1]
            prompt_text = getattr(last, "content", str(last))
    elif isinstance(messages, str):
        prompt_text = messages

    cands = []
    d3fs = []
    try:
        start = prompt_text.find("```json\n")
        if start != -1:
            start += 8
            end = prompt_text.find("\n```", start)
            if end != -1:
                payload = json.loads(prompt_text[start:end])
                cands = payload.get("retrieved_attack_candidates", [])
                d3fs = payload.get("retrieved_d3fend_countermeasures", [])
    except Exception:
        pass

    if not cands:
        extracted = re.findall(r"T\d{4}(?:\.\d{3})?", prompt_text)
        if not extracted:
            extracted = ["T1078"]
        cands = [{"technique_id": tid, "name": f"Technique {tid}", "tactics": ["Initial Access"]} for tid in extracted]

    citations = [
        {
            "source_id": f"att-tech-{c['technique_id']}",
            "external_id": c["technique_id"],
            "excerpt": f"Authoritative MITRE ATT&CK guidance and telemetry for {c['technique_id']}.",
            "relevance_score": 0.95,
            "citation_role": "Technique Evidence",
        }
        for c in cands[:3]
    ]

    for d in d3fs[:2]:
        citations.append({
            "source_id": f"d3f-tech-{d['d3fend_id']}",
            "external_id": d["d3fend_id"],
            "excerpt": f"Authoritative MITRE D3FEND countermeasure definition for {d['d3fend_id']}.",
            "relevance_score": 0.9,
            "citation_role": "Countermeasure Evidence",
        })

    report = {
        "report_title": f"ITDR Threat Analysis Report: {cands[0].get('name', 'Technique')}",
        "executive_summary": "Identified adversary identity techniques based on authoritative retrieved context.",
        "incident_overview": "Adversary accessed domain resources using harvested credentials.",
        "severity": "High",
        "severity_rationale": "High privileged credential manipulation observed in incident telemetry.",
        "technique_candidates": [
            {
                "technique_id": c["technique_id"],
                "name": c.get("name", f"Technique {c['technique_id']}"),
                "tactics": c.get("tactics", ["Initial Access"]),
                "relevance_score": float(c.get("relevance_score", 0.9)),
                "is_exact_match": True,
                "rationale": f"Observed in threat evidence for {c['technique_id']}.",
                "supporting_evidence_ids": [f"att-tech-{c['technique_id']}"],
            }
            for c in cands[:5]
        ],
        "defensive_techniques": [
            {
                "d3fend_id": d["d3fend_id"],
                "name": d.get("name", "Countermeasure"),
                "relationship_type": d.get("relationship_type", "mitigates"),
                "provenance": "MITRE D3FEND",
                "rationale": f"Countermeasure addressing identified attack vector: {d.get('matched_via', 'D3FEND')}",
            }
            for d in d3fs[:3]
        ],
        "recommended_actions": [
            {
                "action": "Enforce Multi-Factor Authentication (MFA) and rotate compromised credentials.",
                "priority": "Critical",
                "category": "Identity Hardening",
                "rationale": "Prevent unauthorized account access and limit privilege escalation blast radius.",
            }
        ],
        "uncertainties": [],
        "citations": citations,
    }
    return AIMessage(content=json.dumps(report), additional_kwargs={})


@pytest.fixture(autouse=True)
def isolate_environment_state():
    """
    Preserves and restores os.environ before and after each test,
    guaranteeing zero cross-test environment contamination or leakages.
    """
    original_env = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original_env)


@pytest.fixture(autouse=True)
def mock_deterministic_llm(request):
    """
    Autouse fixture that provides deterministic, mocked LLM responses for test runs,
    ensuring tests are independent of external LLM API availability and avoiding API costs/failures.
    Automatically bypassed if test has @pytest.mark.live_llm or TEST_USE_LIVE_LLM=true.
    """
    if request.node.get_closest_marker("live_llm") is not None:
        yield
        return

    if os.environ.get("TEST_USE_LIVE_LLM", "").strip().lower() in ("true", "1"):
        yield
        return

    from unittest.mock import patch
    from langchain_openai import ChatOpenAI
    try:
        from langchain_xai import ChatXAI
    except Exception:
        ChatXAI = None

    patches = [
        patch.object(ChatOpenAI, "invoke", side_effect=_generate_grounded_mock_llm_response),
    ]
    if ChatXAI is not None:
        patches.append(patch.object(ChatXAI, "invoke", side_effect=_generate_grounded_mock_llm_response))

    with patches[0]:
        if len(patches) > 1:
            with patches[1]:
                yield
        else:
            yield


def pytest_configure(config):
    """Registers custom markers for test categorization."""
    config.addinivalue_line(
        "markers", "live_llm: marks tests as requiring live LLM API credentials (skipped by default in CI)"
    )


def pytest_collection_modifyitems(config, items):
    """
    Ensures tests marked with @pytest.mark.live_llm are skipped by default
    unless -m live_llm was explicitly specified on the pytest command line.
    """
    markexpr = config.getoption("-m", default="")
    if "live_llm" not in markexpr:
        skip_live = pytest.mark.skip(
            reason="Live LLM tests skipped by default in automated test runs. Run with: pytest -m live_llm"
        )
        for item in items:
            if "live_llm" in item.keywords:
                item.add_marker(skip_live)

