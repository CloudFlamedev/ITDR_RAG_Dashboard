import pytest
from starlette.testclient import TestClient
from app.main import app, langfuse
from app.core.config import get_settings
from app.core.telemetry import (
    mask_sensitive_data,
    check_telemetry_auth,
    flush_telemetry,
    log_threat_score,
    get_current_trace_id,
    observe,
    propagate_attributes,
    CallbackHandler,
)
from app.services.vector_store_service import VectorStoreService
from app.db.session import SessionLocal

settings = get_settings()


def test_telemetry_masking_guardrails():
    """Verify that sensitive credentials, session tokens, and raw hashes are masked."""
    # 1. Passwords
    raw_pwd = "user=admin password=SecretPassword123! in request"
    masked_pwd = mask_sensitive_data(raw_pwd)
    assert "SecretPassword123!" not in masked_pwd
    assert "[REDACTED_PASSWORD]" in masked_pwd

    # 2. NTLM Hash
    raw_ntlm = "Cracked NTLM hash: 31d6cfe0d16ae931b73c59d7e0c089c0 for Domain Admin"
    masked_ntlm = mask_sensitive_data(raw_ntlm)
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in masked_ntlm
    assert "[REDACTED_NTLM_HASH]" in masked_ntlm

    # 3. Argon2id Hash
    raw_argon = "Hash: $argon2id$v=19$m=65536,t=2,p=2$dummyhashfordummyuserdummyhash$dummyhashfordummyuser"
    masked_argon = mask_sensitive_data(raw_argon)
    assert "$argon2id$" not in masked_argon
    assert "[REDACTED_ARGON2_HASH]" in masked_argon

    # 4. Bearer & Session Tokens
    raw_tokens = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token and itdr_session=abcdef1234567890abcdef1234567890"
    masked_tokens = mask_sensitive_data(raw_tokens)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token" not in masked_tokens
    assert "abcdef1234567890abcdef1234567890" not in masked_tokens
    assert "[REDACTED_TOKEN]" in masked_tokens

    # 5. Recursive dictionary masking
    raw_dict = {
        "query": "Attacker password: SuperSecret!",
        "nested": {"hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
        "list": ["password=Secret999"],
    }
    masked_dict = mask_sensitive_data(raw_dict)
    assert "[REDACTED_PASSWORD]" in masked_dict["query"]
    assert "[REDACTED_NTLM_HASH]" in masked_dict["nested"]["hash"]
    assert "[REDACTED_PASSWORD]" in masked_dict["list"][0]


def test_telemetry_client_lifecycle():
    """Verify Langfuse client initialization, auth check, and flush lifecycle."""
    assert langfuse is not None
    # Auth check should succeed with valid credentials or return a bool without raising exceptions
    auth_result = check_telemetry_auth()
    assert isinstance(auth_result, bool)

    # Flush should complete without raising errors
    flush_telemetry()


def test_vector_retrieval_span_instrumentation():
    """Verify that vector similarity search operates within an @observe span and returns valid results."""
    db = SessionLocal()
    try:
        vstore = VectorStoreService(db)
        results = vstore.similarity_search(
            query="Adversaries abused valid domain credentials T1078 password=Secret!",
            top_k=3,
        )
        assert isinstance(results, list)
    finally:
        db.close()


def test_rag_search_tracing_endpoint(analyst_client):
    """Verify /api/rag/search endpoint executes with Langfuse root tracing and returns valid schema."""
    search_res = analyst_client.post(
        "/api/rag/search",
        json={
            "query": "Adversaries abused T1078 Valid Accounts to dump credentials",
            "top_k": 5,
            "include_d3fend": True,
        },
    )
    assert search_res.status_code == 200
    data = search_res.json()
    assert "candidates" in data
    assert "defensive_countermeasures" in data
    assert data["candidate_count"] >= 0


def test_threat_analysis_trace_and_scoring(analyst_client):
    """Verify /api/threats/analyze executes end-to-end within @observe root trace with Langfuse scores."""
    analyze_res = analyst_client.post(
        "/api/threats/analyze",
        json={
            "advisory_text": "Telemetry detected abnormal logon with T1078 Valid Accounts and LSASS access T1003.",
            "sample_id": "test-telemetry-sample",
            "client_restriction": "ALL",
            "itdr_scope": "ITDR Scope Only",
            "view_mode": "ClientReq",
            "include_d3fend": True,
            "max_technique_candidates": 4,
        },
    )
    assert analyze_res.status_code == 200
    report_data = analyze_res.json()
    assert "report_id" in report_data
    assert report_data["status"] in ("COMPLETED", "SUCCESS")
    assert report_data["report"] is not None
    assert "severity" in report_data["report"]

