import pytest
from unittest.mock import patch, MagicMock
from app.services.rerank_service import RerankService
from app.services.retrieval_service import RetrievalService, CandidateTechnique


def test_reranker_initialization():
    service = RerankService(model_name="jina-reranker-v2-base-multilingual")
    assert service.model_name == "jina-reranker-v2-base-multilingual"
    assert service.timeout == 15


def test_reranker_disabled_mode():
    service = RerankService(enabled=False)
    assert service.is_configured is False

    docs = ["Doc A", "Doc B", "Doc C"]
    results = service.rerank("security query", docs)
    assert len(results) == 3
    assert results[0]["index"] == 0
    assert results[0]["document"] == "Doc A"


def test_reranker_exact_match_preservation():
    service = RerankService(enabled=False)  # offline mode

    cands = [
        {"technique_id": "T1566", "name": "Phishing", "similarity_score": 0.85, "is_exact_match": False},
        {"technique_id": "T1078", "name": "Valid Accounts", "similarity_score": 1.0, "is_exact_match": True},
    ]

    reranked, meta = service.rerank_candidates("compromised account credential", cands)
    assert len(reranked) == 2
    # Exact match must remain at index 0 with score 1.0
    assert reranked[0]["technique_id"] == "T1078"
    assert reranked[0]["similarity_score"] == 1.0
    assert reranked[0]["is_exact_match"] is True


def test_reranker_fallback_on_network_error():
    service = RerankService(api_key="mock_key", enabled=True)

    with patch("requests.post", side_effect=Exception("Connection timeout")):
        cands = [
            {"technique_id": "T1566", "name": "Phishing", "similarity_score": 0.75, "is_exact_match": False},
            {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "similarity_score": 0.65, "is_exact_match": False},
        ]
        reranked, meta = service.rerank_candidates("Kerberos attack", cands)

        assert len(reranked) == 2
        assert meta["rerank_performed"] is False
        # Scores must be preserved from original bi-encoder
        assert reranked[0]["similarity_score"] == 0.75
        assert reranked[1]["similarity_score"] == 0.65


def test_reranker_successful_api_scoring():
    service = RerankService(api_key="mock_key", enabled=True)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "jina-reranker-v2-base-multilingual",
        "results": [
            {"index": 1, "relevance_score": 0.942},  # Index 1 promoted to top
            {"index": 0, "relevance_score": 0.128},
        ]
    }

    with patch("requests.post", return_value=mock_resp):
        cands = [
            {"technique_id": "T1566", "name": "Phishing", "similarity_score": 0.75, "is_exact_match": False},
            {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "similarity_score": 0.65, "is_exact_match": False},
        ]
        reranked, meta = service.rerank_candidates("Kerberos attack", cands)

        assert len(reranked) == 2
        assert meta["rerank_performed"] is True
        # Index 1 was promoted to top position!
        assert reranked[0]["technique_id"] == "T1558"
        assert reranked[0]["similarity_score"] == 0.942
        assert reranked[1]["technique_id"] == "T1566"
        assert reranked[1]["similarity_score"] == 0.128


def test_retrieval_service_integrates_reranker():
    service = RetrievalService(db=None)
    res = service.retrieve("Explicit mention of T1078.004 in user advisory", max_candidates=5)

    assert "candidates" in res
    assert "rerank_applied" in res
    assert "rerank_model" in res
    assert "rerank_latency_ms" in res
    assert len(res["candidates"]) > 0
    assert res["candidates"][0]["technique_id"] == "T1078.004"
