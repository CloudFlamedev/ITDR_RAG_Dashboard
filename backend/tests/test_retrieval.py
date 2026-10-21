import pytest
from app.services.retrieval_service import RetrievalService


def test_entity_extraction():
    service = RetrievalService(db=None)
    text = "Adversary used T1078.004 and T1003 to compromise USER_JANE and DC-PRIMARY-01. Countermeasure D3-MFA observed."
    res = service.extract_explicit_entities(text)

    assert "T1078.004" in res["attack_ids"]
    assert "T1003" in res["attack_ids"]
    assert "D3-MFA" in res["d3fend_ids"]


def test_exact_id_boost_retrieval(db_session):
    service = RetrievalService(db_session)
    text = "The analyst noted explicit utilization of technique T1078 for credential access."
    res = service.retrieve(text, max_candidates=5)

    assert len(res["candidates"]) > 0
    top = res["candidates"][0]
    assert "T1078" in top["technique_id"]
    assert top["is_exact_match"] is True
    assert top["similarity_score"] == 1.0


def test_d3fend_countermeasure_retrieval(db_session):
    service = RetrievalService(db_session)
    text = "Attacker performed Active Directory DCSync attack and Kerberos ticket forgery."
    res = service.retrieve(text, max_candidates=5, include_d3fend=True)

    assert "defensive_countermeasures" in res
    assert isinstance(res["defensive_countermeasures"], list)
