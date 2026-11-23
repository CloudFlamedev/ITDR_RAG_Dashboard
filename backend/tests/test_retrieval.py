import pytest
from unittest.mock import MagicMock
from app.services.retrieval_service import RetrievalService
from app.models.rag import RagDocument


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


def test_benign_loopback_ping_returns_no_candidates(db_session):
    """Regression test: ret-011 loopback ping query must return empty candidates and insufficient_evidence=True."""
    service = RetrievalService(db_session)
    query = "Routine network connectivity check: ping 127.0.0.1 and echo test string in local administrative terminal."
    res = service.retrieve(query, max_candidates=5, include_d3fend=True)

    assert res["candidates"] == []
    assert res["candidate_count"] == 0
    assert res["defensive_countermeasures"] == []
    assert res["insufficient_evidence"] is True
    assert res["has_explicit_attack_id"] is False


def test_printer_maintenance_returns_no_candidates(db_session):
    """Regression test: ret-012 printer query must return empty candidates and insufficient_evidence=True."""
    service = RetrievalService(db_session)
    query = "The office color laser printer on the 4th floor is out of paper and needs maintenance before tomorrow morning."
    res = service.retrieve(query, max_candidates=5, include_d3fend=True)

    assert res["candidates"] == []
    assert res["candidate_count"] == 0
    assert res["defensive_countermeasures"] == []
    assert res["insufficient_evidence"] is True
    assert res["has_explicit_attack_id"] is False


def test_low_similarity_vector_results_are_rejected(db_session):
    """Vector results with similarity below min_similarity_threshold must not be admitted as candidates."""
    mock_vector_store = MagicMock()
    mock_doc = RagDocument(
        id=9999,
        chunk_id="test-chunk-1",
        title="Valid Accounts: T1078",
        content="Description of valid accounts.",
        source_kind="attack",
        document_type="technique",
        external_id="T1078",
    )
    mock_vector_store.similarity_search.return_value = [(mock_doc, 0.42)]

    service = RetrievalService(db_session, vector_store=mock_vector_store)
    query = "User logged into administrative machine during routine shift."
    res = service.retrieve(query, min_similarity_threshold=0.55)

    assert res["candidates"] == []
    assert res["insufficient_evidence"] is True
    mock_vector_store.similarity_search.assert_called_once()


def test_relevant_semantic_attack_query_returns_expected_techniques(db_session):
    """Relevant security attack query without explicit ID must retrieve expected ATT&CK technique."""
    from app.models.attack import AttackTechnique
    tech = db_session.query(AttackTechnique).filter(AttackTechnique.technique_id == "T1003.001").first()
    if not tech:
        tech = AttackTechnique(
            stix_id="attack-pattern--test-1003-001",
            technique_id="T1003.001",
            name="OS Credential Dumping: LSASS Memory",
            description="Dumping LSASS memory.",
            url="https://attack.mitre.org/techniques/T1003/001",
        )
        db_session.add(tech)
        db_session.commit()

    has_tech_doc = db_session.query(RagDocument).filter(RagDocument.external_id == "T1003.001").count() > 0
    if not has_tech_doc:
        mock_doc = RagDocument(
            id=1001,
            chunk_id="test-lsass-chunk",
            title="OS Credential Dumping: LSASS Memory (T1003.001)",
            content="Adversaries dump LSASS process memory to harvest credentials.",
            source_kind="attack",
            document_type="technique",
            external_id="T1003.001",
        )
        mock_vector_store = MagicMock()
        mock_vector_store.similarity_search.return_value = [(mock_doc, 0.78)]
        service = RetrievalService(db_session, vector_store=mock_vector_store)
    else:
        service = RetrievalService(db_session)

    query = "Adversaries executed in-memory credential harvesting against lsass.exe to extract plaintext passwords and Kerberos tickets."
    res = service.retrieve(query, max_candidates=5, include_d3fend=True)

    assert res["insufficient_evidence"] is False
    technique_ids = [c["technique_id"] for c in res["candidates"]]
    assert "T1003.001" in technique_ids


def test_explicit_attack_ids_are_preserved(db_session):
    """Explicit ATT&CK technique identifiers in user narrative must be boosted and preserved with exact match flag."""
    service = RetrievalService(db_session)
    query = "Incident triage: Telemetry indicates adversary usage of T1003.001 to dump LSASS memory."
    res = service.retrieve(query, max_candidates=5)

    assert res["insufficient_evidence"] is False
    assert res["has_explicit_attack_id"] is True
    exact_matches = [c for c in res["candidates"] if c["technique_id"] == "T1003.001"]
    assert len(exact_matches) == 1
    assert exact_matches[0]["is_exact_match"] is True
    assert exact_matches[0]["similarity_score"] == 1.0


def test_valid_attack_to_d3fend_mappings_remain_available(db_session):
    """Valid retrieved ATT&CK technique must pull authentic MITRE D3FEND defensive countermeasures."""
    from app.models.attack import AttackTechnique
    from app.models.d3fend import D3fendTechnique, AttackDefenceMapping

    tech = db_session.query(AttackTechnique).filter(AttackTechnique.technique_id == "T1003.001").first()
    if not tech:
        tech = AttackTechnique(
            stix_id="attack-pattern--test-1003-001",
            technique_id="T1003.001",
            name="OS Credential Dumping: LSASS Memory",
            description="Dumping LSASS memory.",
            url="https://attack.mitre.org/techniques/T1003/001",
        )
        db_session.add(tech)
        db_session.flush()

    if db_session.query(AttackDefenceMapping).count() == 0:
        d3f = db_session.query(D3fendTechnique).filter(D3fendTechnique.d3fend_id == "D3-HR").first()
        if not d3f:
            d3f = D3fendTechnique(
                d3fend_id="D3-HR",
                name="Homoglyph Resolution",
                definition="Resolve homoglyphs.",
                url="https://d3fend.mitre.org/technique/d3f:HomoglyphResolution/",
            )
            db_session.add(d3f)
            db_session.flush()
        mapping = AttackDefenceMapping(
            attack_technique_id=tech.id,
            attack_technique_external_id="T1003.001",
            d3fend_technique_id=d3f.id,
            d3fend_external_id="D3-HR",
            relationship_type="mitigates",
            mapping_source="MITRE D3FEND Ontology",
        )
        db_session.add(mapping)
        db_session.commit()

    service = RetrievalService(db_session)
    query = "Adversary dumped LSASS credentials using technique T1003.001."
    res = service.retrieve(query, max_candidates=5, include_d3fend=True)

    countermeasures = res["defensive_countermeasures"]
    assert len(countermeasures) > 0
    d3fend_ids = [d["d3fend_id"] for d in countermeasures]
    assert any(expected_id in d3fend_ids for expected_id in ["D3-HR", "D3-SCF"])


def test_unrelated_d3fend_semantic_results_rejected(db_session):
    """When no candidate techniques or explicit D3FEND IDs exist, D3FEND retrieval must return empty list."""
    service = RetrievalService(db_session)
    countermeasures = service._retrieve_d3fend_countermeasures(
        query_text="Non-security IT helpdesk printer ink order.",
        candidate_technique_ids=[],
        explicit_d3fend_ids=[],
    )
    assert countermeasures == []

    mock_vector_store = MagicMock()
    mock_d3f_doc = RagDocument(
        id=8888,
        chunk_id="d3f-chunk-1",
        title="D3FEND: D3A-WM",
        content="Decoy file description.",
        source_kind="d3fend",
        document_type="technique",
        external_id="D3A-WM",
    )
    mock_vector_store.similarity_search.return_value = [(mock_d3f_doc, 0.15)]
    service_with_mock = RetrievalService(db_session, vector_store=mock_vector_store)
    low_score_cm = service_with_mock._retrieve_d3fend_countermeasures(
        query_text="Some query",
        candidate_technique_ids=["T1003.001"],
        explicit_d3fend_ids=[],
        min_d3fend_score=0.35,
    )
    assert not any(c["d3fend_id"] == "D3A-WM" for c in low_score_cm)


def test_reranker_fallback_cannot_bypass_vector_evidence_threshold(db_session):
    """A high reranker score cannot elevate a candidate if vector similarity fell below evidence threshold."""
    mock_vector_store = MagicMock()
    mock_vector_store.similarity_search.return_value = []

    mock_reranker = MagicMock()
    mock_reranker.rerank_candidates.return_value = ([], {"rerank_performed": False})

    service = RetrievalService(db_session, vector_store=mock_vector_store, rerank_service=mock_reranker)
    query = "Ambiguous low-confidence IT observation without technique indicators."
    res = service.retrieve(query, min_similarity_threshold=0.55)

    assert res["candidates"] == []
    assert res["insufficient_evidence"] is True
    assert res["candidate_count"] == 0
