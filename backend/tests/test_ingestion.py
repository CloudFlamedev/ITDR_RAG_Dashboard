import pytest
from app.services.attack_ingestion_service import AttackIngestionService, evaluate_identity_relevance
from app.services.d3fend_ingestion_service import D3fendIngestionService


def test_evaluate_identity_relevance():
    # Direct account keyword
    assert evaluate_identity_relevance("Valid Accounts", "Adversaries obtain credentials", ["Windows"], ["initial-access"]) is True
    # Identity platform
    assert evaluate_identity_relevance("Some Technique", "Description", ["Azure AD"], []) is True
    # Non-identity technique
    assert evaluate_identity_relevance("Screen Capture", "Adversary captures display framebuffer", ["Linux"], ["collection"]) is False


def test_invalid_stix_bundle_rejection(db_session):
    service = AttackIngestionService(db_session)
    with pytest.raises(ValueError):
        service.ingest_bundle({"type": "not-a-bundle"})


def test_invalid_d3fend_bundle_rejection(db_session):
    service = D3fendIngestionService(db_session)
    with pytest.raises(ValueError):
        service.ingest_data({"invalid": True})


def test_idempotent_stix_ingestion(db_session):
    service = AttackIngestionService(db_session)
    mini_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test-idempotent",
                "name": "Test Technique Idempotency",
                "description": "Test description",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ]
            }
        ]
    }
    # Run twice
    res1 = service.ingest_bundle(mini_bundle)
    res2 = service.ingest_bundle(mini_bundle)

    assert res1["techniques_created"] == 1 or res1["techniques_updated"] == 1
    assert res2["techniques_updated"] == 1
