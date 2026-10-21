import pytest
from app.models.attack import AttackTechnique, AttackTactic
from app.models.coverage import DetectionRule, DetectionRuleTechnique
from app.models.d3fend import D3fendTechnique
from app.models.feeds import ThreatFeed, ThreatScenario


def test_attack_technique_model(db_session):
    tech = db_session.query(AttackTechnique).first()
    assert tech is not None
    assert tech.technique_id.startswith("T")
    assert tech.name is not None
    assert isinstance(tech.is_identity_relevant, bool)


def test_detection_rule_mappings(db_session):
    rules = db_session.query(DetectionRule).all()
    assert len(rules) > 0
    # Verify rule tools
    tools = set(r.tool for r in rules)
    assert "CrowdStrike" in tools or "Defender for Identity" in tools or "Okta" in tools

    # Verify many-to-many relationship
    mappings = db_session.query(DetectionRuleTechnique).all()
    assert len(mappings) > 0
    sample_mapping = mappings[0]
    assert sample_mapping.rule is not None
    assert sample_mapping.technique is not None


def test_d3fend_model(db_session):
    d3f = db_session.query(D3fendTechnique).first()
    assert d3f is not None
    assert d3f.d3fend_id.startswith("D3")
    assert d3f.name is not None


def test_threat_feed_and_scenario_models(db_session):
    feed = db_session.query(ThreatFeed).first()
    assert feed is not None
    assert feed.bulletin_id.startswith("TB-")

    scen = db_session.query(ThreatScenario).first()
    assert scen is not None
    assert 0 <= scen.detection_rate <= 100
    assert 0 <= scen.mitigation_rate <= 100
    assert scen.status in ["Resilient", "Paper Tiger", "High Risk", "Silent Well"]
