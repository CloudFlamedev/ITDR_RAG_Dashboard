import pytest
from app.ai.graph import threat_analysis_app
from app.models.threat_report import ThreatAnalysisReport


def test_full_langgraph_analysis_flow(db_session):
    report_id = "TEST-LG-FLOW-01"
    initial_state = {
        "report_id": report_id,
        "advisory_text": "Adversary gained initial access via T1078 Valid Accounts and manipulated AD group permissions using T1098.",
        "sample_id": None,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "extracted_indicators": {},
        "retrieval_query": "",
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.0,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": None,
        "structured_report": None,
        "citations": [],
        "trace_steps": [],
        "status": "INITIALIZING",
        "error": None,
    }

    result = threat_analysis_app.invoke(initial_state)

    assert result["status"] == "COMPLETED"
    assert result["structured_report"] is not None
    assert len(result["structured_report"]["technique_candidates"]) > 0
    assert len(result["citations"]) > 0
    assert len(result["trace_steps"]) >= 9

    # Verify database persistence
    saved_report = db_session.query(ThreatAnalysisReport).filter_by(report_id=report_id).first()
    assert saved_report is not None
    assert saved_report.completion_status == "COMPLETED"
    assert len(saved_report.citations) > 0
    assert len(saved_report.trace_steps) > 0


def test_empty_input_validation():
    initial_state = {
        "report_id": "TEST-EMPTY",
        "advisory_text": "",
        "sample_id": None,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "extracted_indicators": {},
        "retrieval_query": "",
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.0,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": None,
        "structured_report": None,
        "citations": [],
        "trace_steps": [],
        "status": "INITIALIZING",
        "error": None,
    }

    result = threat_analysis_app.invoke(initial_state)
    assert result["status"] in ["ERROR", "INSUFFICIENT_EVIDENCE"]
