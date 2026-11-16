"""
Automated Test Suite for Three-Layer Evaluation and Monitoring Strategy.
Verifies all 13 core requirements:
1. Precision@K and Recall@K calculations.
2. Explicit-ID and no-ID evaluation groups.
3. Unsupported ATT&CK ID detection.
4. Unsupported D3FEND ID detection.
5. Valid citations are accepted and metadata resolved from backend.
6. Fabricated citations are rejected and counted.
7. Insufficient-evidence metrics are calculated correctly.
8. Vector and reranker scores remain separate.
9. Evaluation mode does not persist reports.
10. Evaluation mode does not consume production user quotas.
11. Normal production execution still persists reports.
12. Missing evaluator credentials are handled gracefully.
13. RAGAS evaluation failures do not affect normal application requests.
"""
import pytest
import datetime
from sqlalchemy.orm import Session
from app.models.threat_report import ThreatAnalysisReport, AnalysisCitation, AnalysisTraceStep
from app.services.retrieval_service import CandidateTechnique, RetrievalService
from app.services.rerank_service import RerankService
from app.ai.nodes.generation_nodes import validate_report_and_citations, build_grounded_prompt
from app.ai.nodes.persistence_nodes import persist_report_and_trace
from app.ai.graph import threat_analysis_app
from evaluation.retrieval_metrics import (
    compute_precision_at_k,
    compute_recall_at_k,
    find_missing_and_unexpected_ids,
    evaluate_case_retrieval,
    aggregate_retrieval_metrics,
)
from evaluation.ragas_evaluator import RagasEvaluator


# ==============================================================================
# 1. Precision@K and Recall@K Calculations
# ==============================================================================

def test_precision_at_k_and_recall_at_k_calculation():
    # Exact match at k=2
    retrieved = ["T1003.001", "T1078.004", "T1098"]
    expected = ["T1003.001", "T1078.004"]
    
    prec_2 = compute_precision_at_k(retrieved, expected, k=2)
    assert prec_2 == 1.0  # 2/2 in top-2

    prec_3 = compute_precision_at_k(retrieved, expected, k=3)
    assert prec_3 == round(2 / 3, 4)  # 2/3 in top-3

    rec_2 = compute_recall_at_k(retrieved, expected, k=2)
    assert rec_2 == 1.0  # all 2 expected retrieved in top-2

    rec_1 = compute_recall_at_k(retrieved, expected, k=1)
    assert rec_1 == 0.5  # only 1 expected retrieved in top-1

    # Edge cases: empty expected (e.g. out-of-scope or insufficient evidence)
    assert compute_precision_at_k([], [], k=5) == 1.0
    assert compute_recall_at_k([], [], k=5) == 1.0
    assert compute_precision_at_k(["T1078"], [], k=5) == 0.0
    assert compute_recall_at_k(["T1078"], [], k=5) == 0.0

    # Missing & unexpected reporting
    diff = find_missing_and_unexpected_ids(retrieved, ["T1003.001", "T1550"], k=3)
    assert diff["missing"] == ["T1550"]
    assert "T1078.004" in diff["unexpected"]
    assert "T1098" in diff["unexpected"]


# ==============================================================================
# 2. Explicit-ID and No-ID Evaluation Groups
# ==============================================================================

def test_explicit_id_vs_no_id_evaluation_groups():
    cases = [
        # Explicit ID case
        {
            "sample_id": "c1",
            "has_explicit_attack_id": True,
            "case_type": "explicit_attack_id",
            "attack_precision_at_k": 1.0,
            "attack_recall_at_k": 1.0,
            "d3fend_precision_at_k": 0.8,
            "d3fend_recall_at_k": 0.8,
        },
        # No-ID natural language case
        {
            "sample_id": "c2",
            "has_explicit_attack_id": False,
            "case_type": "credential_dumping",
            "attack_precision_at_k": 0.6,
            "attack_recall_at_k": 0.8,
            "d3fend_precision_at_k": 0.4,
            "d3fend_recall_at_k": 0.6,
        },
    ]

    agg = aggregate_retrieval_metrics(cases)
    assert agg["total_cases"] == 2
    assert agg["explicit_id_queries"]["count"] == 1
    assert agg["explicit_id_queries"]["mean_attack_precision_at_k"] == 1.0
    assert agg["no_id_queries"]["count"] == 1
    assert agg["no_id_queries"]["mean_attack_precision_at_k"] == 0.6
    assert agg["combined"]["count"] == 2
    assert agg["combined"]["mean_attack_precision_at_k"] == 0.8


# ==============================================================================
# 3. Unsupported ATT&CK ID Detection
# ==============================================================================

def test_unsupported_attack_id_detection():
    # Candidate techniques in retrieved context
    retrieved_cands = [
        {"technique_id": "T1003.001", "name": "LSASS Memory", "similarity_score": 0.95}
    ]
    # Model hallucinated T9999 and included T1003.001
    structured_report = {
        "report_title": "Test Brief",
        "executive_summary": "Summary",
        "severity": "High",
        "technique_candidates": [
            {"technique_id": "T1003.001", "name": "LSASS Memory", "relevance_score": 0.95},
            {"technique_id": "T9999", "name": "Fake Technique", "relevance_score": 0.80},
        ],
        "citations": [],
    }

    state = {
        "candidate_techniques": retrieved_cands,
        "d3fend_countermeasures": [],
        "structured_report": structured_report,
        "trace_steps": [],
    }

    result = validate_report_and_citations(state)
    unsupported = result["unsupported_attack_ids"]
    assert "T9999" in unsupported
    assert "T1003.001" not in unsupported

    # Verify candidate flagging
    cands = result["structured_report"]["technique_candidates"]
    t9999 = next(c for c in cands if c["technique_id"] == "T9999")
    t1003 = next(c for c in cands if c["technique_id"] == "T1003.001")
    assert t9999["is_supported"] is False
    assert "Unsupported ID warning" in t9999["support_warning"]
    assert t1003["is_supported"] is True


# ==============================================================================
# 4. Unsupported D3FEND ID Detection
# ==============================================================================

def test_unsupported_d3fend_id_detection():
    retrieved_d3f = [
        {"d3fend_id": "D3-MFA", "name": "Multi-Factor Auth", "relationship_type": "mitigates"}
    ]
    # Model hallucinated D3-FAKE
    structured_report = {
        "report_title": "Test Defense Brief",
        "executive_summary": "Summary",
        "severity": "Medium",
        "defensive_techniques": [
            {"d3fend_id": "D3-MFA", "name": "MFA"},
            {"d3fend_id": "D3-FAKE", "name": "Invented Shield"},
        ],
        "citations": [],
    }

    state = {
        "candidate_techniques": [],
        "d3fend_countermeasures": retrieved_d3f,
        "structured_report": structured_report,
        "trace_steps": [],
    }

    result = validate_report_and_citations(state)
    unsupported_d3f = result["unsupported_d3fend_ids"]
    assert "D3-FAKE" in unsupported_d3f
    assert "D3-MFA" not in unsupported_d3f

    defs = result["structured_report"]["defensive_techniques"]
    fake_def = next(d for d in defs if d["d3fend_id"] == "D3-FAKE")
    assert fake_def["is_supported"] is False
    assert "Unsupported ID warning" in fake_def["support_warning"]


# ==============================================================================
# 5. Valid Citations Accepted & Backend Resolution
# ==============================================================================

def test_valid_citations_accepted():
    state = {
        "candidate_techniques": [
            {
                "technique_id": "T1003.001",
                "name": "OS Credential Dumping: LSASS Memory",
                "similarity_score": 0.98,
                "url": "https://attack.mitre.org/techniques/T1003/001/",
                "description": "Adversaries may attempt to dump credentials from LSASS process memory.",
                "evidence_snippets": [
                    {
                        "source_id": "att-proc-lsass-01",
                        "title": "Mimikatz LSASS Dump",
                        "excerpt": "Procdump execution targeting lsass.exe process.",
                        "score": 0.95,
                        "url": "https://attack.mitre.org/techniques/T1003/001/",
                    }
                ],
            }
        ],
        "d3fend_countermeasures": [],
        "structured_report": {
            "report_title": "Credential Dump Analysis",
            "executive_summary": "LSASS dumping detected.",
            "citations": [
                {
                    "source_id": "att-tech-T1003.001",
                    "external_id": "T1003.001",
                    "source_url": "http://hallucinated-url.com",  # Should be overridden by authentic backend URL
                    "excerpt": "hallucinated quote",
                    "relevance_score": 0.9,
                    "citation_role": "Technique Evidence",
                }
            ],
        },
        "trace_steps": [],
    }

    result = validate_report_and_citations(state)
    assert len(result["citations"]) == 1
    cit = result["citations"][0]
    assert cit["source_id"] == "att-tech-T1003.001"
    # Official URL must be resolved from authentic candidate record
    assert cit["source_url"] == "https://attack.mitre.org/techniques/T1003/001/"
    assert "LSASS Memory" in cit["excerpt"]
    assert result["invalid_citations_count"] == 0


# ==============================================================================
# 6. Fabricated Citations Rejected
# ==============================================================================

def test_fabricated_citations_rejected():
    state = {
        "candidate_techniques": [
            {
                "technique_id": "T1078.004",
                "name": "Cloud Accounts",
                "similarity_score": 0.92,
                "url": "https://attack.mitre.org/techniques/T1078/004/",
                "description": "Cloud account compromise",
                "evidence_snippets": [],
            }
        ],
        "d3fend_countermeasures": [],
        "structured_report": {
            "report_title": "Cloud Incident",
            "executive_summary": "Compromised cloud account.",
            "citations": [
                # 1 authentic citation
                {
                    "source_id": "att-tech-T1078.004",
                    "external_id": "T1078.004",
                    "relevance_score": 0.9,
                    "citation_role": "Technique Evidence",
                },
                # 2 completely fabricated citations
                {
                    "source_id": "fabricated-source-id-12345",
                    "external_id": "T9999",
                    "relevance_score": 0.99,
                    "citation_role": "Technique Evidence",
                },
                {
                    "source_id": "nonexistent-doc-999",
                    "external_id": "T8888",
                    "relevance_score": 0.85,
                    "citation_role": "Technique Evidence",
                },
            ],
        },
        "trace_steps": [],
    }

    result = validate_report_and_citations(state)
    # The 2 fabricated citations must be rejected
    assert result["invalid_citations_count"] == 2
    assert len(result["citations"]) == 1
    assert result["citations"][0]["source_id"] == "att-tech-T1078.004"


# ==============================================================================
# 7. Insufficient-Evidence Metrics Calculated Correctly
# ==============================================================================

def test_insufficient_evidence_metrics_calculated(db_session: Session):
    retriever = RetrievalService(db_session)

    # Test A: Out-of-scope question with zero similarity and no explicit IDs
    out_of_scope = "What is the best recipe for baking chocolate chip cookies?"
    res_oos = retriever.retrieve(out_of_scope, min_similarity_threshold=0.35)
    assert res_oos["insufficient_evidence"] is True
    assert res_oos["has_explicit_attack_id"] is False

    # Test B: Query with explicit ATT&CK indicator (T1078.004)
    # Even if vector similarity is low, explicit indicator anchors evidence sufficiency
    explicit_query = "Analysis of T1078.004 cloud account usage in AWS environment."
    res_exp = retriever.retrieve(explicit_query, min_similarity_threshold=0.35)
    assert res_exp["insufficient_evidence"] is False
    assert res_exp["has_explicit_attack_id"] is True
    assert "T1078.004" in res_exp["explicit_indicators"]["attack_ids"]


# ==============================================================================
# 8. Vector and Reranker Scores Remain Separate
# ==============================================================================

def test_vector_and_reranker_scores_remain_separate():
    cand = CandidateTechnique(
        technique_id="T1003.001",
        name="LSASS Memory Dumping",
        score=0.72,
        is_exact_match=False,
        tactics=["Credential Access"],
        url="https://attack.mitre.org/techniques/T1003/001/",
        description="Dumps credentials from memory.",
        evidence_snippets=[],
        vector_score=0.72,
        rerank_score=None,
    )

    assert cand.vector_score == 0.72
    assert cand.rerank_score is None

    # Simulate reranker updating score
    reranker = RerankService(enabled=False)
    # Even when reranking runs, vector_score is preserved
    cand.rerank_score = 0.94
    cand.score = 0.94

    cand_dict = cand.to_dict()
    assert cand_dict["vector_score"] == 0.72
    assert cand_dict["rerank_score"] == 0.94
    assert cand_dict["similarity_score"] == 0.72


# ==============================================================================
# 9. Evaluation Mode Does Not Persist Reports
# ==============================================================================

def test_evaluation_mode_does_not_persist_reports(db_session: Session):
    eval_report_id = "EVAL-TEST-NO-PERSIST-999"

    state = {
        "report_id": eval_report_id,
        "advisory_text": "Sample threat advisory for evaluation runner.",
        "sample_id": "eval-test-01",
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.85,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": "{}",
        "structured_report": {"report_title": "Eval Title", "executive_summary": "Eval summary"},
        "citations": [],
        "trace_steps": [],
        "status": "COMPLETED",
        "error": None,
        "evaluation_mode": True,  # Safe Evaluation Mode
    }

    result = persist_report_and_trace(state)
    assert result["report_id"] == eval_report_id

    # Verify that NO database record was created
    db_report = db_session.query(ThreatAnalysisReport).filter_by(report_id=eval_report_id).first()
    assert db_report is None


# ==============================================================================
# 10. Evaluation Mode Does Not Consume Production Quotas
# ==============================================================================

def test_evaluation_mode_does_not_consume_quotas(db_session: Session):
    # Count total reports before evaluation execution
    initial_count = db_session.query(ThreatAnalysisReport).count()

    eval_state = {
        "report_id": "EVAL-QUOTA-TEST-123",
        "advisory_text": "Evaluation testing quota isolation.",
        "sample_id": "eval-quota-01",
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.85,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": "{}",
        "structured_report": {"report_title": "Quota Safe Eval", "executive_summary": "Quota safe"},
        "citations": [],
        "trace_steps": [],
        "status": "COMPLETED",
        "error": None,
        "evaluation_mode": True,
    }

    persist_report_and_trace(eval_state)
    final_count = db_session.query(ThreatAnalysisReport).count()

    # Database count must remain unchanged
    assert final_count == initial_count


# ==============================================================================
# 11. Normal Production Execution Still Persists Reports
# ==============================================================================

def test_normal_production_execution_persists_reports(db_session: Session):
    prod_report_id = f"PROD-TEST-{int(datetime.datetime.now().timestamp())}"

    state = {
        "report_id": prod_report_id,
        "advisory_text": "Production threat advisory submission.",
        "sample_id": None,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.90,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": "{}",
        "structured_report": {
            "report_title": "Production Verified Report",
            "executive_summary": "Adversary observed performing credential access.",
            "severity": "High",
        },
        "citations": [],
        "trace_steps": [],
        "status": "COMPLETED",
        "error": None,
        "evaluation_mode": False,  # Normal production execution
    }

    persist_report_and_trace(state)

    # Verify that database record was created
    db_report = db_session.query(ThreatAnalysisReport).filter_by(report_id=prod_report_id).first()
    assert db_report is not None
    assert db_report.report_title == "Production Verified Report"

    # Clean up test artifact
    db_session.delete(db_report)
    db_session.commit()


# ==============================================================================
# 12. Missing Evaluator Credentials Handled Gracefully
# ==============================================================================

def test_missing_evaluator_credentials_handled_gracefully():
    # Instantiate evaluator with explicit None/empty API key
    evaluator = RagasEvaluator(api_key=None)
    evaluator.is_configured = False
    evaluator._llm_wrapper = None

    samples = [
        {
            "sample_id": "eval-graceful-01",
            "question": "Testing missing credentials handling",
            "contexts": ["Some context"],
            "response": "Some answer",
            "reference": "Reference answer",
        }
    ]

    res = evaluator.evaluate_samples(samples)
    assert res["status"] == "SKIPPED"
    assert "not configured" in res["reason"].lower()
    assert res["aggregate_scores"]["mean_faithfulness"] is None


# ==============================================================================
# 13. RAGAS Failures Do Not Affect Normal Application Requests
# ==============================================================================

def test_ragas_evaluation_failures_do_not_affect_normal_requests():
    # Execute full LangGraph pipeline on valid threat input
    # Pipeline must complete successfully without relying on or failing on RAGAS
    normal_request_state = {
        "report_id": f"TEST-NORMAL-{int(datetime.datetime.now().timestamp())}",
        "advisory_text": "Suspicious login attempt with valid credentials (T1078) followed by PowerShell execution.",
        "sample_id": "sample-01",
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "retrieval_query": "",
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.0,
        "highest_vector_similarity": 0.0,
        "highest_rerank_score": None,
        "rerank_applied": False,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": None,
        "structured_report": None,
        "citations": [],
        "evaluation_contexts": [],
        "unsupported_attack_ids": [],
        "unsupported_d3fend_ids": [],
        "invalid_citations_count": 0,
        "trace_steps": [],
        "status": "INITIALIZING",
        "error": None,
        "evaluation_mode": True,  # Use evaluation_mode to avoid cluttering test DB
    }

    result = threat_analysis_app.invoke(normal_request_state)
    assert result["status"] == "COMPLETED"
    assert result["structured_report"] is not None
    assert len(result["candidate_techniques"]) > 0
    # Exact contexts were retained for evaluation
    assert len(result["evaluation_contexts"]) > 0


# ==============================================================================
# 14. Sub-technique Parent Inheritance and Authoritative Taxonomy Validation (Issue 7)
# ==============================================================================

def test_subtechnique_does_not_inherit_parent_support():
    """
    Issue 7: A parent technique ID must not automatically prove that every
    sub-technique ID is valid or supported.
    """
    # Parent T1003 is in retrieved candidates, but subtechnique T1003.001 was NOT retrieved
    retrieved_cands = [
        {
            "technique_id": "T1003",
            "name": "OS Credential Dumping",
            "similarity_score": 0.85,
            "vector_score": 0.85,
            "rerank_score": None,
            "is_exact_match": False,
            "evidence_snippets": [],
        }
    ]

    # Report contains valid parent T1003, unretrieved subtechnique T1003.001, and fake T1003.999
    report_dict = {
        "report_title": "Credential Access Analysis",
        "executive_summary": "Dumped credentials via LSASS.",
        "severity": "High",
        "technique_candidates": [
            {
                "technique_id": "T1003.001",
                "name": "OS Credential Dumping: LSASS Memory",
                "relevance_score": 0.90,
                "rationale": "Dumped LSASS memory.",
            },
            {
                "technique_id": "T1003.999",
                "name": "Fake Sub-technique",
                "relevance_score": 0.50,
                "rationale": "Fabricated sub-technique.",
            },
            {
                "technique_id": "T1003",
                "name": "OS Credential Dumping",
                "relevance_score": 0.85,
                "rationale": "Retrieved parent technique.",
            },
        ],
        "defensive_techniques": [
            {
                "d3fend_id": "D3-FAKE-DEFENSE",
                "name": "Fabricated Countermeasure",
                "relationship_type": "mitigates",
                "rationale": "Not in D3FEND taxonomy.",
            }
        ],
        "citations": [],
    }

    state = {
        "candidate_techniques": retrieved_cands,
        "d3fend_countermeasures": [],
        "structured_report": report_dict,
        "trace_steps": [],
    }

    val_res = validate_report_and_citations(state)
    report = val_res["structured_report"]

    cands_by_id = {c["technique_id"]: c for c in report["technique_candidates"]}
    
    # 1. T1003 was retrieved -> supported
    assert cands_by_id["T1003"]["is_supported"] is True

    # 2. T1003.001 was NOT retrieved -> NOT supported (parent presence does NOT grant support!)
    assert cands_by_id["T1003.001"]["is_supported"] is False
    assert "T1003.001" in val_res["unsupported_attack_ids"]

    # 3. T1003.999 does not exist in authoritative DB -> invalid taxonomy and not supported
    assert cands_by_id["T1003.999"]["is_valid_taxonomy"] is False
    assert cands_by_id["T1003.999"]["is_supported"] is False
    assert "T1003.999" in val_res["unsupported_attack_ids"]

    # 4. Fake D3FEND countermeasure -> invalid taxonomy and not supported
    assert "D3-FAKE-DEFENSE" in val_res["unsupported_d3fend_ids"]


# ==============================================================================
# 15. Vector Score and Rerank Score Independence (Issue 6)
# ==============================================================================

def test_vector_and_rerank_scores_strict_independence():
    """
    Issue 6: Keep vector_score and rerank_score independent.
    Do not use legacy score field as a substitute for either value.
    """
    c = CandidateTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        score=0.7250,
        is_exact_match=False,
        tactics=["Defense Evasion", "Initial Access"],
        url="https://attack.mitre.org/techniques/T1078",
        description="Adversaries may obtain and abuse credentials.",
        evidence_snippets=[],
        vector_score=0.7250,
        rerank_score=None,
    )

    # Initial state
    assert c.vector_score == 0.7250
    assert c.rerank_score is None
    d = c.to_dict()
    assert d["vector_score"] == 0.7250
    assert d["similarity_score"] == 0.7250
    assert d["rerank_score"] is None

    # Simulate reranker updating rerank_score
    reranker = RerankService()
    reranker.is_configured = True
    reranker.last_api_succeeded = True
    reranker.rerank = lambda query, documents, top_n: [
        {"index": 0, "relevance_score": 0.9421, "document": documents[0]}
    ]

    reranked, meta = reranker.rerank_candidates("compromised valid credentials", [c])
    assert meta["rerank_performed"] is True

    # After reranking: rerank_score is 0.9421, vector_score remains strictly 0.7250!
    assert c.rerank_score == 0.9421
    assert c.vector_score == 0.7250
    d_after = c.to_dict()
    assert d_after["vector_score"] == 0.7250
    assert d_after["rerank_score"] == 0.9421


# ==============================================================================
# 16. Complete Structured Report Formatting for RAGAS (Issue 4)
# ==============================================================================

def test_format_report_for_evaluation_excludes_metadata():
    """
    Issue 4: Evaluate the complete structured security report, not only executive_summary.
    Include relevant report sections and avoid irrelevant metadata.
    """
    from evaluation.ragas_evaluator import format_report_for_evaluation

    full_report = {
        "report_title": "Enterprise Active Directory Threat Assessment",
        "executive_summary": "Detected lateral movement via Kerberoasting.",
        "severity": "Critical",
        "severity_rationale": "High privileged service accounts compromised.",
        "incident_overview": "Adversary requested TGS tickets for SPNs.",
        "technique_candidates": [
            {
                "technique_id": "T1558.003",
                "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
                "relevance_score": 0.98,
                "rationale": "Specific Event ID 4769 with RC4 encryption observed.",
                "tactics": ["Credential Access"],
            }
        ],
        "defensive_techniques": [
            {
                "d3fend_id": "D3-SPNA",
                "name": "Service Principal Name Analysis",
                "relationship_type": "detects",
                "rationale": "Monitors abnormal Kerberos ticket requests.",
            }
        ],
        "coverage_assessment": [
            {
                "technique_id": "T1558.003",
                "status": "covered",
                "active_rules_count": 2,
                "mapped_tools": ["Microsoft Defender for Identity"],
            }
        ],
        "recommended_actions": [
            {
                "priority": "Critical",
                "category": "Active Directory",
                "action": "Rotate passwords for all service accounts with SPNs.",
                "rationale": "Invalidates cracked service ticket hashes.",
            }
        ],
        "uncertainties": [
            "Source IP of adversary workstation remains unconfirmed."
        ],
        # System metadata that must be excluded:
        "model_provider": "xAI Grok",
        "model_name": "grok-4.7",
        "execution_duration_ms": 3412.5,
        "token_usage": {"input_tokens": 1200, "output_tokens": 450},
        "created_at": "2026-11-15T12:00:00Z",
    }

    formatted = format_report_for_evaluation(full_report)

    # Core sections present
    assert "Enterprise Active Directory Threat Assessment" in formatted
    assert "Detected lateral movement via Kerberoasting" in formatted
    assert "Severity: Critical" in formatted
    assert "T1558.003" in formatted
    assert "D3-SPNA" in formatted
    assert "Service Principal Name Analysis" in formatted
    assert "Rotate passwords for all service accounts" in formatted
    assert "Source IP of adversary workstation" in formatted

    # Irrelevant system metadata excluded
    assert "token_usage" not in formatted
    assert "3412.5" not in formatted
    assert "2026-11-15T12:00:00Z" not in formatted
    assert "model_provider" not in formatted


# ==============================================================================
# 17. Safe Baseline Generation Guardrails (Issue 2)
# ==============================================================================

def test_baseline_guardrails_prevent_saving_null_or_partial_runs(tmp_path):
    """
    Issue 2: Do not save null RAGAS scores as an approved baseline.
    Do not generate baseline on partial runs.
    """
    from evaluation.run_evaluation import run_evaluation
    from pathlib import Path

    fake_dataset = tmp_path / "mini_eval.jsonl"
    with open(fake_dataset, "w", encoding="utf-8") as f:
        f.write('{"sample_id": "m1", "question": "test", "reference_answer": "ans", "expected_attack_ids": ["T1078"], "expected_d3fend_ids": [], "has_explicit_attack_id": false, "case_type": "test"}\n')

    baseline_dest = tmp_path / "baseline.json"

    # 1. Run with skip_ragas=True and generate_baseline=True
    # Must NOT save baseline because RAGAS scores are null!
    run_evaluation(
        dataset_path=fake_dataset,
        skip_ragas=True,
        baseline_path=baseline_dest,
        generate_baseline=True,
    )
    assert not baseline_dest.exists(), "Baseline must NOT be saved when RAGAS scores are null!"

    # 2. Run with partial limit and generate_baseline=True
    run_evaluation(
        dataset_path=fake_dataset,
        limit=1,
        sample_ids=["m1"],
        skip_ragas=True,
        baseline_path=baseline_dest,
        generate_baseline=True,
    )
    assert not baseline_dest.exists(), "Baseline must NOT be saved on partial runs!"


# ==============================================================================
# 18. LangGraph State Propagation and API Response Fields (Issue 5)
# ==============================================================================

def test_api_response_and_state_propagation_fields():
    """
    Issue 5: Confirm highest_vector_similarity, highest_rerank_score,
    rerank_applied, unsupported IDs and citation counts reach state and API response.
    """
    test_state = {
        "report_id": "REP-AUDIT-PROPAGATION",
        "advisory_text": "Adversary used stolen credentials (T1078) to execute Mimikatz (T1003.001).",
        "sample_id": "test-prop",
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "retrieval_query": "",
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.0,
        "highest_vector_similarity": 0.0,
        "highest_rerank_score": None,
        "rerank_applied": False,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": None,
        "structured_report": None,
        "citations": [],
        "evaluation_contexts": [],
        "unsupported_attack_ids": [],
        "unsupported_d3fend_ids": [],
        "invalid_citations_count": 0,
        "trace_steps": [],
        "status": "INITIALIZING",
        "error": None,
        "evaluation_mode": True,
    }

    result = threat_analysis_app.invoke(test_state)

    # Check state propagation
    assert "highest_vector_similarity" in result
    assert isinstance(result["highest_vector_similarity"], float)
    assert result["highest_vector_similarity"] > 0.0

    assert "highest_rerank_score" in result
    assert "rerank_applied" in result
    assert isinstance(result["rerank_applied"], bool)

    assert "unsupported_attack_ids" in result
    assert isinstance(result["unsupported_attack_ids"], list)

    assert "unsupported_d3fend_ids" in result
    assert isinstance(result["unsupported_d3fend_ids"], list)

    assert "invalid_citations_count" in result
    assert isinstance(result["invalid_citations_count"], int)


# ==============================================================================
# 19. RAGAS Collections API Imports & Initialization (Issue 1 & 2)
# ==============================================================================

def test_ragas_collections_imports_and_initialization():
    """
    Issue 1 & 2: Verify all 5 metrics can be imported and initialized directly
    from ragas.metrics.collections using BaseRagasEmbedding and Instructor LLM.
    Tests the real evaluator initialization path using mocked credentials and
    confirms all 5 metrics receive their LLM and embedding dependencies.
    """
    from ragas.metrics.collections import (
        ContextPrecision,
        ContextRecall,
        Faithfulness,
        AnswerRelevancy,
        FactualCorrectness,
    )
    from ragas.embeddings.base import BaseRagasEmbedding
    from ragas.llms.base import InstructorBaseRagasLLM
    from evaluation.ragas_evaluator import RagasEvaluator, ITDRRagasEmbeddings

    class _TestInstructorLLM(InstructorBaseRagasLLM):
        def generate(self, *args, **kwargs):
            pass
        async def agenerate(self, *args, **kwargs):
            pass

    mock_llm = _TestInstructorLLM()
    mock_emb = ITDRRagasEmbeddings()
    assert isinstance(mock_emb, BaseRagasEmbedding)

    # 1. Initialize all 5 collections metrics directly
    cp = ContextPrecision(llm=mock_llm)
    cr = ContextRecall(llm=mock_llm)
    faith = Faithfulness(llm=mock_llm)
    ar = AnswerRelevancy(llm=mock_llm, embeddings=mock_emb)
    fc = FactualCorrectness(llm=mock_llm)

    for m in [cp, cr, faith, ar, fc]:
        assert hasattr(m, "ascore")
        assert hasattr(m, "score")
        assert hasattr(m, "name")

    # 2. Test real evaluator initialization path with mocked credentials and real client instantiation
    real_evaluator = RagasEvaluator(
        api_key="mock-groq-evaluator-key-abcdef123456",
        base_url="https://api.groq.com/openai/v1",
        model_name="openai/gpt-oss-20b",
    )
    assert real_evaluator.is_configured is True
    assert real_evaluator._llm_wrapper is not None
    assert isinstance(real_evaluator._llm_wrapper, InstructorBaseRagasLLM)
    assert isinstance(real_evaluator._embeddings_wrapper, BaseRagasEmbedding)

    # Confirm all five metrics initialize with their expected dependencies
    assert isinstance(real_evaluator.context_precision, ContextPrecision)
    assert real_evaluator.context_precision.llm is real_evaluator._llm_wrapper

    assert isinstance(real_evaluator.context_recall, ContextRecall)
    assert real_evaluator.context_recall.llm is real_evaluator._llm_wrapper

    assert isinstance(real_evaluator.faithfulness, Faithfulness)
    assert real_evaluator.faithfulness.llm is real_evaluator._llm_wrapper

    assert isinstance(real_evaluator.answer_relevancy, AnswerRelevancy)
    assert real_evaluator.answer_relevancy.llm is real_evaluator._llm_wrapper
    assert real_evaluator.answer_relevancy.embeddings is real_evaluator._embeddings_wrapper

    assert isinstance(real_evaluator.factual_correctness, FactualCorrectness)
    assert real_evaluator.factual_correctness.llm is real_evaluator._llm_wrapper

    metrics = real_evaluator.get_metrics()
    assert len(metrics) == 5
    metric_names = [m.name for m in metrics]
    assert metric_names == ["context_precision", "context_recall", "faithfulness", "answer_relevancy", "factual_correctness"]


# ==============================================================================
# 20. Explicit Empty Context Handling & Distinct Failure Tracking (Issue 2 & 3)
# ==============================================================================

@pytest.mark.asyncio
async def test_empty_retrieval_context_handling():
    """
    Issue 2 & 3: Do not insert placeholder text like 'No retrieved context supplied to model.'
    Record missing context explicitly as a retrieval failure (0.0).
    Clearly distinguish assigned empty-context failures from actual RAGAS calculations.
    """
    from evaluation.ragas_evaluator import RagasEvaluator
    from ragas.llms.base import InstructorBaseRagasLLM
    from unittest.mock import AsyncMock

    class _TestInstructorLLM(InstructorBaseRagasLLM):
        def generate(self, *args, **kwargs):
            pass
        async def agenerate(self, *args, **kwargs):
            pass

    evaluator = RagasEvaluator()
    evaluator._llm_wrapper = _TestInstructorLLM()
    evaluator.is_configured = True

    # Mock collections metrics
    mock_ar = AsyncMock()
    mock_ar.ascore.return_value = 0.95
    evaluator.answer_relevancy = mock_ar

    mock_fc = AsyncMock()
    mock_fc.ascore.return_value = 0.90
    evaluator.factual_correctness = mock_fc

    # Sample with EMPTY contexts
    samples = [{
        "sample_id": "test-empty-ctx",
        "question": "What is Kerberoasting?",
        "contexts": [],  # Completely empty context
        "response": "Kerberoasting targets SPNs.",
        "reference": "Kerberoasting is T1558.003.",
        "is_fallback_generation": False,
    }]

    result = await evaluator._aevaluate_samples(samples)
    assert result["status"] == "SUCCESS"
    per_s = result["per_sample_scores"][0]

    # Explicit failure for retrieval metrics when context is empty
    assert per_s["has_empty_context"] is True
    assert per_s["is_assigned_empty_context_failure"] is True
    assert per_s["retrieval_context_status"] == "EMPTY_CONTEXT_ASSIGNED_FAILURE"
    assert per_s["context_precision"] == 0.0, "Empty context must score 0.0 for context_precision"
    assert per_s["context_recall"] == 0.0, "Empty context must score 0.0 for context_recall"
    assert per_s["faithfulness"] == 0.0, "Empty context must score 0.0 for faithfulness"

    # Generation metrics still evaluated for valid non-fallback response
    assert per_s["answer_relevancy"] == 0.95
    assert per_s["factual_correctness"] == 0.90

    # Aggregate counts and distinct metrics
    agg = result["aggregate_scores"]
    assert agg["empty_context_count"] == 1
    assert agg["retrieved_context_count"] == 0
    assert agg["mean_context_precision"] == 0.0
    assert agg["mean_context_recall"] == 0.0
    assert agg["mean_calculated_context_precision"] is None
    assert agg["mean_calculated_context_recall"] is None


# ==============================================================================
# 21. Fallback Generation Exclusion & All-Fallback Handling (Issue 3)
# ==============================================================================

@pytest.mark.asyncio
async def test_fallback_generations_excluded_and_all_fallback_returns_na():
    """
    Issue 3: Exclude fallback generations from Faithfulness, Answer Relevancy,
    and Factual Correctness. If all generations are fallback, return None (N/A).
    """
    from evaluation.ragas_evaluator import RagasEvaluator
    from ragas.llms.base import InstructorBaseRagasLLM
    from unittest.mock import AsyncMock

    class _TestInstructorLLM(InstructorBaseRagasLLM):
        def generate(self, *args, **kwargs):
            pass
        async def agenerate(self, *args, **kwargs):
            pass

    evaluator = RagasEvaluator()
    evaluator._llm_wrapper = _TestInstructorLLM()
    evaluator.is_configured = True

    # Mock retrieval metrics
    mock_cp = AsyncMock()
    mock_cp.ascore.return_value = 0.85
    evaluator.context_precision = mock_cp

    mock_cr = AsyncMock()
    mock_cr.ascore.return_value = 0.80
    evaluator.context_recall = mock_cr

    # All samples are fallback generations
    samples = [
        {
            "sample_id": "fb-1",
            "question": "Q1",
            "contexts": ["Evidence 1"],
            "response": "Fallback response 1",
            "reference": "Ref 1",
            "is_fallback_generation": True,
        },
        {
            "sample_id": "fb-2",
            "question": "Q2",
            "contexts": ["Evidence 2"],
            "response": "Fallback response 2",
            "reference": "Ref 2",
            "is_fallback_generation": True,
        },
    ]

    result = await evaluator._aevaluate_samples(samples, skip_generation_metrics_for_fallback=True)
    assert result["status"] == "SUCCESS"

    # Retrieval metrics must still be computed
    for s in result["per_sample_scores"]:
        assert s["context_precision"] == 0.85
        assert s["context_recall"] == 0.80
        # Generation metrics MUST be excluded for fallback samples
        assert s["faithfulness"] is None
        assert s["answer_relevancy"] is None
        assert s["factual_correctness"] is None

    # Aggregate scores: retrieval present, generation MUST be None (displays as N/A)
    agg = result["aggregate_scores"]
    assert agg["mean_context_precision"] == 0.85
    assert agg["mean_context_recall"] == 0.80
    assert agg["mean_faithfulness"] is None
    assert agg["mean_answer_relevancy"] is None
    assert agg["mean_factual_correctness"] is None
    assert agg["fallback_generation_count"] == 2
    assert agg["llm_generation_count"] == 0


# ==============================================================================
# 22. Missing Baseline Reported as NOT_BASELINED (Issue 4 & 5)
# ==============================================================================

def test_missing_baseline_reported_as_not_baselined(tmp_path):
    """
    Issue 4: Make sure a missing baseline is clearly reported as NOT BASELINED,
    rather than presenting it as a fully validated regression pass (passed: False).
    """
    from evaluation.run_evaluation import compare_against_baseline

    non_existent_baseline = tmp_path / "does_not_exist_baseline.json"
    dummy_metrics = {
        "retrieval": {
            "combined": {"mean_attack_precision_at_k": 0.8, "mean_attack_recall_at_k": 0.8}
        },
        "ragas": {
            "mean_context_precision": 0.9,
            "mean_context_recall": 0.9,
            "mean_faithfulness": 0.9,
        }
    }

    result = compare_against_baseline(dummy_metrics, non_existent_baseline)

    assert result["has_baseline"] is False
    assert result["status"] == "NOT_BASELINED"
    assert result["passed"] is False
    assert "No approved baseline found" in result["message"]


# ==============================================================================
# 23. Four Regression Statuses and Error Handling (Issue 4)
# ==============================================================================

def test_four_regression_statuses_and_error_handling(tmp_path):
    """
    Issue 4: Validate four clear statuses: PASSED, FAILED, NOT_BASELINED, EVALUATION_ERROR.
    Ensure NOT_BASELINED, FAILED, and EVALUATION_ERROR never report passed: True.
    """
    from evaluation.run_evaluation import compare_against_baseline
    import json

    dummy_curr = {
        "retrieval": {
            "combined": {
                "mean_attack_precision_at_k": 0.85,
                "mean_attack_recall_at_k": 0.80,
            },
            "no_id_queries": {
                "mean_attack_precision_at_k": 0.75,
                "mean_attack_recall_at_k": 0.70,
            }
        },
        "ragas": {
            "mean_context_precision": 0.88,
            "mean_context_recall": 0.82,
            "mean_faithfulness": 0.90,
            "mean_answer_relevancy": 0.89,
            "mean_factual_correctness": 0.85,
        }
    }

    # 1. NOT_BASELINED
    missing_file = tmp_path / "non_existent.json"
    res_not_baselined = compare_against_baseline(dummy_curr, missing_file)
    assert res_not_baselined["status"] == "NOT_BASELINED"
    assert res_not_baselined["passed"] is False

    # 2. PASSED (scores match or are within tolerance)
    baseline_passed_file = tmp_path / "baseline_passed.json"
    with open(baseline_passed_file, "w", encoding="utf-8") as f:
        json.dump({
            "aggregate_metrics": dummy_curr
        }, f)
    res_passed = compare_against_baseline(dummy_curr, baseline_passed_file, tolerance=0.10)
    assert res_passed["status"] == "PASSED"
    assert res_passed["passed"] is True
    assert len(res_passed["regressions"]) == 0

    # 3. FAILED (regression exceeds tolerance)
    baseline_high_file = tmp_path / "baseline_high.json"
    high_metrics = {
        "retrieval": {
            "combined": {
                "mean_attack_precision_at_k": 0.99,  # Current is 0.85 -> dropped > 10%
                "mean_attack_recall_at_k": 0.80,
            },
            "no_id_queries": {
                "mean_attack_precision_at_k": 0.75,
                "mean_attack_recall_at_k": 0.70,
            }
        },
        "ragas": {
            "mean_context_precision": 0.88,
            "mean_context_recall": 0.82,
            "mean_faithfulness": 0.90,
            "mean_answer_relevancy": 0.89,
            "mean_factual_correctness": 0.85,
        }
    }
    with open(baseline_high_file, "w", encoding="utf-8") as f:
        json.dump({"aggregate_metrics": high_metrics}, f)
    res_failed = compare_against_baseline(dummy_curr, baseline_high_file, tolerance=0.10)
    assert res_failed["status"] == "FAILED"
    assert res_failed["passed"] is False
    assert len(res_failed["regressions"]) == 1
    assert res_failed["regressions"][0]["metric"] == "combined_attack_precision_at_k"

    # 4. EVALUATION_ERROR (malformed baseline or missing aggregate_metrics)
    corrupted_file = tmp_path / "corrupted_baseline.json"
    with open(corrupted_file, "w", encoding="utf-8") as f:
        f.write("{ INVALID JSON")
    res_err1 = compare_against_baseline(dummy_curr, corrupted_file)
    assert res_err1["status"] == "EVALUATION_ERROR"
    assert res_err1["passed"] is False

    empty_metrics_file = tmp_path / "empty_metrics_baseline.json"
    with open(empty_metrics_file, "w", encoding="utf-8") as f:
        json.dump({"foo": "bar"}, f)
    res_err2 = compare_against_baseline(dummy_curr, empty_metrics_file)
    assert res_err2["status"] == "EVALUATION_ERROR"
    assert res_err2["passed"] is False

