from typing import TypedDict, List, Dict, Any, Optional


class ThreatAnalysisState(TypedDict, total=False):
    """
    Typed execution state for the 11-node LangGraph Threat Analysis workflow.
    Tracks input telemetry, extracted entities, retrieved candidates, citations,
    validated report output, monitoring validation signals, and step execution timing.
    """
    # Request Input
    report_id: str
    advisory_text: str
    sample_id: Optional[str]
    client_restriction: str
    itdr_scope: str
    view_mode: str
    include_d3fend: bool
    max_technique_candidates: int
    created_by_user_id: Optional[int]

    # Entity Extraction
    extracted_indicators: Dict[str, Any]
    retrieval_query: str

    # Retrieval Context & Monitoring Scores
    candidate_techniques: List[Dict[str, Any]]
    d3fend_countermeasures: List[Dict[str, Any]]
    coverage_records: List[Dict[str, Any]]
    highest_retrieval_confidence: float
    highest_vector_similarity: float
    highest_rerank_score: Optional[float]
    rerank_applied: bool
    insufficient_evidence: bool

    # LLM Interaction & Grounded Context Preservation
    prompt_messages: List[Dict[str, str]]
    raw_llm_response: Optional[str]
    structured_report: Optional[Dict[str, Any]]
    citations: List[Dict[str, Any]]
    evaluation_contexts: List[str]  # Exact context strings supplied to LLM for RAGAS eval

    # Live Production Monitoring & Validation Guardrails
    unsupported_attack_ids: List[str]
    unsupported_d3fend_ids: List[str]
    invalid_citations_count: int
    validation_status: str  # VALIDATED, SCHEMA_REPAIRED, FALLBACK_SYNTHESIZED, UNSUPPORTED_TAXONOMY_DETECTED
    is_schema_repaired: bool
    is_fallback_generation: bool

    # AI Security Guardrails Telemetry & Status
    input_security_status: str  # CLEAN, SUSPICIOUS, BLOCKED, MONITORED
    input_security_risk: float  # 0.0 to 1.0
    input_security_findings: List[Dict[str, Any]]
    retrieved_context_security_status: str  # CLEAN, SANITIZED, UNTRUSTED_CONTENT_DETECTED, BLOCKED
    retrieved_context_findings: List[Dict[str, Any]]
    suspicious_document_ids: List[str]
    quarantined_document_ids: List[str]
    raw_retrieved_candidates: List[Dict[str, Any]]  # Preserved original evidence for auditability
    raw_retrieved_d3fend: List[Dict[str, Any]]        # Preserved original evidence for auditability
    trusted_candidate_techniques: List[Dict[str, Any]]
    trusted_d3fend_countermeasures: List[Dict[str, Any]]
    output_security_status: str  # VERIFIED, UNSAFE, LEAKAGE_DETECTED, UNGROUNDED, SCHEMA_REPAIRED, FALLBACK_UNVERIFIED
    output_security_findings: List[Dict[str, Any]]
    review_reasons: List[str]
    guardrail_metadata: Dict[str, Any]

    # Execution Trace & Status
    trace_steps: List[Dict[str, Any]]
    status: str  # INITIALIZING, PROCESSING, COMPLETED, PARTIAL, INSUFFICIENT_EVIDENCE, NEEDS_REVIEW, BLOCKED, ERROR
    error: Optional[str]
    token_usage: Optional[Dict[str, int]]

    # Explicit Provider Selection & Invocation Tracking Telemetry
    llm_provider: Optional[str]
    llm_model: Optional[str]
    provider_request_attempted: Optional[bool]
    provider_response_received: Optional[bool]
    llm_generation_succeeded: Optional[bool]
    offline_fallback_used: Optional[bool]

    # Explicit Ungrounded Detection Telemetry
    ungrounded_id_detected: Optional[bool]
    ungrounded_guardrail_intercepted: Optional[bool]

    # Safe Evaluation Execution Mode
    evaluation_mode: bool  # When True, skips report persistence and user quota tracking
