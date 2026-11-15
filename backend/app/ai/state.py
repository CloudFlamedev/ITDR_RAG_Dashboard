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

    # Execution Trace & Status
    trace_steps: List[Dict[str, Any]]
    status: str  # INITIALIZING, PROCESSING, COMPLETED, PARTIAL, INSUFFICIENT_EVIDENCE, ERROR
    error: Optional[str]

    # Safe Evaluation Execution Mode
    evaluation_mode: bool  # When True, skips report persistence and user quota tracking
