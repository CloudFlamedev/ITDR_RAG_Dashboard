from typing import TypedDict, List, Dict, Any, Optional


class ThreatAnalysisState(TypedDict):
    """
    Typed execution state for the 11-node LangGraph Threat Analysis workflow.
    Tracks input telemetry, extracted entities, retrieved candidates, citations,
    validated report output, and step execution timing.
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

    # Entity Extraction
    extracted_indicators: Dict[str, Any]
    retrieval_query: str

    # Retrieval Context
    candidate_techniques: List[Dict[str, Any]]
    d3fend_countermeasures: List[Dict[str, Any]]
    coverage_records: List[Dict[str, Any]]
    highest_retrieval_confidence: float
    insufficient_evidence: bool

    # LLM Interaction
    prompt_messages: List[Dict[str, str]]
    raw_llm_response: Optional[str]
    structured_report: Optional[Dict[str, Any]]
    citations: List[Dict[str, Any]]

    # Execution Trace & Status
    trace_steps: List[Dict[str, Any]]
    status: str  # INITIALIZING, PROCESSING, COMPLETED, PARTIAL, INSUFFICIENT_EVIDENCE, ERROR
    error: Optional[str]
