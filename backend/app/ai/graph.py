import logging
from langgraph.graph import StateGraph, END
from app.ai.state import ThreatAnalysisState
from app.ai.nodes.input_nodes import (
    validate_input,
    extract_entities_and_indicators,
    build_retrieval_query,
)
from app.ai.nodes.retrieval_nodes import (
    retrieve_attack_context,
    retrieve_d3fend_context,
    rank_and_deduplicate_candidates,
)
from app.ai.nodes.generation_nodes import (
    build_grounded_prompt,
    generate_structured_report,
    validate_report_and_citations,
    handle_insufficient_evidence_or_model_error,
)
from app.ai.nodes.persistence_nodes import persist_report_and_trace

logger = logging.getLogger(__name__)


def route_after_input_validation(state: ThreatAnalysisState) -> str:
    """Route to entity extraction or error handling if input invalid."""
    if state.get("status") == "ERROR":
        return "handle_insufficient_evidence_or_model_error"
    return "extract_entities_and_indicators"


def route_after_retrieval(state: ThreatAnalysisState) -> str:
    """
    Conditional routing node evaluating evidence sufficiency.
    If evidence is insufficient, skips LLM generation and routes to safety brief.
    """
    if state.get("insufficient_evidence", False):
        logger.info("Insufficient evidence gate triggered; routing to safety brief.")
        return "handle_insufficient_evidence_or_model_error"
    return "build_grounded_prompt"


def create_threat_analysis_graph():
    """
    Compiles the 11-node stateful LangGraph workflow for explainable ITDR threat modeling.
    """
    workflow = StateGraph(ThreatAnalysisState)

    # 1. Register Nodes
    workflow.add_node("validate_input", validate_input)
    workflow.add_node("extract_entities_and_indicators", extract_entities_and_indicators)
    workflow.add_node("build_retrieval_query", build_retrieval_query)
    workflow.add_node("retrieve_attack_context", retrieve_attack_context)
    workflow.add_node("retrieve_d3fend_context", retrieve_d3fend_context)
    workflow.add_node("rank_and_deduplicate_candidates", rank_and_deduplicate_candidates)
    workflow.add_node("build_grounded_prompt", build_grounded_prompt)
    workflow.add_node("generate_structured_report", generate_structured_report)
    workflow.add_node("validate_report_and_citations", validate_report_and_citations)
    workflow.add_node("handle_insufficient_evidence_or_model_error", handle_insufficient_evidence_or_model_error)
    workflow.add_node("persist_report_and_trace", persist_report_and_trace)

    # 2. Build Directed Edges
    workflow.set_entry_point("validate_input")

    workflow.add_conditional_edges(
        "validate_input",
        route_after_input_validation,
        {
            "extract_entities_and_indicators": "extract_entities_and_indicators",
            "handle_insufficient_evidence_or_model_error": "handle_insufficient_evidence_or_model_error",
        }
    )

    workflow.add_edge("extract_entities_and_indicators", "build_retrieval_query")
    workflow.add_edge("build_retrieval_query", "retrieve_attack_context")
    workflow.add_edge("retrieve_attack_context", "retrieve_d3fend_context")
    workflow.add_edge("retrieve_d3fend_context", "rank_and_deduplicate_candidates")

    workflow.add_conditional_edges(
        "rank_and_deduplicate_candidates",
        route_after_retrieval,
        {
            "build_grounded_prompt": "build_grounded_prompt",
            "handle_insufficient_evidence_or_model_error": "handle_insufficient_evidence_or_model_error",
        }
    )

    workflow.add_edge("build_grounded_prompt", "generate_structured_report")
    workflow.add_edge("generate_structured_report", "validate_report_and_citations")
    workflow.add_edge("validate_report_and_citations", "persist_report_and_trace")
    workflow.add_edge("handle_insufficient_evidence_or_model_error", "persist_report_and_trace")
    workflow.add_edge("persist_report_and_trace", END)

    return workflow.compile()


threat_analysis_app = create_threat_analysis_graph()
