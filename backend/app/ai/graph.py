import logging
from langgraph.graph import StateGraph, END
from app.ai.state import ThreatAnalysisState
from app.core.config import get_settings
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
from app.ai.nodes.guardrail_nodes import (
    screen_input_for_injection,
    screen_retrieved_context,
    validate_output_safety,
    handle_security_review,
)

logger = logging.getLogger(__name__)
settings = get_settings()


def route_after_input_validation(state: ThreatAnalysisState) -> str:
    """
    Route 1: Preserves existing error gate for empty/invalid inputs.
    Routes valid input to the screen_input_for_injection guardrail node.
    """
    if state.get("status") == "ERROR":
        return "handle_insufficient_evidence_or_model_error"
    return "screen_input_for_injection"


def route_after_input_screening(state: ThreatAnalysisState) -> str:
    """
    Route 2: Guardrail Edge evaluating direct prompt injection and jailbreaks.
    In enforce mode, high-risk adversarial input routes directly to handle_security_review.
    In monitor mode or clean input, proceeds to entity extraction.
    """
    if settings.guardrails_enforce and state.get("input_security_status") in ["BLOCKED", "SUSPICIOUS"]:
        logger.warning(
            f"Advisory {state.get('report_id')} flagged with {state.get('input_security_status')} "
            "by input injection guardrail. Diverting to security review."
        )
        return "handle_security_review"
    return "extract_entities_and_indicators"


def route_after_retrieval(state: ThreatAnalysisState) -> str:
    """
    Route 3: Preserves existing retrieval confidence and evidence sufficiency gate.
    If evidence is insufficient, skips LLM generation and routes to safety brief.
    If evidence is sufficient, routes to screen_retrieved_context guardrail.
    """
    if state.get("insufficient_evidence", False):
        logger.info("Insufficient evidence gate triggered; routing to safety brief.")
        return "handle_insufficient_evidence_or_model_error"
    return "screen_retrieved_context"


def route_after_context_screening(state: ThreatAnalysisState) -> str:
    """
    Route 4: Guardrail Edge evaluating retrieved context for indirect prompt injection.
    In enforce mode, if all evidence was quarantined and insufficient trusted context remains,
    routes to handle_security_review. Otherwise, proceeds to prompt building with trusted context.
    """
    if settings.guardrails_enforce and state.get("retrieved_context_security_status") == "BLOCKED":
        logger.warning(
            f"Advisory {state.get('report_id')} blocked by retrieved context guardrail. "
            "Diverting to security review."
        )
        return "handle_security_review"
    return "build_grounded_prompt"


def route_after_output_safety(state: ThreatAnalysisState) -> str:
    """
    Route 5: Guardrail Edge validating generated report safety, prompt leakage, and false claims.
    In enforce mode, reports with critical safety violations (UNSAFE) or unsupported claims (UNGROUNDED)
    divert to handle_security_review.
    Non-malicious fallback or schema-repaired reports proceed to persistence with PARTIAL status.
    """
    if settings.guardrails_enforce:
        out_status = state.get("output_security_status")
        if out_status in ["UNSAFE", "UNGROUNDED", "FLAGGED"]:
            logger.warning(
                f"Advisory {state.get('report_id')} generated non-verified or unsafe output ({out_status}). "
                "Diverting to security review."
            )
            return "handle_security_review"
    return "persist_report_and_trace"


def create_threat_analysis_graph():
    """
    Compiles the 15-node stateful LangGraph workflow for explainable ITDR threat modeling
    with multi-layer AI security guardrails (direct injection, indirect injection, output safety).
    """
    workflow = StateGraph(ThreatAnalysisState)

    # 1. Register All 15 Nodes
    workflow.add_node("validate_input", validate_input)
    workflow.add_node("screen_input_for_injection", screen_input_for_injection)
    workflow.add_node("extract_entities_and_indicators", extract_entities_and_indicators)
    workflow.add_node("build_retrieval_query", build_retrieval_query)
    workflow.add_node("retrieve_attack_context", retrieve_attack_context)
    workflow.add_node("retrieve_d3fend_context", retrieve_d3fend_context)
    workflow.add_node("rank_and_deduplicate_candidates", rank_and_deduplicate_candidates)
    workflow.add_node("screen_retrieved_context", screen_retrieved_context)
    workflow.add_node("build_grounded_prompt", build_grounded_prompt)
    workflow.add_node("generate_structured_report", generate_structured_report)
    workflow.add_node("validate_report_and_citations", validate_report_and_citations)
    workflow.add_node("validate_output_safety", validate_output_safety)
    workflow.add_node("handle_security_review", handle_security_review)
    workflow.add_node("handle_insufficient_evidence_or_model_error", handle_insufficient_evidence_or_model_error)
    workflow.add_node("persist_report_and_trace", persist_report_and_trace)

    # 2. Build Directed Edges
    workflow.set_entry_point("validate_input")

    # Edge 1: After input validation (preserves existing error gate)
    workflow.add_conditional_edges(
        "validate_input",
        route_after_input_validation,
        {
            "screen_input_for_injection": "screen_input_for_injection",
            "handle_insufficient_evidence_or_model_error": "handle_insufficient_evidence_or_model_error",
        }
    )

    # Edge 2: After input screening (routes suspicious input to security review in enforce mode)
    workflow.add_conditional_edges(
        "screen_input_for_injection",
        route_after_input_screening,
        {
            "extract_entities_and_indicators": "extract_entities_and_indicators",
            "handle_security_review": "handle_security_review",
        }
    )

    workflow.add_edge("extract_entities_and_indicators", "build_retrieval_query")
    workflow.add_edge("build_retrieval_query", "retrieve_attack_context")
    workflow.add_edge("retrieve_attack_context", "retrieve_d3fend_context")
    workflow.add_edge("retrieve_d3fend_context", "rank_and_deduplicate_candidates")

    # Edge 3: After retrieval & ranking (preserves existing insufficient evidence gate)
    workflow.add_conditional_edges(
        "rank_and_deduplicate_candidates",
        route_after_retrieval,
        {
            "screen_retrieved_context": "screen_retrieved_context",
            "handle_insufficient_evidence_or_model_error": "handle_insufficient_evidence_or_model_error",
        }
    )

    # Edge 4: After context screening (routes poisoned context to security review if untrusted)
    workflow.add_conditional_edges(
        "screen_retrieved_context",
        route_after_context_screening,
        {
            "build_grounded_prompt": "build_grounded_prompt",
            "handle_security_review": "handle_security_review",
        }
    )

    workflow.add_edge("build_grounded_prompt", "generate_structured_report")
    workflow.add_edge("generate_structured_report", "validate_report_and_citations")
    workflow.add_edge("validate_report_and_citations", "validate_output_safety")

    # Edge 5: After output safety validation (routes unsafe output to security review in enforce mode)
    workflow.add_conditional_edges(
        "validate_output_safety",
        route_after_output_safety,
        {
            "persist_report_and_trace": "persist_report_and_trace",
            "handle_security_review": "handle_security_review",
        }
    )

    workflow.add_edge("handle_security_review", "persist_report_and_trace")
    workflow.add_edge("handle_insufficient_evidence_or_model_error", "persist_report_and_trace")
    workflow.add_edge("persist_report_and_trace", END)

    return workflow.compile()


threat_analysis_app = create_threat_analysis_graph()
