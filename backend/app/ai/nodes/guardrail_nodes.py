import time
import datetime
import logging
from typing import Dict, Any, List
from app.ai.state import ThreatAnalysisState
from app.core.config import get_settings
from app.services.guardrails_service import GuardrailsService

logger = logging.getLogger(__name__)
settings = get_settings()


def _get_guardrail_service() -> GuardrailsService:
    """Helper to instantiate GuardrailsService using current runtime settings."""
    return GuardrailsService(
        mode=settings.ITDR_GUARDRAIL_MODE,
        input_threshold=settings.GUARDRAIL_INPUT_RISK_THRESHOLD,
        context_threshold=settings.GUARDRAIL_CONTEXT_RISK_THRESHOLD,
        output_threshold=settings.GUARDRAIL_OUTPUT_RISK_THRESHOLD,
        classifier_provider=settings.GUARDRAIL_CLASSIFIER_PROVIDER,
        timeout_seconds=settings.GUARDRAIL_CLASSIFIER_TIMEOUT_SECONDS,
    )


# ==============================================================================
# Node: screen_input_for_injection
# ==============================================================================

def screen_input_for_injection(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Guardrail Node 1: Screens incoming advisory text for direct prompt injection,
    jailbreak attempts, and system prompt extraction attacks.
    Context-aware: Distinguishes between direct adversarial commands and legitimate
    threat intelligence describing quoted injection payloads or attack incidents.

    Fail-closed in enforce mode: Exceptions route to security review.
    Fail-open in monitor mode: Exceptions log and proceed.
    """
    start = time.perf_counter()
    if not settings.ITDR_GUARDRAILS_ENABLED:
        trace_step = {
            "step_name": "screen_input_for_injection",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SKIPPED",
            "duration_ms": 0.0,
            "metadata": {"reason": "ITDR_GUARDRAILS_ENABLED is False"},
            "error": None,
        }
        return {
            "input_security_status": "SKIPPED",
            "input_security_risk": 0.0,
            "input_security_findings": [],
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    try:
        guardrail_svc = _get_guardrail_service()
        res = guardrail_svc.screen_input(state.get("advisory_text", ""))

        review_reasons = list(state.get("review_reasons", []))
        if res.get("is_blocked"):
            review_reasons.append("Direct prompt injection or jailbreak detected in advisory text.")

        trace_step = {
            "step_name": "screen_input_for_injection",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SUCCESS",
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "metadata": {
                "guardrail_mode": settings.ITDR_GUARDRAIL_MODE,
                "input_security_status": res["status"],
                "risk_score": res["risk_score"],
                "is_suspicious": res["is_suspicious"],
                "is_blocked": res["is_blocked"],
                "findings_count": len(res["findings"]),
                "findings": res["findings"],
                "has_incident_context": res.get("has_incident_context", False),
                "is_quoted_or_evidentiary": res.get("is_quoted_or_evidentiary", False),
            },
            "error": None,
        }

        return {
            "input_security_status": res["status"],
            "input_security_risk": res["risk_score"],
            "input_security_findings": res["findings"],
            "review_reasons": review_reasons,
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    except Exception as exc:
        logger.warning(f"Error in screen_input_for_injection: {exc}")
        if settings.guardrails_enforce:
            trace_step = {
                "step_name": "screen_input_for_injection",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fallback": False, "fail_closed": True, "error": str(exc), "stage": "input_screening"},
                "error": str(exc),
            }
            review_reasons = list(state.get("review_reasons", []))
            review_reasons.append(f"Input screening failed in enforce mode (fail-closed): {str(exc)}")
            return {
                "input_security_status": "BLOCKED",
                "input_security_risk": 1.0,
                "input_security_findings": [{"category": "screening_exception", "description": f"Fail-closed guardrail trigger: {str(exc)}"}],
                "review_reasons": review_reasons,
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }
        else:
            trace_step = {
                "step_name": "screen_input_for_injection",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fallback": True, "fail_closed": False, "error": str(exc), "stage": "input_screening"},
                "error": str(exc),
            }
            return {
                "input_security_status": "MONITORED",
                "input_security_risk": 0.0,
                "input_security_findings": [{"category": "screening_error", "description": str(exc)}],
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }


# ==============================================================================
# Node: screen_retrieved_context
# ==============================================================================

def screen_retrieved_context(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Guardrail Node 2: Screens retrieved ATT&CK, D3FEND, and CTI feed knowledge documents
    for indirect prompt injection attempts across all text fields (descriptions, evidence snippets,
    procedure usages, threat feeds, and countermeasures).

    Separates original retrieved evidence from trusted evidence to protect LLM synthesis
    while preserving original evidence for security auditing.

    Fail-closed in enforce mode: Exceptions prevent unchecked context from reaching LLM.
    Fail-open in monitor mode: Exceptions log and proceed.
    """
    start = time.perf_counter()
    raw_cands = state.get("candidate_techniques", [])
    raw_d3f = state.get("d3fend_countermeasures", [])

    if not settings.ITDR_GUARDRAILS_ENABLED:
        trace_step = {
            "step_name": "screen_retrieved_context",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SKIPPED",
            "duration_ms": 0.0,
            "metadata": {"reason": "ITDR_GUARDRAILS_ENABLED is False"},
            "error": None,
        }
        return {
            "retrieved_context_security_status": "SKIPPED",
            "retrieved_context_findings": [],
            "suspicious_document_ids": [],
            "quarantined_document_ids": [],
            "raw_retrieved_candidates": raw_cands,
            "raw_retrieved_d3fend": raw_d3f,
            "trusted_candidate_techniques": raw_cands,
            "trusted_d3fend_countermeasures": raw_d3f,
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    try:
        guardrail_svc = _get_guardrail_service()
        res = guardrail_svc.screen_retrieved_context(raw_cands, raw_d3f)

        review_reasons = list(state.get("review_reasons", []))
        if res.get("status") == "BLOCKED":
            review_reasons.append("Indirect prompt injection in retrieved documents: All evidence quarantined.")

        trace_step = {
            "step_name": "screen_retrieved_context",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SUCCESS",
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "metadata": {
                "guardrail_mode": settings.ITDR_GUARDRAIL_MODE,
                "retrieved_context_security_status": res["status"],
                "has_suspicious_content": res["has_suspicious_content"],
                "has_quarantined_content": res["has_quarantined_content"],
                "suspicious_document_ids": res["suspicious_document_ids"],
                "quarantined_document_ids": res["quarantined_document_ids"],
                "raw_candidates_count": len(raw_cands),
                "trusted_candidates_count": len(res["trusted_candidates"]),
                "trusted_d3fend_count": len(res["trusted_d3fend"]),
                "sufficient_trusted_evidence": res["sufficient_trusted_evidence"],
            },
            "error": None,
        }

        # In enforce mode, replace candidate techniques and d3fend with trusted sanitized versions
        trusted_cands = res["trusted_candidates"] if settings.guardrails_enforce else raw_cands
        trusted_d3f = res["trusted_d3fend"] if settings.guardrails_enforce else raw_d3f

        return {
            "retrieved_context_security_status": res["status"],
            "retrieved_context_findings": res.get("findings", []),
            "suspicious_document_ids": res["suspicious_document_ids"],
            "quarantined_document_ids": res["quarantined_document_ids"],
            "raw_retrieved_candidates": raw_cands,
            "raw_retrieved_d3fend": raw_d3f,
            "trusted_candidate_techniques": res["trusted_candidates"],
            "trusted_d3fend_countermeasures": res["trusted_d3fend"],
            "candidate_techniques": trusted_cands,
            "d3fend_countermeasures": trusted_d3f,
            "review_reasons": review_reasons,
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    except Exception as exc:
        logger.warning(f"Error in screen_retrieved_context: {exc}")
        if settings.guardrails_enforce:
            trace_step = {
                "step_name": "screen_retrieved_context",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fail_closed": True, "error": str(exc), "stage": "retrieval_context_screening"},
                "error": str(exc),
            }
            review_reasons = list(state.get("review_reasons", []))
            review_reasons.append(f"Retrieved-context screening failed in enforce mode (fail-closed): {str(exc)}")
            return {
                "retrieved_context_security_status": "BLOCKED",
                "candidate_techniques": [],
                "d3fend_countermeasures": [],
                "trusted_candidate_techniques": [],
                "trusted_d3fend_countermeasures": [],
                "raw_retrieved_candidates": raw_cands,
                "raw_retrieved_d3fend": raw_d3f,
                "retrieved_context_findings": [{"category": "screening_exception", "description": f"Fail-closed context trigger: {str(exc)}"}],
                "review_reasons": review_reasons,
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }
        else:
            trace_step = {
                "step_name": "screen_retrieved_context",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fallback": True, "fail_closed": False, "error": str(exc), "stage": "retrieval_context_screening"},
                "error": str(exc),
            }
            return {
                "retrieved_context_security_status": "MONITORED",
                "retrieved_context_findings": [{"category": "screening_error", "description": str(exc)}],
                "raw_retrieved_candidates": raw_cands,
                "raw_retrieved_d3fend": raw_d3f,
                "trusted_candidate_techniques": raw_cands,
                "trusted_d3fend_countermeasures": raw_d3f,
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }


# ==============================================================================
# Node: validate_output_safety
# ==============================================================================

def validate_output_safety(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Guardrail Node 3: Inspects the generated threat analysis report recursively
    across all fields for system prompt leakage, secret exposure, destructive recommendations,
    and false automated remediation execution claims.

    Connects ATT&CK/D3FEND validation results with output safety:
    Unsupported technique findings and schema-repaired reports are not marked as verified.

    Fail-closed in enforce mode: Exceptions prevent report from being marked as verified.
    Fail-open in monitor mode: Exceptions log and proceed.
    """
    start = time.perf_counter()
    if not settings.ITDR_GUARDRAILS_ENABLED:
        trace_step = {
            "step_name": "validate_output_safety",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SKIPPED",
            "duration_ms": 0.0,
            "metadata": {"reason": "ITDR_GUARDRAILS_ENABLED is False"},
            "error": None,
        }
        return {
            "output_security_status": "SKIPPED",
            "output_security_findings": [],
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    try:
        guardrail_svc = _get_guardrail_service()
        report_dict = state.get("structured_report", {})

        res = guardrail_svc.validate_output_safety(
            report_dict=report_dict,
            unsupported_attack_ids=state.get("unsupported_attack_ids", []),
            unsupported_d3fend_ids=state.get("unsupported_d3fend_ids", []),
            invalid_citations_count=state.get("invalid_citations_count", 0),
            validation_status=state.get("validation_status"),
            is_fallback_generation=state.get("is_fallback_generation", False),
            is_schema_repaired=state.get("is_schema_repaired", False),
        )

        review_reasons = list(state.get("review_reasons", []))
        if res.get("status") == "UNSAFE":
            findings_summary = ", ".join(f.get("category", "") for f in res.get("findings", []))
            review_reasons.append(f"Generated report violated output safety policies: {findings_summary}")
        elif res.get("status") == "UNGROUNDED" and settings.guardrails_enforce:
            review_reasons.append("Generated report contains unsupported technique IDs not backed by retrieved evidence.")

        trace_step = {
            "step_name": "validate_output_safety",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SUCCESS",
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "metadata": {
                "guardrail_mode": settings.ITDR_GUARDRAIL_MODE,
                "output_security_status": res["status"],
                "risk_score": res["risk_score"],
                "is_safe": res["is_safe"],
                "is_verified": res["is_verified"],
                "findings_count": len(res["findings"]),
                "findings": res["findings"],
                "has_unsupported_findings": res.get("has_unsupported_findings", False),
            },
            "error": None,
        }

        # Update report dictionary validation flag
        if isinstance(report_dict, dict):
            report_dict["is_verified"] = res["is_verified"]
            report_dict["output_security_status"] = res["status"]

        return {
            "output_security_status": res["status"],
            "output_security_findings": res["findings"],
            "review_reasons": review_reasons,
            "structured_report": report_dict,
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    except Exception as exc:
        logger.warning(f"Error in validate_output_safety: {exc}")
        if settings.guardrails_enforce:
            trace_step = {
                "step_name": "validate_output_safety",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fail_closed": True, "error": str(exc), "stage": "output_validation"},
                "error": str(exc),
            }
            review_reasons = list(state.get("review_reasons", []))
            review_reasons.append(f"Output safety validation failed in enforce mode (fail-closed): {str(exc)}")
            return {
                "output_security_status": "UNSAFE",
                "output_security_findings": [{"category": "validation_exception", "description": f"Fail-closed output trigger: {str(exc)}"}],
                "review_reasons": review_reasons,
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }
        else:
            trace_step = {
                "step_name": "validate_output_safety",
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "FAILED",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "metadata": {"fallback": True, "fail_closed": False, "error": str(exc), "stage": "output_validation"},
                "error": str(exc),
            }
            return {
                "output_security_status": "MONITORED",
                "output_security_findings": [{"category": "validation_error", "description": str(exc)}],
                "trace_steps": state.get("trace_steps", []) + [trace_step],
            }


# ==============================================================================
# Node: handle_security_review
# ==============================================================================

def handle_security_review(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Guardrail Node 4: Safe handling path for suspicious input, poisoned context,
    or unsafe output. Produces an authentic security review brief without re-executing
    or echoing hostile payloads. Routes directly to persistence.
    """
    start = time.perf_counter()
    guardrail_svc = _get_guardrail_service()

    # Determine triggering stage and reason
    stage = "input_screening"
    reason = "Prompt injection or adversarial instruction detected."

    if state.get("output_security_status") in ["UNSAFE", "UNGROUNDED"]:
        stage = "output_validation"
        reason = "Generated report contained unsafe recommendations, secret leakage, or unsupported technique claims."
    elif state.get("retrieved_context_security_status") in ["BLOCKED", "UNTRUSTED_CONTENT_DETECTED"]:
        stage = "retrieval_context_screening"
        reason = "Retrieved knowledge documents contained indirect prompt injection payloads."
    elif state.get("input_security_status") in ["BLOCKED", "SUSPICIOUS"]:
        stage = "input_screening"
        reason = "User-submitted advisory text contained direct prompt injection or jailbreak patterns."

    review_reasons = state.get("review_reasons") or [reason]

    all_findings = []
    all_findings.extend(state.get("input_security_findings") or [])
    all_findings.extend(state.get("retrieved_context_findings") or [])
    all_findings.extend(state.get("output_security_findings") or [])

    review_brief = guardrail_svc.create_security_review_brief(
        reason="; ".join(review_reasons),
        stage=stage,
        findings=all_findings,
        advisory_text=state.get("advisory_text", ""),
        extracted_indicators=state.get("extracted_indicators", {}),
        quarantined_document_ids=state.get("quarantined_document_ids"),
        suspicious_document_ids=state.get("suspicious_document_ids"),
        report_id=state.get("report_id"),
    )

    review_status = "BLOCKED" if any(state.get(k) == "BLOCKED" for k in ["input_security_status", "retrieved_context_security_status"]) else "NEEDS_REVIEW"

    trace_step = {
        "step_name": "handle_security_review",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "COMPLETED",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "review_stage": stage,
            "review_status": review_status,
            "reasons": review_reasons,
            "input_security_status": state.get("input_security_status"),
            "retrieved_context_security_status": state.get("retrieved_context_security_status"),
            "output_security_status": state.get("output_security_status"),
            "quarantined_document_ids": state.get("quarantined_document_ids", []),
            "suspicious_document_ids": state.get("suspicious_document_ids", []),
        },
        "error": None,
    }

    return {
        "structured_report": review_brief,
        "citations": [],
        "unsupported_attack_ids": [],
        "unsupported_d3fend_ids": [],
        "invalid_citations_count": 0,
        "status": review_status,
        "trace_steps": state.get("trace_steps", []) + [trace_step],
    }
