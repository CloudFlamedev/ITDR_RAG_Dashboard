import time
import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.ai.state import ThreatAnalysisState
from app.services.retrieval_service import RetrievalService
from app.models.coverage import DetectionRuleTechnique, DetectionRule
from app.db.session import SessionLocal


def retrieve_attack_context(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 4: Executes hybrid retrieval over ATT&CK techniques, procedure usages,
    and CTI bulletins using both exact-ID match and vector semantic search.
    """
    start = time.perf_counter()
    query = state.get("retrieval_query", state["advisory_text"])
    max_cands = state.get("max_technique_candidates", 8)

    db: Session = SessionLocal()
    try:
        retriever = RetrievalService(db)
        retrieval_res = retriever.retrieve(
            advisory_text=query,
            max_candidates=max_cands,
            include_d3fend=False,  # D3FEND retrieved in next node
        )
    finally:
        db.close()

    trace_step = {
        "step_name": "retrieve_attack_context",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "candidates_found": len(retrieval_res["candidates"]),
            "highest_confidence": retrieval_res["highest_confidence"],
            "explicit_indicators": retrieval_res["explicit_indicators"],
        },
        "error": None,
    }

    return {
        "candidate_techniques": retrieval_res["candidates"],
        "highest_retrieval_confidence": retrieval_res["highest_confidence"],
        "insufficient_evidence": retrieval_res["insufficient_evidence"],
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def retrieve_d3fend_context(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 5: Retrieves MITRE D3FEND defensive countermeasures based on candidate
    ATT&CK techniques and query semantics. Never asserts guessed relationships.
    """
    start = time.perf_counter()
    if not state.get("include_d3fend", True):
        trace_step = {
            "step_name": "retrieve_d3fend_context",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SKIPPED",
            "duration_ms": 0.0,
            "metadata": {"reason": "include_d3fend is False"},
            "error": None,
        }
        return {
            "d3fend_countermeasures": [],
            "trace_steps": state["trace_steps"] + [trace_step],
        }

    db: Session = SessionLocal()
    try:
        retriever = RetrievalService(db)
        cand_ids = [c["technique_id"] for c in state.get("candidate_techniques", [])]
        d3f_res = retriever._retrieve_d3fend_countermeasures(
            query_text=state["advisory_text"],
            candidate_technique_ids=cand_ids,
            explicit_d3fend_ids=state.get("extracted_indicators", {}).get("d3fend_ids", []),
        )
    finally:
        db.close()

    trace_step = {
        "step_name": "retrieve_d3fend_context",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {"countermeasures_found": len(d3f_res)},
        "error": None,
    }

    return {
        "d3fend_countermeasures": d3f_res,
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def rank_and_deduplicate_candidates(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 6: Finalizes candidate ranking, deduplicates findings, and cross-references
    internal active detection rules to evaluate real coverage state (Covered vs Exposed).
    """
    start = time.perf_counter()
    candidates = state.get("candidate_techniques", [])

    coverage_assessments = []
    db: Session = SessionLocal()
    try:
        for cand in candidates:
            tid = cand["technique_id"]
            # Look up active rules protecting this technique
            mappings = (
                db.query(DetectionRuleTechnique)
                .join(DetectionRule)
                .filter(
                    (DetectionRuleTechnique.technique_external_id == tid) |
                    (DetectionRuleTechnique.technique_external_id == tid.split(".")[0])
                )
                .filter(DetectionRule.enabled.is_(True))
                .all()
            )

            tools = sorted(list(set(m.rule.tool for m in mappings)))
            rule_count = len(mappings)

            status = "exposed"
            gap_summary = f"No active detection rules mapped to {tid}"
            if rule_count > 0:
                status = "covered"
                gap_summary = None

            coverage_assessments.append({
                "technique_id": tid,
                "status": status,
                "active_rules_count": rule_count,
                "mapped_tools": tools,
                "gap_summary": gap_summary,
            })
    finally:
        db.close()

    trace_step = {
        "step_name": "rank_and_deduplicate_candidates",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "final_candidate_count": len(candidates),
            "covered_candidates": sum(1 for c in coverage_assessments if c["status"] == "covered"),
            "exposed_candidates": sum(1 for c in coverage_assessments if c["status"] == "exposed"),
        },
        "error": None,
    }

    return {
        "coverage_records": coverage_assessments,
        "trace_steps": state["trace_steps"] + [trace_step],
    }
