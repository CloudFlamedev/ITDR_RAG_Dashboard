import time
import uuid
import datetime
import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.ai.state import ThreatAnalysisState
from app.models.threat_report import ThreatAnalysisReport, AnalysisCitation, AnalysisTraceStep
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)


def persist_report_and_trace(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 11: Persists the completed threat analysis report, validated citations,
    and observable LangGraph execution trace steps into Neon PostgreSQL.
    """
    start = time.perf_counter()
    report_id = state.get("report_id") or f"REP-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    report_dict = state.get("structured_report") or {}
    citations_data = state.get("citations") or []
    status = state.get("status", "COMPLETED")

    db: Session = SessionLocal()
    try:
        # Calculate total execution duration
        total_duration = sum(s.get("duration_ms", 0.0) for s in state.get("trace_steps", []))

        # Check if report exists
        existing_report = db.query(ThreatAnalysisReport).filter_by(report_id=report_id).first()
        if existing_report:
            existing_report.input_advisory = state["advisory_text"]
            existing_report.report_title = report_dict.get("report_title", "ITDR Threat Analysis Report")
            existing_report.executive_summary = report_dict.get("executive_summary", "")
            existing_report.severity = report_dict.get("severity", "High")
            existing_report.severity_rationale = report_dict.get("severity_rationale", "")
            existing_report.structured_report = report_dict
            existing_report.completion_status = status
            existing_report.execution_duration_ms = total_duration
            report_obj = existing_report
        else:
            report_obj = ThreatAnalysisReport(
                report_id=report_id,
                input_advisory=state["advisory_text"],
                report_title=report_dict.get("report_title", "ITDR Threat Analysis Report"),
                executive_summary=report_dict.get("executive_summary", ""),
                severity=report_dict.get("severity", "High"),
                severity_rationale=report_dict.get("severity_rationale", ""),
                structured_report=report_dict,
                model_provider=report_dict.get("model_metadata", {}).get("model_provider", "xAI Grok"),
                model_name=report_dict.get("model_metadata", {}).get("model_name", "grok-4.7"),
                completion_status=status,
                execution_duration_ms=total_duration,
                is_demo=False,
            )
            db.add(report_obj)

        db.flush()

        # Delete old citations and trace steps if updating
        db.query(AnalysisCitation).filter_by(report_id=report_obj.id).delete()
        db.query(AnalysisTraceStep).filter_by(report_id=report_obj.id).delete()

        # Insert Citations
        for c in citations_data:
            cit_obj = AnalysisCitation(
                report_id=report_obj.id,
                cited_source_id=c.get("source_id", "unknown-source"),
                external_id=c.get("external_id", "T0000"),
                source_url=c.get("source_url"),
                excerpt=c.get("excerpt", "")[:1000],
                relevance_score=float(c.get("relevance_score", 1.0)),
                citation_role=c.get("citation_role", "Technique Evidence"),
            )
            db.add(cit_obj)

        # Record this persistence step
        this_step = {
            "step_name": "persist_report_and_trace",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "SUCCESS",
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "metadata": {
                "report_id": report_id,
                "citations_stored": len(citations_data),
            },
            "error": None,
        }
        all_steps = state.get("trace_steps", []) + [this_step]

        # Insert Trace Steps
        for step in all_steps:
            trace_obj = AnalysisTraceStep(
                report_id=report_obj.id,
                step_name=step.get("step_name", "step"),
                status=step.get("status", "SUCCESS"),
                duration_ms=float(step.get("duration_ms", 0.0)),
                trace_metadata=step.get("metadata", {}),
                error_details=step.get("error"),
            )
            db.add(trace_obj)

        db.commit()
        logger.info(f"Report {report_id} and {len(all_steps)} trace steps persisted.")

    except Exception as e:
        db.rollback()
        logger.error(f"Error persisting report {report_id}: {e}", exc_info=True)
    finally:
        db.close()

    return {
        "report_id": report_id,
        "trace_steps": all_steps,
    }
