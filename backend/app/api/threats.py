import uuid
import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.ai.graph import threat_analysis_app
from app.models.threat_report import ThreatAnalysisReport, AnalysisCitation, AnalysisTraceStep

router = APIRouter(prefix="/api/threats", tags=["Threat Modeling & GenAI Analysis"])

# Curated sample threat intelligence inputs for Screen 6 (Step 1)
SAMPLES = [
    {
        "id": "sample-01",
        "title": "Adversaries abused T1078.004 Cloud Token to Bypass MFA and Dump LSASS",
        "source": "CISA Advisory AA26-001A",
        "text": (
            "A security analyst observed suspicious PowerShell execution originating from an Azure VM jump-box. "
            "Adversaries obtained valid cloud credentials (T1078.004) and abused session tokens to bypass multi-factor authentication. "
            "Following initial access, the actor performed memory injection on LSASS process (T1003.001) on DC-PRIMARY-01 "
            "to extract plaintext Kerberos credentials and attempt Active Directory DCSync directory replication (T1003.006)."
        ),
        "related_ttps": ["T1078.004", "T1003.001", "T1003.006"],
    },
    {
        "id": "sample-02",
        "title": "Emergency Advisory: APT29 Cloud Token & Privilege Escalation Campaign",
        "source": "Microsoft Threat Intelligence",
        "text": (
            "Threat actor APT29 targeted hybrid enterprise environments by abusing OAuth multi-tenant application permissions. "
            "The adversary manipulated app credentials (T1098.005) to grant privileged Exchange.ManageAsApp roles. "
            "Subsequent lateral movement was observed via Pass-the-PRT (T1550) against joined corporate workstations."
        ),
        "related_ttps": ["T1098.005", "T1550", "T1078"],
    },
    {
        "id": "sample-03",
        "title": "Scattered Spider Okta Helpdesk Vishing & MFA Reset Campaign",
        "source": "Okta Security Incident Brief",
        "text": (
            "Social engineering actors conducted voice phishing (vishing) campaigns against the corporate IT help desk. "
            "The callers impersonated high-privilege executives, prompting support agents to reset multi-factor authentication (T1556) "
            "and register adversary-controlled FIDO authenticators. Once inside the identity provider tenant, the actor forged user session cookies (T1539)."
        ),
        "related_ttps": ["T1556", "T1539", "T1078"],
    },
    {
        "id": "sample-04",
        "title": "AD CS ESC1 Vulnerable Certificate Template Abuse for Domain Admin Persistence",
        "source": "SpecterOps BloodHound Telemetry",
        "text": (
            "During an internal identity posture review, an adversary utilized standard user credentials to enroll in a misconfigured "
            "Active Directory Certificate Services (AD CS) template ESC1. The template permitted ENROLLEE_SUPPLIES_SUBJECT, "
            "allowing the attacker to request an authentication certificate specifying the SAN of the Domain Administrator account, "
            "achieving full domain takeover without triggering password change alarms."
        ),
        "related_ttps": ["T1649", "T1078.002", "T1098"],
    }
]


class ThreatAnalysisRequest(BaseModel):
    advisory_text: str = Field(..., min_length=10, description="Submitted security advisory, narrative, or log excerpt")
    sample_id: Optional[str] = Field(default=None, description="Optional ID of loaded sample")
    client_restriction: str = Field(default="ALL", description="ALL, Client Restricted, Unrestricted")
    itdr_scope: str = Field(default="ITDR Scope Only", description="ALL, ITDR Scope Only, Non-ITDR")
    view_mode: str = Field(default="ClientReq", description="ClientReq, MVP1, MVP2, MVP3")
    include_d3fend: bool = Field(default=True, description="Whether to retrieve and map MITRE D3FEND countermeasures")
    max_technique_candidates: int = Field(default=8, ge=1, le=25, description="Max candidate techniques to evaluate")


@router.get("/samples")
def get_sample_threat_inputs():
    """Returns curated threat advisory inputs for the Threat Modeling Workspace."""
    return SAMPLES


@router.post("/analyze")
def analyze_threat(
    req: ThreatAnalysisRequest,
    db: Session = Depends(get_db),
):
    """
    Executes the 11-node stateful LangGraph threat analysis workflow.
    Retrieves candidate ATT&CK techniques, procedures, and D3FEND countermeasures;
    evaluates active detection coverage; invokes Grok LLM; validates citations;
    and persists the complete report and observable trace in Neon PostgreSQL.
    """
    report_id = f"REP-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    initial_state = {
        "report_id": report_id,
        "advisory_text": req.advisory_text,
        "sample_id": req.sample_id,
        "client_restriction": req.client_restriction,
        "itdr_scope": req.itdr_scope,
        "view_mode": req.view_mode,
        "include_d3fend": req.include_d3fend,
        "max_technique_candidates": req.max_technique_candidates,
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

    return {
        "report_id": result.get("report_id", report_id),
        "status": result.get("status", "COMPLETED"),
        "report": result.get("structured_report"),
        "citations": result.get("citations", []),
        "trace_steps": result.get("trace_steps", []),
        "execution_duration_ms": sum(s.get("duration_ms", 0.0) for s in result.get("trace_steps", [])),
    }


@router.get("/reports")
def list_reports(
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Lists completed threat intelligence reports with pagination and filtering."""
    query = db.query(ThreatAnalysisReport)
    if status and status != "ALL":
        query = query.filter(ThreatAnalysisReport.completion_status == status)
    if search:
        query = query.filter(
            (ThreatAnalysisReport.report_title.ilike(f"%{search}%")) |
            (ThreatAnalysisReport.report_id.ilike(f"%{search}%"))
        )

    total = query.count()
    records = query.order_by(ThreatAnalysisReport.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": [
            {
                "id": r.id,
                "report_id": r.report_id,
                "title": r.report_title,
                "summary": r.executive_summary,
                "severity": r.severity,
                "status": r.completion_status,
                "model_provider": r.model_provider,
                "model_name": r.model_name,
                "duration_ms": r.execution_duration_ms,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]
    }


@router.get("/reports/{report_id}")
def get_report_detail(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves full report brief with evidence citations and execution trace steps."""
    rep = db.query(ThreatAnalysisReport).filter(
        (ThreatAnalysisReport.report_id == report_id) |
        (ThreatAnalysisReport.id == int(report_id) if report_id.isdigit() else False)
    ).first()

    if not rep:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    return {
        "report_id": rep.report_id,
        "title": rep.report_title,
        "severity": rep.severity,
        "severity_rationale": rep.severity_rationale,
        "executive_summary": rep.executive_summary,
        "input_advisory": rep.input_advisory,
        "status": rep.completion_status,
        "model_provider": rep.model_provider,
        "model_name": rep.model_name,
        "duration_ms": rep.execution_duration_ms,
        "created_at": rep.created_at.isoformat() if rep.created_at else None,
        "structured_report": rep.structured_report,
        "citations": [
            {
                "source_id": c.cited_source_id,
                "external_id": c.external_id,
                "source_url": c.source_url,
                "excerpt": c.excerpt,
                "relevance_score": c.relevance_score,
                "citation_role": c.citation_role,
            }
            for c in rep.citations
        ],
        "trace_steps": [
            {
                "step_name": s.step_name,
                "status": s.status,
                "duration_ms": s.duration_ms,
                "metadata": s.trace_metadata,
                "error": s.error_details,
            }
            for s in rep.trace_steps
        ],
    }
