from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CitationItemSchema(BaseModel):
    source_id: str = Field(..., description="Unique chunk/document ID cited")
    external_id: str = Field(..., description="Technique ID or Bulletin ID e.g. T1078")
    source_url: Optional[str] = Field(default=None, description="Official MITRE or CTI URL")
    excerpt: str = Field(..., description="Verbatim or summary excerpt from retrieved context")
    relevance_score: float = Field(default=1.0, description="Relevance score (0.0 to 1.0)")
    citation_role: str = Field(default="Technique Evidence", description="Role e.g. Technique Evidence, Countermeasure")


class TechniqueCandidateSchema(BaseModel):
    technique_id: str = Field(..., description="Official MITRE technique identifier e.g. T1078")
    name: str = Field(..., description="Official technique name")
    tactics: List[str] = Field(default_factory=list, description="Associated MITRE tactics")
    relevance_score: float = Field(default=0.0, description="Confidence or similarity score")
    is_exact_match: bool = Field(default=False, description="Whether technique ID was explicitly named in input")
    rationale: str = Field(..., description="Specific grounding rationale connecting input behaviors to this technique")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="IDs of cited source documents")
    official_url: Optional[str] = Field(default=None, description="Official MITRE ATT&CK reference URL")


class DefensiveTechniqueSchema(BaseModel):
    d3fend_id: str = Field(..., description="MITRE D3FEND identifier e.g. D3-MFA")
    name: str = Field(..., description="Defensive technique name")
    relationship_type: str = Field(default="mitigates", description="counters, mitigates, detects, restricts")
    provenance: str = Field(..., description="Provenance source of the mapping (never guessed)")
    rationale: str = Field(..., description="How this defensive countermeasure addresses the observed threat")
    official_url: Optional[str] = Field(default=None, description="Official MITRE D3FEND URL")


class CoverageAssessmentSchema(BaseModel):
    technique_id: str = Field(..., description="ATT&CK Technique ID evaluated")
    status: str = Field(..., description="covered, partially_covered, exposed, unknown")
    active_rules_count: int = Field(default=0, description="Number of active detection rules protecting this technique")
    mapped_tools: List[str] = Field(default_factory=list, description="Tools providing coverage e.g. CrowdStrike, MDI")
    gap_summary: Optional[str] = Field(default=None, description="Description of detection gap if exposed")


class RecommendedActionSchema(BaseModel):
    priority: str = Field(default="High", description="Critical, High, Medium, Low")
    category: str = Field(..., description="Detection Rule, Identity Hardening, Architecture, SOC Playbook")
    action: str = Field(..., description="Concrete defensive recommendation")
    rationale: str = Field(..., description="Why this action reduces identity blast radius")


class ThreatAnalysisReportSchema(BaseModel):
    report_title: str = Field(..., description="Concise executive title for the threat analysis brief")
    executive_summary: str = Field(..., description="High-level executive summary of observed threat activity")
    severity: str = Field(default="High", description="Critical, High, Medium, Low")
    severity_rationale: str = Field(..., description="Analytical justification for assigned severity level")
    incident_overview: str = Field(..., description="Technical narrative summarizing attack stages and identity impact")
    extracted_indicators: Dict[str, Any] = Field(default_factory=dict, description="Identified entities, TTPs, accounts")
    technique_candidates: List[TechniqueCandidateSchema] = Field(default_factory=list)
    defensive_techniques: List[DefensiveTechniqueSchema] = Field(default_factory=list)
    coverage_assessment: List[CoverageAssessmentSchema] = Field(default_factory=list)
    recommended_actions: List[RecommendedActionSchema] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list, description="Explicit unsupported fields or analytical unknowns")
    citations: List[CitationItemSchema] = Field(default_factory=list, description="Authoritative grounding citations")
    model_metadata: Dict[str, Any] = Field(default_factory=dict, description="Model provider, name, and inference parameters")
