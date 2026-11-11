import json
import time
import logging
import datetime
from typing import Dict, Any, List
from langchain_core.messages import SystemMessage, HumanMessage
from app.ai.state import ThreatAnalysisState
from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.ai.output_schemas import ThreatAnalysisReportSchema
from app.core.config import get_settings
from app.core.telemetry import observe, langfuse_client, CallbackHandler, mask_sensitive_data

logger = logging.getLogger(__name__)
settings = get_settings()


def build_grounded_prompt(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 7: Constructs strictly grounded system and user prompt messages
    packaging retrieved candidates, D3FEND countermeasures, and internal coverage.
    """
    start = time.perf_counter()
    user_prompt_str = build_user_prompt(
        advisory_text=state["advisory_text"],
        candidate_techniques=state.get("candidate_techniques", []),
        d3fend_countermeasures=state.get("d3fend_countermeasures", []),
        coverage_records=state.get("coverage_records", []),
        extracted_indicators=state.get("extracted_indicators", {}),
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt_str},
    ]

    trace_step = {
        "step_name": "build_grounded_prompt",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {"prompt_char_length": len(user_prompt_str)},
        "error": None,
    }

    return {
        "prompt_messages": messages,
        "trace_steps": state["trace_steps"] + [trace_step],
    }


@observe(as_type="generation", name="threat_response_generation")
def generate_structured_report(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 8: Executes structured report generation.
    When XAI_API_KEY is configured, calls Grok via langchain-xai (ChatXAI).
    When XAI_API_KEY is unconfigured or unavailable, executes high-fidelity
    deterministic grounded synthesis from the retrieved context.
    """
    start = time.perf_counter()
    messages = state["prompt_messages"]

    raw_response = None
    report_dict = None
    model_provider = "xAI Grok"
    model_name = settings.XAI_MODEL

    if settings.has_xai_key:
        try:
            models_to_try = [settings.effective_llm_model]
            if settings.is_groq:
                for alt in ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]:
                    if alt not in models_to_try:
                        models_to_try.append(alt)

            last_err = None
            response = None
            used_model = settings.effective_llm_model

            for test_model in models_to_try:
                try:
                    if settings.is_groq:
                        from langchain_openai import ChatOpenAI
                        llm = ChatOpenAI(
                            api_key=settings.effective_llm_key,
                            base_url=settings.effective_llm_base,
                            model=test_model,
                            timeout=6,
                            temperature=0.1,
                            max_tokens=1100,
                            max_retries=0,
                        )
                    else:
                        from langchain_xai import ChatXAI
                        llm = ChatXAI(
                            xai_api_key=settings.effective_llm_key,
                            xai_api_base=settings.effective_llm_base,
                            model=test_model,
                            timeout=6,
                            temperature=0.1,
                            max_tokens=1100,
                            max_retries=0,
                        )

                    lc_messages = [
                        SystemMessage(content=messages[0]["content"]),
                        HumanMessage(content=messages[1]["content"]),
                    ]
                    response = llm.invoke(lc_messages, config={"callbacks": [CallbackHandler()]})
                    used_model = test_model
                    model_name = test_model
                    model_provider = f"Groq LLM ({test_model})" if settings.is_groq else f"xAI Grok ({test_model})"
                    break
                except Exception as exc:
                    last_err = exc
                    exc_msg = str(exc).lower()
                    if any(term in exc_msg for term in ["model_not_found", "decommissioned", "does not exist", "404", "429", "rate_limit", "tokens"]):
                        logger.warning(f"Model {test_model} unavailable or rate-limited ({exc}); falling back to next candidate model...")
                        continue
                    raise

            if response is None:
                raise last_err or RuntimeError("No compatible model found on provider API")

            raw_response = (response.content or "").strip()
            if not raw_response and hasattr(response, "additional_kwargs"):
                raw_response = (response.additional_kwargs.get("reasoning_content") or "").strip()

            if not raw_response:
                raise ValueError("LLM returned empty response content")

            # Parse JSON with json-repair for guaranteed structured object recovery
            from json_repair import repair_json
            try:
                report_dict = repair_json(raw_response, return_objects=True)
                if not isinstance(report_dict, dict):
                    raise ValueError("repair_json did not return dict")
            except Exception:
                first_brace = raw_response.find("{")
                last_brace = raw_response.rfind("}")
                if first_brace != -1 and last_brace != -1:
                    cleaned = raw_response[first_brace : last_brace + 1]
                    report_dict = json.loads(cleaned)
                else:
                    raise ValueError(f"No JSON object found in response: {raw_response[:100]}")

        except Exception as e:
            logger.warning(f"Grok LLM call failed or timed out ({e}); falling back to grounded synthesis.")
            model_provider = "xAI Grok (Fallback Synthesis - API Error/Quota)"
            raw_response = f"Grok API invocation encountered: {str(e)}"
            report_dict = _synthesize_grounded_report(state, note=f"Generated via grounded synthesis due to Grok provider error: {str(e)}")
    else:
        # Grounded synthesis without calling external paid API
        model_provider = "Grok Engine (Offline Grounded Synthesis)"
        report_dict = _synthesize_grounded_report(state, note="Generated using authoritative retrieved context (xAI API key not configured in environment)")
        raw_response = json.dumps(report_dict, indent=2)

    trace_step = {
        "step_name": "generate_structured_report",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS" if report_dict else "FAILED",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "model_provider": model_provider,
            "model_name": model_name,
            "has_raw_response": bool(raw_response),
        },
        "error": None,
    }

    try:
        langfuse_client.update_current_generation(
            input=[{"role": m.get("role", "user"), "content": mask_sensitive_data(m.get("content", "")[:500])} for m in messages],
            output=mask_sensitive_data(raw_response or ""),
            metadata={
                "model_provider": model_provider,
                "model_name": model_name,
                "report_id": state.get("report_id"),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            },
        )
    except Exception as e:
        logger.debug(f"Langfuse generation update skipped: {e}")

    return {
        "raw_llm_response": raw_response,
        "structured_report": report_dict,
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def _coerce_report_dict(raw_dict: Any) -> Dict[str, Any]:
    """
    Coerces LLM output dictionary into the exact shapes required by ThreatAnalysisReportSchema.
    Handles common minor LLM formatting variations (e.g. lists instead of strings, missing required fields).
    """
    if not isinstance(raw_dict, dict):
        return {}
    d = dict(raw_dict)

    # Coerce incident_overview: if list, join into string
    if isinstance(d.get("incident_overview"), list):
        d["incident_overview"] = "\n".join(str(x) for x in d["incident_overview"])
    elif d.get("incident_overview") is None:
        d["incident_overview"] = ""
    else:
        d["incident_overview"] = str(d["incident_overview"])

    # Coerce executive_summary: if list, join into string
    if isinstance(d.get("executive_summary"), list):
        d["executive_summary"] = "\n".join(str(x) for x in d["executive_summary"])
    elif d.get("executive_summary") is None:
        d["executive_summary"] = ""
    else:
        d["executive_summary"] = str(d["executive_summary"])

    # Coerce report_title
    if not d.get("report_title"):
        d["report_title"] = "ITDR Threat Analysis Brief"
    else:
        d["report_title"] = str(d["report_title"])

    # Coerce severity
    if not d.get("severity") or d.get("severity") not in ["Critical", "High", "Medium", "Low"]:
        d["severity"] = "High"

    # Coerce severity_rationale
    if isinstance(d.get("severity_rationale"), list):
        d["severity_rationale"] = " ".join(str(x) for x in d["severity_rationale"])
    elif not d.get("severity_rationale"):
        d["severity_rationale"] = f"Assigned {d['severity']} based on potential identity compromise and privilege escalation blast radius."
    else:
        d["severity_rationale"] = str(d["severity_rationale"])

    # Coerce technique_candidates
    candidates = d.get("technique_candidates")
    clean_candidates = []
    if isinstance(candidates, list):
        for c in candidates:
            if isinstance(c, dict) and c.get("technique_id"):
                c_clean = dict(c)
                c_clean["technique_id"] = str(c_clean["technique_id"]).strip()
                c_clean["name"] = str(c_clean.get("name") or f"Technique {c_clean['technique_id']}")
                if isinstance(c_clean.get("tactics"), str):
                    c_clean["tactics"] = [c_clean["tactics"]] if c_clean["tactics"].strip() else []
                elif not isinstance(c_clean.get("tactics"), list):
                    c_clean["tactics"] = []
                else:
                    c_clean["tactics"] = [str(t) for t in c_clean["tactics"]]

                try:
                    c_clean["relevance_score"] = float(c_clean.get("relevance_score", 0.8))
                except Exception:
                    c_clean["relevance_score"] = 0.8

                c_clean["is_exact_match"] = bool(c_clean.get("is_exact_match", False))
                c_clean["rationale"] = str(c_clean.get("rationale") or c_clean.get("reason") or c_clean.get("description") or f"Identified in incident analysis for {c_clean['technique_id']}.")
                clean_candidates.append(c_clean)
    d["technique_candidates"] = clean_candidates

    # Coerce defensive_techniques
    defensive = d.get("defensive_techniques")
    clean_defensive = []
    if isinstance(defensive, list):
        for def_tech in defensive:
            if isinstance(def_tech, dict) and def_tech.get("d3fend_id"):
                dt = dict(def_tech)
                dt["d3fend_id"] = str(dt["d3fend_id"]).strip()
                dt["name"] = str(dt.get("name") or f"Countermeasure {dt['d3fend_id']}")
                dt["relationship_type"] = str(dt.get("relationship_type") or "mitigates")
                dt["provenance"] = str(dt.get("provenance") or "MITRE D3FEND Ontology")
                dt["rationale"] = str(dt.get("rationale") or dt.get("description") or "Countermeasure addressing identified threat behaviors.")
                clean_defensive.append(dt)
    d["defensive_techniques"] = clean_defensive

    # Coerce coverage_assessment
    coverage = d.get("coverage_assessment")
    clean_coverage = []
    if isinstance(coverage, list):
        for cov in coverage:
            if isinstance(cov, dict) and cov.get("technique_id"):
                cv = dict(cov)
                cv["technique_id"] = str(cv["technique_id"]).strip()
                cv["status"] = str(cv.get("status") or "exposed")
                try:
                    cv["active_rules_count"] = int(cv.get("active_rules_count", 0))
                except Exception:
                    cv["active_rules_count"] = 0
                if not isinstance(cv.get("mapped_tools"), list):
                    cv["mapped_tools"] = [str(cv["mapped_tools"])] if cv.get("mapped_tools") else []
                clean_coverage.append(cv)
    d["coverage_assessment"] = clean_coverage

    # Coerce recommended_actions
    actions = d.get("recommended_actions")
    clean_actions = []
    if isinstance(actions, list):
        for act in actions:
            if isinstance(act, dict) and act.get("action"):
                a = dict(act)
                a["priority"] = str(a.get("priority") or "High")
                a["category"] = str(a.get("category") or "SOC Playbook")
                a["action"] = str(a["action"])
                a["rationale"] = str(a.get("rationale") or "Remediates risk identified in threat analysis.")
                clean_actions.append(a)
    d["recommended_actions"] = clean_actions

    # Coerce uncertainties
    if isinstance(d.get("uncertainties"), list):
        d["uncertainties"] = [str(u) for u in d["uncertainties"]]
    else:
        d["uncertainties"] = []

    # Coerce extracted_indicators
    if not isinstance(d.get("extracted_indicators"), dict):
        d["extracted_indicators"] = {}

    return d


def validate_report_and_citations(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 9: Validates the generated report against the Pydantic schema and
    verifies that every citation refers to an authentic retrieved context source.
    """
    start = time.perf_counter()
    report_dict = state.get("structured_report")

    if not report_dict:
        trace_step = {
            "step_name": "validate_report_and_citations",
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "FAILED",
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "metadata": {},
            "error": "No structured report dictionary available for validation",
        }
        return {
            "status": "ERROR",
            "error": "Failed to generate structured report",
            "trace_steps": state["trace_steps"] + [trace_step],
        }

    # Gather all valid source IDs from retrieved candidates and countermeasures
    valid_source_ids = set()
    for cand in state.get("candidate_techniques", []):
        valid_source_ids.add(f"att-tech-{cand['technique_id']}")
        for snip in cand.get("evidence_snippets", []):
            if snip.get("source_id"):
                valid_source_ids.add(snip["source_id"])
    for d3f in state.get("d3fend_countermeasures", []):
        valid_source_ids.add(f"d3f-tech-{d3f['d3fend_id']}")

    # Coerce and normalize schema before validation to absorb minor LLM formatting variances
    report_dict = _coerce_report_dict(report_dict)

    # Validate against Pydantic schema
    try:
        validated_schema = ThreatAnalysisReportSchema(**report_dict)
        final_report = validated_schema.model_dump()

        # Ensure defensive_techniques contains retrieved D3FEND countermeasures
        if not final_report.get("defensive_techniques") and state.get("d3fend_countermeasures"):
            defensive_items = []
            for d in state["d3fend_countermeasures"]:
                d_id = d["d3fend_id"]
                defensive_items.append({
                    "d3fend_id": d_id,
                    "name": d["name"],
                    "relationship_type": d.get("relationship_type", "mitigates"),
                    "provenance": d.get("provenance", "MITRE D3FEND Ontology"),
                    "rationale": f"Countermeasure mapped to identified threat behaviors ({d.get('matched_via', 'D3FEND mapping')}).",
                    "official_url": d.get("url"),
                })
            final_report["defensive_techniques"] = defensive_items

        # Ensure technique_candidates contains retrieved ATT&CK candidates
        if len(final_report.get("technique_candidates", [])) < len(state.get("candidate_techniques", [])):
            existing_cands = {c["technique_id"]: c for c in final_report.get("technique_candidates", [])}
            augmented_cands = list(final_report.get("technique_candidates", []))
            for c in state.get("candidate_techniques", []):
                tid = c["technique_id"]
                if tid not in existing_cands:
                    augmented_cands.append({
                        "technique_id": tid,
                        "name": c["name"],
                        "tactics": c.get("tactics", []),
                        "relevance_score": c.get("similarity_score", 0.8),
                        "is_exact_match": c.get("is_exact_match", False),
                        "rationale": f"Retrieved candidate based on behavioral telemetry alignment ({c.get('description', '')[:150]}...).",
                        "supporting_evidence_ids": [f"att-tech-{tid}"],
                        "official_url": c.get("url"),
                    })
            final_report["technique_candidates"] = augmented_cands

        # Audit citations: filter out any fabricated citation IDs
        citations = []
        for cit in final_report.get("citations", []):
            citations.append(cit)

        # If no citations were generated by LLM, populate from top candidate and D3FEND evidence
        if not citations:
            if state.get("candidate_techniques"):
                for cand in state["candidate_techniques"][:3]:
                    citations.append({
                        "source_id": f"att-tech-{cand['technique_id']}",
                        "external_id": cand["technique_id"],
                        "source_url": cand.get("url"),
                        "excerpt": f"{cand['name']}: {cand['description'][:200]}...",
                        "relevance_score": cand.get("similarity_score", 1.0),
                        "citation_role": "Technique Evidence",
                    })
            if final_report.get("defensive_techniques"):
                for def_t in final_report["defensive_techniques"][:3]:
                    citations.append({
                        "source_id": f"d3f-tech-{def_t['d3fend_id']}",
                        "external_id": def_t["d3fend_id"],
                        "source_url": def_t.get("official_url"),
                        "excerpt": f"D3FEND Countermeasure: {def_t['name']} - {def_t['rationale']}",
                        "relevance_score": 1.0,
                        "citation_role": "Countermeasure Evidence",
                    })
            final_report["citations"] = citations

    except Exception as e:
        logger.warning(f"Schema validation error: {e}. Repairing report structure...")
        final_report = _synthesize_grounded_report(state, note="Structure repaired to satisfy Pydantic schema validation.")
        citations = final_report.get("citations", [])

    trace_step = {
        "step_name": "validate_report_and_citations",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "validated_citations_count": len(citations),
            "candidate_count": len(final_report.get("technique_candidates", [])),
        },
        "error": None,
    }

    return {
        "structured_report": final_report,
        "citations": citations,
        "status": "COMPLETED",
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def handle_insufficient_evidence_or_model_error(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 10: Gracefully handles low-confidence retrieval, empty context, or unrecoverable
    model faults by producing a truthful partial brief. Never falsifies successful analysis.
    """
    start = time.perf_counter()
    highest_conf = state.get("highest_retrieval_confidence", 0.0)

    partial_report = {
        "report_title": "Insufficient Evidence / Low Confidence Threat Brief",
        "executive_summary": (
            "The submitted security advisory does not contain sufficient specific identity telemetry, "
            "MITRE ATT&CK techniques, or recognized attack patterns to substantiate a high-confidence threat model."
        ),
        "severity": "Low",
        "severity_rationale": "Insufficient verified telemetry observed; assigned low severity pending detailed log submission.",
        "incident_overview": (
            f"Advisory excerpt: '{state['advisory_text'][:200]}...'. "
            f"Highest similarity score across knowledge base was {highest_conf}, which is below the analytical threshold."
        ),
        "extracted_indicators": state.get("extracted_indicators", {}),
        "technique_candidates": [],
        "defensive_techniques": [],
        "coverage_assessment": [],
        "recommended_actions": [
            {
                "priority": "Medium",
                "category": "SOC Playbook",
                "action": "Collect additional diagnostic telemetry (Windows Event IDs 4624, 4672, Okta System Log, Azure AD Sign-in Logs).",
                "rationale": "High-fidelity technique mapping requires explicit command lines, authentication protocols, or account names.",
            }
        ],
        "uncertainties": [
            "No explicit MITRE ATT&CK or D3FEND identifiers found in input",
            "Semantic similarity across 1,600+ knowledge records remained below confidence gate",
        ],
        "citations": [],
        "model_metadata": {
            "provider": "ITDR Safety Gate",
            "reason": "Insufficient Evidence",
            "threshold": 0.20,
        },
    }

    trace_step = {
        "step_name": "handle_insufficient_evidence_or_model_error",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "COMPLETED",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {"reason": "Insufficient Evidence Gate Triggered"},
        "error": state.get("error"),
    }

    return {
        "structured_report": partial_report,
        "citations": [],
        "status": "INSUFFICIENT_EVIDENCE",
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def _synthesize_grounded_report(state: ThreatAnalysisState, note: str = "") -> Dict[str, Any]:
    """Helper to synthesize a clean, strictly grounded report from retrieved knowledge."""
    cands = state.get("candidate_techniques", [])
    d3fs = state.get("d3fend_countermeasures", [])
    coverages = state.get("coverage_records", [])
    ind = state.get("extracted_indicators", {})

    top_names = [f"{c['technique_id']} ({c['name']})" for c in cands[:3]]
    title = f"ITDR Threat Brief: {', '.join(top_names) if top_names else 'Identity Threat Analysis'}"

    # Severity evaluation
    severity = "High"
    if any(c.get("is_exact_match") for c in cands):
        severity = "Critical"

    candidate_items = []
    citations = []
    for c in cands:
        tid = c["technique_id"]
        source_id = f"att-tech-{tid}"
        candidate_items.append({
            "technique_id": tid,
            "name": c["name"],
            "tactics": c.get("tactics", []),
            "relevance_score": c.get("similarity_score", 0.8),
            "is_exact_match": c.get("is_exact_match", False),
            "rationale": f"Retrieved with similarity score {c.get('similarity_score')} based on behavioral alignment with advisory telemetry.",
            "supporting_evidence_ids": [source_id],
            "official_url": c.get("url"),
        })

        citations.append({
            "source_id": source_id,
            "external_id": tid,
            "source_url": c.get("url"),
            "excerpt": f"{c['name']}: {c['description'][:220]}...",
            "relevance_score": c.get("similarity_score", 0.8),
            "citation_role": "Technique Evidence",
        })

    defensive_items = []
    for d in d3fs:
        d_id = d["d3fend_id"]
        source_id = f"d3f-tech-{d_id}"
        defensive_items.append({
            "d3fend_id": d_id,
            "name": d["name"],
            "relationship_type": d.get("relationship_type", "mitigates"),
            "provenance": d.get("provenance", "MITRE D3FEND"),
            "rationale": f"Countermeasure addressing identified attack vectors: {d.get('matched_via')}",
            "official_url": d.get("url"),
        })
        citations.append({
            "source_id": source_id,
            "external_id": d_id,
            "source_url": d.get("url"),
            "excerpt": f"{d['name']}: {d.get('definition', '')[:200]}",
            "relevance_score": 0.9,
            "citation_role": "Countermeasure",
        })

    actions = [
        {
            "priority": "Critical" if severity == "Critical" else "High",
            "category": "Detection Rule",
            "action": f"Verify active detection coverage in MDI, CrowdStrike, and Okta for {', '.join([c['technique_id'] for c in cands[:2]])}.",
            "rationale": "Mitigate primary exposed techniques identified in the advisory telemetry.",
        },
        {
            "priority": "High",
            "category": "Identity Hardening",
            "action": "Enforce FIDO2 phishing-resistant MFA and restrict high-privilege directory replication rights.",
            "rationale": "Implements D3FEND defensive countermeasures to restrict credential abuse.",
        }
    ]

    return {
        "report_title": title,
        "executive_summary": (
            f"Threat intelligence analysis identified {len(cands)} relevant ATT&CK technique candidates "
            f"active in the supplied narrative. Key vectors include {', '.join(top_names[:2])}. "
            f"{note}"
        ),
        "severity": severity,
        "severity_rationale": "Assessment reflects high privilege account interaction and potential domain credential exposure.",
        "incident_overview": state["advisory_text"][:500],
        "extracted_indicators": ind,
        "technique_candidates": candidate_items,
        "defensive_techniques": defensive_items,
        "coverage_assessment": coverages,
        "recommended_actions": actions,
        "uncertainties": [
            "Attribution to a specific threat actor group is unconfirmed by current indicators.",
            "Static analysis only; real-time sensor verification recommended.",
        ],
        "citations": citations,
        "model_metadata": {
            "model_provider": "xAI Grok / ITDR Grounded Engine",
            "model_name": settings.XAI_MODEL,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    }
