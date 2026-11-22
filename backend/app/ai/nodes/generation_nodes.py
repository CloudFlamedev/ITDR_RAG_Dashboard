import json
import time
import logging
import datetime
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from sqlalchemy.orm import Session
from langchain_core.messages import SystemMessage, HumanMessage
from app.ai.state import ThreatAnalysisState
from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.ai.output_schemas import ThreatAnalysisReportSchema
from app.core.config import get_settings
from app.core.telemetry import observe, langfuse_client, CallbackHandler, mask_sensitive_data
from app.db.session import SessionLocal
from app.models.attack import AttackTechnique
from app.models.d3fend import D3fendTechnique

logger = logging.getLogger(__name__)
settings = get_settings()

# Ensure backwards-compatibility for langchain-xai with BaseChatOpenAI across langchain versions
try:
    from pydantic.fields import ModelPrivateAttr
    try:
        from langchain_openai.chat_models.base import BaseChatOpenAI
        if hasattr(BaseChatOpenAI, "__private_attributes__") and "_langsmith_gateway_headers" not in BaseChatOpenAI.__private_attributes__:
            BaseChatOpenAI.__private_attributes__["_langsmith_gateway_headers"] = ModelPrivateAttr(default=None)
    except Exception:
        pass

    try:
        from langchain_xai import ChatXAI
        if hasattr(ChatXAI, "__private_attributes__") and "_langsmith_gateway_headers" not in ChatXAI.__private_attributes__:
            ChatXAI.__private_attributes__["_langsmith_gateway_headers"] = ModelPrivateAttr(default=None)
    except Exception:
        pass
except Exception:
    pass

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_xai import ChatXAI
except ImportError:
    ChatXAI = None

_authoritative_attack_ids: Optional[Set[str]] = None
_authoritative_d3fend_ids: Optional[Set[str]] = None
_taxonomy_lock = threading.Lock()


def _get_authoritative_taxonomy_sets() -> Tuple[Set[str], Set[str]]:
    """Retrieves and caches authoritative ATT&CK and D3FEND technique IDs from database records."""
    global _authoritative_attack_ids, _authoritative_d3fend_ids
    if not _authoritative_attack_ids or not _authoritative_d3fend_ids:
        with _taxonomy_lock:
            if not _authoritative_attack_ids or not _authoritative_d3fend_ids:
                db: Session = SessionLocal()
                try:
                    att_ids = {r[0] for r in db.query(AttackTechnique.technique_id).all()}
                    d3f_ids = {r[0] for r in db.query(D3fendTechnique.d3fend_id).all()}
                    if att_ids:
                        _authoritative_attack_ids = att_ids
                    if d3f_ids:
                        _authoritative_d3fend_ids = d3f_ids
                except Exception as e:
                    logger.warning(f"Failed to load authoritative taxonomy from DB: {e}")
                    return _authoritative_attack_ids or set(), _authoritative_d3fend_ids or set()
                finally:
                    db.close()
    return _authoritative_attack_ids or set(), _authoritative_d3fend_ids or set()


def build_grounded_prompt(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 7: Constructs strictly grounded system and user prompt messages
    packaging retrieved candidates, D3FEND countermeasures, and internal coverage.
    Instruments exact context preservation for authoritative RAGAS evaluation.
    """
    start = time.perf_counter()
    candidates = state.get("candidate_techniques", [])
    d3fend = state.get("d3fend_countermeasures", [])
    coverage = state.get("coverage_records", [])

    user_prompt_str = build_user_prompt(
        advisory_text=state["advisory_text"],
        candidate_techniques=candidates,
        d3fend_countermeasures=d3fend,
        coverage_records=coverage,
        extracted_indicators=state.get("extracted_indicators", {}),
    )

    # Instrument exact context items actually formatted and passed to the LLM
    evaluation_contexts: List[str] = []
    for c in candidates[:5]:
        desc = c.get("description", "")
        evaluation_contexts.append(
            f"MITRE ATT&CK Technique {c['technique_id']} - {c['name']} (Tactics: {', '.join(c.get('tactics', []))}): {desc[:250]}"
        )
    for d in d3fend[:5]:
        definition = d.get("definition", "")
        evaluation_contexts.append(
            f"MITRE D3FEND Countermeasure {d['d3fend_id']} - {d['name']} ({d.get('relationship_type', 'mitigates')}): {definition[:250]}"
        )
    for cov in coverage[:8]:
        evaluation_contexts.append(
            f"Active Detection Coverage: Technique {cov.get('technique_id')} (Status: {cov.get('status')}, Tools: {', '.join(cov.get('mapped_tools', []))})"
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
        "metadata": {
            "prompt_char_length": len(user_prompt_str),
            "evaluation_contexts_count": len(evaluation_contexts),
        },
        "error": None,
    }

    return {
        "prompt_messages": messages,
        "evaluation_contexts": evaluation_contexts,
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

    # Explicit provider selection: state > settings.LLM_PROVIDER > auto-detect
    explicit_provider = state.get("llm_provider") or getattr(settings, "LLM_PROVIDER", None)
    if explicit_provider:
        selected_provider = explicit_provider.strip().lower()
    elif settings.is_groq:
        selected_provider = "groq"
    else:
        selected_provider = "xai"

    # Resolve active credentials, base URL, and candidate models for selected provider
    if selected_provider == "groq":
        active_key = (
            getattr(settings, "GROQ_API_KEY_NEW_FOR_TESTING", None)
            or getattr(settings, "GROQ_API_KEY", None)
        )
        if active_key:
            active_key = active_key.strip()
        active_base = getattr(settings, "GROQ_API_BASE", None) or "https://api.groq.com/openai/v1"
        configured_model = state.get("llm_model") or getattr(settings, "GROQ_MODEL", None) or "openai/gpt-oss-120b"
        models_to_try = [configured_model]
        for alt in ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]:
            if alt not in models_to_try:
                models_to_try.append(alt)
    else:
        active_key = getattr(settings, "XAI_API_KEY", None)
        if active_key:
            active_key = active_key.strip()
        active_base = getattr(settings, "XAI_API_BASE", None) or "https://api.x.ai/v1"
        configured_model = state.get("llm_model") or getattr(settings, "XAI_MODEL", None) or "grok-4.7"
        models_to_try = [configured_model]

    has_active_key = bool(active_key and not active_key.startswith("replace-") and active_key.strip())

    provider_request_attempted = False
    provider_response_received = False
    offline_fallback_used = False
    token_usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    used_model = configured_model
    model_name = configured_model
    model_provider = f"Groq LLM ({configured_model})" if selected_provider == "groq" else f"xAI Grok ({configured_model})"

    if has_active_key:
        try:
            last_err = None
            response = None

            for test_model in models_to_try:
                try:
                    if selected_provider == "groq":
                        if ChatOpenAI is None:
                            raise ImportError("langchain_openai is required for Groq provider")
                        llm = ChatOpenAI(
                            api_key=active_key,
                            base_url=active_base,
                            model=test_model,
                            timeout=30,
                            temperature=0.1,
                            max_tokens=2048,
                            max_retries=0,
                        )
                    else:
                        if ChatXAI is None:
                            raise ImportError("langchain_xai is required for xAI provider")
                        llm = ChatXAI(
                            xai_api_key=active_key,
                            xai_api_base=active_base,
                            model=test_model,
                            timeout=30,
                            temperature=0.1,
                            max_tokens=2048,
                            max_retries=0,
                        )

                    lc_messages = [
                        SystemMessage(content=messages[0]["content"]),
                        HumanMessage(content=messages[1]["content"]),
                    ]
                    provider_request_attempted = True
                    response = llm.invoke(lc_messages, config={"callbacks": [CallbackHandler()]})
                    content = (response.content or "").strip()
                    if not content and hasattr(response, "additional_kwargs"):
                        content = (
                            response.additional_kwargs.get("reasoning_content")
                            or response.additional_kwargs.get("reasoning")
                            or ""
                        ).strip()

                    if not content:
                        logger.warning(f"Model {test_model} returned empty content; trying next candidate model...")
                        continue

                    provider_response_received = True
                    raw_response = content
                    used_model = test_model
                    model_name = test_model
                    model_provider = f"Groq LLM ({test_model})" if selected_provider == "groq" else f"xAI Grok ({test_model})"
                    usage_dict = getattr(response, "usage_metadata", None) or getattr(response, "response_metadata", {}).get("token_usage") or {}
                    token_usage = {
                        "input_tokens": int(usage_dict.get("input_tokens") or usage_dict.get("prompt_tokens") or 0),
                        "output_tokens": int(usage_dict.get("output_tokens") or usage_dict.get("completion_tokens") or 0),
                        "total_tokens": int(usage_dict.get("total_tokens") or 0),
                    }
                    if not token_usage["total_tokens"]:
                        token_usage["total_tokens"] = token_usage["input_tokens"] + token_usage["output_tokens"]
                    break
                except Exception as exc:
                    last_err = exc
                    exc_msg = str(exc).lower()
                    if any(term in exc_msg for term in ["model_not_found", "decommissioned", "does not exist", "404", "429", "rate_limit", "tokens"]):
                        if any(term in exc_msg for term in ["429", "rate_limit", "tokens"]):
                            logger.warning(f"Model {test_model} rate-limited ({exc}); waiting 4s before trying next candidate model...")
                            time.sleep(4.0)
                        else:
                            logger.warning(f"Model {test_model} unavailable ({exc}); falling back to next candidate model...")
                        continue
                    raise

            if response is None or not raw_response:
                raise last_err or RuntimeError(f"No compatible model returned content on {selected_provider} API")

            # Parse JSON with json-repair for guaranteed structured object recovery
            from json_repair import repair_json
            try:
                parsed = repair_json(raw_response, return_objects=True)
                if isinstance(parsed, dict):
                    report_dict = parsed
                elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    report_dict = parsed[0]
            except Exception:
                pass

            if not report_dict:
                first_brace = raw_response.find("{")
                if first_brace != -1:
                    try:
                        parsed = repair_json(raw_response[first_brace:], return_objects=True)
                        if isinstance(parsed, dict):
                            report_dict = parsed
                        elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                            report_dict = parsed[0]
                    except Exception:
                        pass

            if not isinstance(report_dict, dict):
                raise ValueError("Could not parse valid JSON dictionary from LLM response")

        except Exception as e:
            logger.warning(f"LLM call to {selected_provider} failed or timed out ({e}); falling back to grounded synthesis.")
            offline_fallback_used = True
            model_provider = f"{'Groq' if selected_provider == 'groq' else 'xAI Grok'} (Fallback Synthesis - API Error/Quota)"
            raw_response = f"{selected_provider.upper()} API invocation encountered: {str(e)}"
            report_dict = _synthesize_grounded_report(state, note=f"Generated via grounded synthesis due to {selected_provider} provider error: {str(e)}")
    else:
        # Grounded synthesis without calling external paid API
        offline_fallback_used = True
        model_provider = "Grok Engine (Offline Grounded Synthesis)"
        report_dict = _synthesize_grounded_report(state, note="Generated using authoritative retrieved context (API key not configured in environment)")
        raw_response = json.dumps(report_dict, indent=2)

    is_fallback = offline_fallback_used
    if isinstance(report_dict, dict):
        report_dict["is_fallback_generation"] = is_fallback
        report_dict["model_provider"] = model_provider
        report_dict["model_name"] = model_name

    trace_step = {
        "step_name": "generate_structured_report",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS" if report_dict else "FAILED",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "model_provider": model_provider,
            "model_name": model_name,
            "selected_provider": selected_provider,
            "is_fallback_generation": is_fallback,
            "provider_request_attempted": provider_request_attempted,
            "provider_response_received": provider_response_received,
            "offline_fallback_used": offline_fallback_used,
            "has_raw_response": bool(raw_response),
            "token_usage": token_usage,
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
                "selected_provider": selected_provider,
                "is_fallback_generation": is_fallback,
                "provider_request_attempted": provider_request_attempted,
                "provider_response_received": provider_response_received,
                "offline_fallback_used": offline_fallback_used,
                "report_id": state.get("report_id"),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "token_usage": token_usage,
            },
        )
    except Exception as e:
        logger.debug(f"Langfuse generation update skipped: {e}")

    return {
        "raw_llm_response": raw_response,
        "structured_report": report_dict,
        "is_fallback_generation": is_fallback,
        "token_usage": token_usage,
        "provider_request_attempted": provider_request_attempted,
        "provider_response_received": provider_response_received,
        "offline_fallback_used": offline_fallback_used,
        "llm_provider": selected_provider,
        "llm_model": model_name,
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

    # Coerce citations
    citations = d.get("citations")
    clean_citations = []
    if isinstance(citations, list):
        for cit in citations:
            if isinstance(cit, dict) and cit.get("source_id"):
                c = dict(cit)
                c["source_id"] = str(c["source_id"])
                c["external_id"] = str(c.get("external_id") or "T0000")
                c["source_url"] = str(c["source_url"]) if c.get("source_url") else None
                c["excerpt"] = str(c.get("excerpt") or f"Cited context for {c['source_id']}")
                try:
                    c["relevance_score"] = float(c.get("relevance_score", 1.0))
                except Exception:
                    c["relevance_score"] = 1.0
                c["citation_role"] = str(c.get("citation_role") or "Technique Evidence")
                clean_citations.append(c)
    d["citations"] = clean_citations

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

        # Build authoritative valid source lookup map from retrieved evidence
        valid_source_map: Dict[str, Dict[str, Any]] = {}
        for cand in state.get("candidate_techniques", []):
            cand_src = f"att-tech-{cand['technique_id']}"
            cand_entry = {
                "source_id": cand_src,
                "external_id": cand["technique_id"],
                "source_url": cand.get("url") or f"https://attack.mitre.org/techniques/{cand['technique_id']}",
                "excerpt": f"{cand['name']}: {(cand.get('description') or '')[:250]}...",
                "relevance_score": float(cand.get("similarity_score", 1.0)),
                "citation_role": "Technique Evidence",
            }
            valid_source_map[cand_src] = cand_entry
            valid_source_map[cand["technique_id"]] = cand_entry

            for snip in cand.get("evidence_snippets", []):
                if isinstance(snip, dict) and snip.get("source_id"):
                    valid_source_map[snip["source_id"]] = {
                        "source_id": snip["source_id"],
                        "external_id": cand["technique_id"],
                        "source_url": snip.get("url") or cand.get("url"),
                        "excerpt": snip.get("excerpt", "")[:500],
                        "relevance_score": float(snip.get("score", 1.0)),
                        "citation_role": "Technique Evidence",
                    }
            for proc in (cand.get("procedure_evidence") or cand.get("procedures") or []):
                if isinstance(proc, dict) and proc.get("source_id"):
                    valid_source_map[proc["source_id"]] = {
                        "source_id": proc["source_id"],
                        "external_id": cand["technique_id"],
                        "source_url": cand.get("url"),
                        "excerpt": (proc.get("usage") or proc.get("description") or proc.get("excerpt") or "")[:500],
                        "relevance_score": 1.0,
                        "citation_role": "Procedure Evidence",
                    }
            for feed in (cand.get("threat_feed_content") or cand.get("cti_feeds") or []):
                if isinstance(feed, dict) and feed.get("source_id"):
                    valid_source_map[feed["source_id"]] = {
                        "source_id": feed["source_id"],
                        "external_id": cand["technique_id"],
                        "source_url": cand.get("url"),
                        "excerpt": (feed.get("content") or feed.get("summary") or "")[:500],
                        "relevance_score": 1.0,
                        "citation_role": "Threat Feed Evidence",
                    }
        for d3f in state.get("d3fend_countermeasures", []):
            did = d3f["d3fend_id"]
            d3f_src = f"d3f-tech-{did}"
            d3f_entry = {
                "source_id": d3f_src,
                "external_id": did,
                "source_url": d3f.get("url") or f"https://d3fend.mitre.org/technique/{did}",
                "excerpt": f"D3FEND Countermeasure: {d3f['name']} - {(d3f.get('definition') or d3f.get('rationale') or '')[:250]}",
                "relevance_score": 1.0,
                "citation_role": "Countermeasure Evidence",
            }
            valid_source_map[d3f_src] = d3f_entry
            valid_source_map[did] = d3f_entry
            valid_source_map[f"d3fend-{did}"] = d3f_entry
            valid_source_map[f"d3f-{did}"] = d3f_entry
            valid_source_map[d3f_src.lower()] = d3f_entry
            valid_source_map[did.lower()] = d3f_entry
            valid_source_map[f"d3fend-{did.lower()}"] = d3f_entry
            valid_source_map[f"d3f-{did.lower()}"] = d3f_entry

        # Audit citations: filter out any fabricated citation IDs and resolve authentic metadata
        citations = []
        invalid_citations_count = 0
        rejected_citations = []
        raw_citations = final_report.get("citations", [])
        for cit in raw_citations:
            s_id = str(cit.get("source_id") or "").strip()
            auth_rec = (
                valid_source_map.get(s_id)
                or valid_source_map.get(s_id.lower())
                or valid_source_map.get(s_id.upper())
                or valid_source_map.get(s_id.replace("d3fend-", "d3f-tech-"))
                or valid_source_map.get(s_id.replace("attack-", "att-tech-"))
                or valid_source_map.get(s_id.replace("att-", "att-tech-"))
            )
            if auth_rec:
                # Resolve source URLs, titles and excerpts using authentic backend records
                citations.append({
                    "source_id": auth_rec["source_id"],
                    "external_id": auth_rec["external_id"],
                    "source_url": auth_rec["source_url"],
                    "excerpt": auth_rec["excerpt"],
                    "relevance_score": float(cit.get("relevance_score", auth_rec["relevance_score"])),
                    "citation_role": cit.get("citation_role", auth_rec["citation_role"]),
                })
            else:
                invalid_citations_count += 1
                rejected_citations.append(s_id or "unknown-source")
                logger.warning(f"Rejected fabricated or unknown citation source_id: '{s_id}'")

        # If no valid citations remained from LLM, populate authentic fallback from top evidence
        if not citations:
            if state.get("candidate_techniques"):
                for cand in state["candidate_techniques"][:3]:
                    cand_src = f"att-tech-{cand['technique_id']}"
                    if cand_src in valid_source_map:
                        citations.append(valid_source_map[cand_src])
            if final_report.get("defensive_techniques"):
                for def_t in final_report["defensive_techniques"][:3]:
                    d3f_src = f"d3f-tech-{def_t['d3fend_id']}"
                    if d3f_src in valid_source_map:
                        citations.append(valid_source_map[d3f_src])

        final_report["citations"] = citations

        # Authoritative Database Taxonomy Validation & Context Support Check
        auth_attack_ids, auth_d3fend_ids = _get_authoritative_taxonomy_sets()
        retrieved_exact_attack_ids = {c["technique_id"] for c in state.get("candidate_techniques", [])}
        retrieved_exact_d3fend_ids = {d["d3fend_id"] for d in state.get("d3fend_countermeasures", [])}

        unsupported_attack_ids = []
        for cand in final_report.get("technique_candidates", []):
            tid = cand.get("technique_id")
            # Authoritative validity check against database records
            is_valid_taxonomy = (tid in auth_attack_ids) if auth_attack_ids else True
            # Sub-technique parent rule: A parent ID does NOT prove sub-technique is valid or supported!
            is_supported = (tid in retrieved_exact_attack_ids)

            cand["is_valid_taxonomy"] = is_valid_taxonomy
            cand["is_supported"] = bool(is_supported and is_valid_taxonomy)

            if not cand["is_supported"]:
                unsupported_attack_ids.append(tid)
                cand["support_warning"] = (
                    f"Unsupported ID warning: Technique {tid} was generated without supporting evidence in retrieved context."
                    if is_valid_taxonomy else
                    f"Unsupported ID warning (Invalid taxonomy): Technique {tid} does not exist in authoritative MITRE ATT&CK taxonomy records."
                )
                logger.warning(f"Unsupported/invalid ATT&CK ID detected in generated report: {tid} (valid_taxonomy={is_valid_taxonomy})")
            else:
                cand["is_supported"] = True

        unsupported_d3fend_ids = []
        for def_t in final_report.get("defensive_techniques", []):
            did = def_t.get("d3fend_id")
            is_valid_taxonomy = (did in auth_d3fend_ids) if auth_d3fend_ids else True
            is_supported = (did in retrieved_exact_d3fend_ids)

            def_t["is_valid_taxonomy"] = is_valid_taxonomy
            def_t["is_supported"] = bool(is_supported and is_valid_taxonomy)

            if not def_t["is_supported"]:
                unsupported_d3fend_ids.append(did)
                def_t["support_warning"] = (
                    f"Unsupported ID warning: D3FEND countermeasure {did} was not present in retrieved context."
                    if is_valid_taxonomy else
                    f"Unsupported ID warning (Invalid taxonomy): D3FEND countermeasure {did} does not exist in authoritative MITRE D3FEND taxonomy records."
                )
                logger.warning(f"Unsupported/invalid D3FEND ID detected in generated report: {did} (valid_taxonomy={is_valid_taxonomy})")
            else:
                def_t["is_supported"] = True

        is_fallback = report_dict.get("is_fallback_generation", False)
        is_schema_repaired = False
        if unsupported_attack_ids or unsupported_d3fend_ids:
            validation_status = "UNSUPPORTED_TAXONOMY_DETECTED"
        elif is_fallback:
            validation_status = "FALLBACK_SYNTHESIZED"
        else:
            validation_status = "VALIDATED"

        final_report["validation_status"] = validation_status
        final_report["is_schema_repaired"] = False
        final_report["unsupported_attack_ids"] = unsupported_attack_ids
        final_report["unsupported_d3fend_ids"] = unsupported_d3fend_ids
        final_report["invalid_citations_count"] = invalid_citations_count
        final_report["model_provider"] = report_dict.get("model_provider")
        final_report["model_name"] = report_dict.get("model_name")
        final_report["is_fallback_generation"] = is_fallback

    except Exception as e:
        logger.warning(f"Schema validation error: {e}. Repairing report structure...")
        final_report = _synthesize_grounded_report(state, note="Structure repaired to satisfy Pydantic schema validation.")
        citations = final_report.get("citations", [])
        unsupported_attack_ids = []
        unsupported_d3fend_ids = []
        invalid_citations_count = 0
        rejected_citations = []
        is_schema_repaired = True
        is_fallback = True
        validation_status = "SCHEMA_REPAIRED"
        final_report["validation_status"] = "SCHEMA_REPAIRED"
        final_report["is_schema_repaired"] = True
        final_report["is_fallback_generation"] = True
        final_report["schema_validation_error"] = str(e)

    trace_step = {
        "step_name": "validate_report_and_citations",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "validation_status": validation_status,
            "is_schema_repaired": is_schema_repaired,
            "is_fallback_generation": is_fallback,
            "validated_citations_count": len(citations),
            "invalid_citations_count": invalid_citations_count,
            "rejected_citations": rejected_citations,
            "unsupported_attack_ids_count": len(unsupported_attack_ids),
            "unsupported_attack_ids": unsupported_attack_ids,
            "unsupported_d3fend_ids_count": len(unsupported_d3fend_ids),
            "unsupported_d3fend_ids": unsupported_d3fend_ids,
            "candidate_count": len(final_report.get("technique_candidates", [])),
        },
        "error": None,
    }

    return {
        "structured_report": final_report,
        "citations": citations,
        "is_fallback_generation": is_fallback,
        "is_schema_repaired": is_schema_repaired,
        "validation_status": validation_status,
        "unsupported_attack_ids": unsupported_attack_ids,
        "unsupported_d3fend_ids": unsupported_d3fend_ids,
        "invalid_citations_count": invalid_citations_count,
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
        "unsupported_attack_ids": [],
        "unsupported_d3fend_ids": [],
        "invalid_citations_count": 0,
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
            "excerpt": f"{c['name']}: {(c.get('description') or '')[:220]}...",
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
        "incident_overview": state.get("advisory_text", "")[:500],
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
