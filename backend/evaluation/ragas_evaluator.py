"""
RAGAS Automated Evaluation Engine for the ITDR RAG Pipeline.
Implements:
- Retrieval Evaluation: Context Precision, Context Recall
- Generation Evaluation: Faithfulness, Answer Relevancy, Factual Correctness
Uses pinned RAGAS API, Groq/OpenAI compatible LLM factory, ITDR internal embedding adapter,
evaluates complete structured security reports (excluding metadata), and handles rate limits safely.
"""
import os
import sys
import time
import types
import logging
from typing import List, Dict, Any, Optional

# Ensure compatibility shim for langchain_community.chat_models.vertexai if imported by legacy modules
if "langchain_community.chat_models.vertexai" not in sys.modules:
    shim = types.ModuleType("langchain_community.chat_models.vertexai")
    try:
        from langchain_google_vertexai import ChatVertexAI
        shim.ChatVertexAI = ChatVertexAI
    except ImportError:
        class ChatVertexAI:
            pass
        shim.ChatVertexAI = ChatVertexAI
    sys.modules["langchain_community.chat_models.vertexai"] = shim

from ragas.embeddings.base import BaseRagasEmbeddings
from app.core.config import get_settings
from app.services.embedding_service import EmbeddingService

logger = logging.getLogger(__name__)
settings = get_settings()


def format_report_for_evaluation(report: Any) -> str:
    """
    Formats the complete structured security report into a clean, comprehensive
    text representation for RAGAS evaluation, including all relevant report sections
    (Executive Summary, Severity, Overview, Techniques, D3FEND, Coverage, Actions, Uncertainties)
    and strictly avoiding internal metadata (timestamps, trace steps, token counts, etc.).
    """
    if isinstance(report, str):
        return report.strip()
    if not report or not isinstance(report, dict):
        return "No structured report content generated."

    lines = []

    # 1. Title & Executive Summary
    title = report.get("report_title") or "ITDR Threat Analysis Report"
    lines.append(f"Title: {title}")

    exec_summary = report.get("executive_summary", "")
    if exec_summary:
        lines.append(f"\nExecutive Summary:\n{exec_summary}")

    # 2. Severity & Rationale
    severity = report.get("severity") or "Unknown"
    rationale = report.get("severity_rationale") or ""
    lines.append(f"\nAssigned Severity: {severity}")
    if rationale:
        lines.append(f"Severity Rationale: {rationale}")

    # 3. Incident Technical Overview
    overview = report.get("incident_overview", "")
    if overview:
        lines.append(f"\nIncident Technical Overview:\n{overview}")

    # 4. Technique Candidates (Findings)
    candidates = report.get("technique_candidates", [])
    if candidates:
        lines.append("\nIdentified Threat Techniques (MITRE ATT&CK):")
        for c in candidates:
            tid = c.get("technique_id", "Unknown")
            name = c.get("name", "Unknown")
            score = c.get("relevance_score") if c.get("relevance_score") is not None else c.get("similarity_score")
            score_str = f" (Confidence: {score})" if score is not None else ""
            lines.append(f"- {tid} - {name}{score_str}")
            if c.get("rationale"):
                lines.append(f"  Rationale: {c['rationale']}")
            if c.get("tactics"):
                t_str = ", ".join(c["tactics"]) if isinstance(c["tactics"], list) else str(c["tactics"])
                lines.append(f"  Tactics: {t_str}")

    # 5. Defensive Countermeasures (D3FEND)
    defensive = report.get("defensive_techniques", [])
    if defensive:
        lines.append("\nDefensive Countermeasures (MITRE D3FEND):")
        for d in defensive:
            did = d.get("d3fend_id", "Unknown")
            dname = d.get("name", "Unknown")
            rel = d.get("relationship_type", "mitigates")
            lines.append(f"- {did} - {dname} (Relationship: {rel})")
            if d.get("rationale"):
                lines.append(f"  Rationale: {d['rationale']}")

    # 6. Detection Coverage Assessment
    coverage = report.get("coverage_assessment", [])
    if coverage:
        lines.append("\nDetection Coverage Assessment:")
        for cov in coverage:
            tid = cov.get("technique_id", "Unknown")
            status = cov.get("status", "unknown")
            rules = cov.get("active_rules_count", 0)
            tools = ", ".join(cov.get("mapped_tools", [])) if cov.get("mapped_tools") else "None"
            lines.append(f"- {tid}: Status={status}, Active Rules={rules}, Tools={tools}")

    # 7. Recommended Actions
    actions = report.get("recommended_actions", [])
    if actions:
        lines.append("\nRecommended Defensive Actions:")
        for a in actions:
            prio = a.get("priority", "High")
            cat = a.get("category", "General")
            act = a.get("action", "")
            lines.append(f"- [{prio}] [{cat}] {act}")
            if a.get("rationale"):
                lines.append(f"  Rationale: {a['rationale']}")

    # 8. Uncertainties & Analytical Limitations
    uncertainties = report.get("uncertainties", [])
    if uncertainties:
        lines.append("\nUncertainties & Analytical Limitations:")
        for u in uncertainties:
            lines.append(f"- {u}")

    return "\n".join(lines)


class ITDRRagasEmbeddings(BaseRagasEmbeddings):
    """Adapter bridging ITDR EmbeddingService to Ragas BaseRagasEmbeddings interface."""
    def __init__(self, service: Optional[EmbeddingService] = None):
        super().__init__()
        self.service = service or EmbeddingService()

    def embed_text(self, text: str) -> List[float]:
        return self.service.embed_query(text)

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        return self.service.embed_documents(texts)

    def embed_query(self, text: str) -> List[float]:
        return self.service.embed_query(text)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.service.embed_documents(texts)

    async def aembed_query(self, text: str) -> List[float]:
        return self.embed_query(text)

    async def aembed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.embed_documents(texts)


class RagasEvaluator:
    """
    RAGAS Evaluator for ITDR RAG Pipeline.
    Evaluates:
    - Context Precision
    - Context Recall
    - Faithfulness
    - Answer Relevancy
    - Factual Correctness
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
    ):
        # Resolve Evaluator LLM credentials
        # Priority: explicit arg -> EVALUATOR_LLM_API_KEY -> GROQ_API_KEY -> OPENAI_API_KEY -> backend/.env -> settings.effective_llm_key
        backend_key = None
        backend_base = None
        backend_model = None
        try:
            from dotenv import dotenv_values
            env_dict = dotenv_values("backend/.env")
            backend_key = env_dict.get("GROQ_API_KEY") or env_dict.get("XAI_API_KEY") or env_dict.get("OPENAI_API_KEY")
            backend_base = env_dict.get("XAI_API_BASE")
            backend_model = env_dict.get("XAI_MODEL")
        except Exception:
            pass

        raw_key = (
            api_key
            or os.environ.get("EVALUATOR_LLM_API_KEY")
            or os.environ.get("GROQ_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or backend_key
            or (settings.effective_llm_key if settings.has_xai_key else None)
        )

        self.api_key = raw_key if (raw_key and not raw_key.startswith("replace-") and len(raw_key.strip()) > 5) else None

        self.is_groq = bool(
            os.environ.get("GROQ_API_KEY")
            or (self.api_key and self.api_key.startswith("gsk_"))
            or (base_url and "groq" in base_url.lower())
            or (backend_base and "groq" in backend_base.lower())
            or (settings.is_groq if settings.has_xai_key else False)
        )

        if self.is_groq:
            self.base_url = base_url or os.environ.get("GROQ_BASE_URL") or backend_base or "https://api.groq.com/openai/v1"
            self.model_name = model_name or os.environ.get("EVALUATOR_LLM_MODEL") or "openai/gpt-oss-20b"
        else:
            self.base_url = base_url or os.environ.get("OPENAI_BASE_URL") or settings.effective_llm_base
            self.model_name = model_name or os.environ.get("EVALUATOR_LLM_MODEL", "gpt-4o-mini")

        self.is_configured = bool(self.api_key)

        self._llm_wrapper = None
        self._embeddings_wrapper = None
        if self.is_configured:
            self._init_ragas_components()

    def _init_ragas_components(self):
        """Initializes Ragas LLM factory and embeddings adapter."""
        try:
            import instructor
            from openai import OpenAI
            from ragas.llms import llm_factory

            client = OpenAI(api_key=self.api_key, base_url=self.base_url, max_retries=10, timeout=90)
            mode = instructor.Mode.MD_JSON if self.is_groq else instructor.Mode.JSON
            extra_kwargs = {"reasoning_effort": "low"} if ("oss" in self.model_name.lower() or "o1" in self.model_name.lower()) else {}
            self._llm_wrapper = llm_factory(
                self.model_name,
                client=client,
                mode=mode,
                max_tokens=2048,
                **extra_kwargs,
            )
            self._embeddings_wrapper = ITDRRagasEmbeddings()
            logger.info(f"Initialized RAGAS evaluator LLM ({self.model_name} at {self.base_url}) and ITDR embeddings.")
        except Exception as e:
            logger.warning(f"Failed to initialize RAGAS components via llm_factory: {e}. Attempting fallback...")
            try:
                from langchain_openai import ChatOpenAI
                from ragas.llms import LangchainLLMWrapper
                lc_llm = ChatOpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                    model=self.model_name,
                    temperature=0.0,
                    timeout=30,
                    max_retries=2,
                )
                self._llm_wrapper = LangchainLLMWrapper(lc_llm)
                self._embeddings_wrapper = ITDRRagasEmbeddings()
                logger.info(f"Initialized RAGAS evaluator fallback with Langchain wrapper ({self.model_name}).")
            except Exception as e2:
                logger.warning(f"Failed to initialize RAGAS components: {e2}")
                self.is_configured = False

    def get_metrics(self) -> List[Any]:
        """Loads and returns configured RAGAS metric instances."""
        from ragas.metrics import (
            context_precision,
            context_recall,
            faithfulness,
            answer_relevancy,
            FactualCorrectness,
        )
        factual_correctness = FactualCorrectness()
        return [
            context_precision,
            context_recall,
            faithfulness,
            answer_relevancy,
            factual_correctness,
        ]

    def evaluate_samples(
        self,
        samples_data: List[Dict[str, Any]],
        skip_generation_metrics_for_fallback: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes RAGAS evaluation on prepared evaluation samples.
        """
        if not self.is_configured or not self._llm_wrapper:
            logger.warning("RAGAS evaluator not configured (missing evaluator API key). Skipping RAGAS scores.")
            return {
                "status": "SKIPPED",
                "reason": "Evaluator LLM API key not configured in environment.",
                "per_sample_scores": [
                    {
                        "sample_id": s.get("sample_id"),
                        "context_precision": None,
                        "context_recall": None,
                        "faithfulness": None,
                        "answer_relevancy": None,
                        "factual_correctness": None,
                    }
                    for s in samples_data
                ],
                "aggregate_scores": {
                    "mean_context_precision": None,
                    "mean_context_recall": None,
                    "mean_faithfulness": None,
                    "mean_answer_relevancy": None,
                    "mean_factual_correctness": None,
                },
            }

        try:
            from ragas.dataset_schema import SingleTurnSample, EvaluationDataset
            from ragas.run_config import RunConfig
            from ragas import evaluate

            ragas_samples = []
            for s in samples_data:
                contexts = s.get("contexts") or []
                if not contexts:
                    contexts = ["No retrieved context supplied to model."]

                raw_resp = s.get("response") or s.get("structured_report") or "Insufficient evidence to generate report."
                resp = format_report_for_evaluation(raw_resp) if isinstance(raw_resp, dict) else str(raw_resp)
                ref = s.get("reference") or "Authoritative reference answer."
                q = s.get("question") or "Security advisory query."

                sample = SingleTurnSample(
                    user_input=q,
                    retrieved_contexts=contexts,
                    response=resp,
                    reference=ref,
                )
                ragas_samples.append(sample)

            metrics = self.get_metrics()
            run_cfg = RunConfig(max_workers=1, timeout=120, max_retries=10)

            logger.info(f"Running RAGAS evaluation on {len(ragas_samples)} samples across 5 metrics (max_workers=1)...")
            batch_size = 5
            dfs = []
            import pandas as pd

            for batch_start in range(0, len(ragas_samples), batch_size):
                batch_end = min(batch_start + batch_size, len(ragas_samples))
                batch_samples = ragas_samples[batch_start:batch_end]
                batch_dataset = EvaluationDataset(samples=batch_samples)
                logger.info(f"Evaluating RAGAS batch [{batch_start + 1}..{batch_end}/{len(ragas_samples)}]...")
                batch_res = evaluate(
                    dataset=batch_dataset,
                    metrics=metrics,
                    llm=self._llm_wrapper,
                    embeddings=self._embeddings_wrapper,
                    run_config=run_cfg,
                )
                dfs.append(batch_res.to_pandas())
                if batch_end < len(ragas_samples):
                    time.sleep(6)  # Paced token bucket replenishment

            df = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

            def _extract_metric_val(row, prefix):
                col = next((c for c in row.index if c == prefix or c.startswith(f"{prefix}(") or c.startswith(f"{prefix}_")), None)
                if col is not None:
                    val = row[col]
                    try:
                        fval = float(val)
                        if fval == fval:  # not NaN
                            return round(fval, 4)
                    except (ValueError, TypeError):
                        pass
                return None

            per_sample = []
            for idx, s in enumerate(samples_data):
                is_fallback = bool(s.get("is_fallback_generation", False))
                row = df.iloc[idx] if idx < len(df) else {}

                c_prec = _extract_metric_val(row, "context_precision")
                c_rec = _extract_metric_val(row, "context_recall")
                faith = _extract_metric_val(row, "faithfulness")
                ans_rel = _extract_metric_val(row, "answer_relevancy")
                fact_corr = _extract_metric_val(row, "factual_correctness")

                per_sample.append({
                    "sample_id": s.get("sample_id"),
                    "is_fallback_generation": is_fallback,
                    "context_precision": c_prec,
                    "context_recall": c_rec,
                    "faithfulness": faith,
                    "answer_relevancy": ans_rel,
                    "factual_correctness": fact_corr,
                })

            def _clean_mean(vals):
                clean = [v for v in vals if v is not None]
                return round(sum(clean) / len(clean), 4) if clean else None

            # Calculate aggregates for generation metrics (optionally excluding fallback synthesis)
            gen_samples = [s for s in per_sample if not s.get("is_fallback_generation")] if skip_generation_metrics_for_fallback else per_sample
            if not gen_samples:
                gen_samples = per_sample

            aggregate = {
                "mean_context_precision": _clean_mean([s["context_precision"] for s in per_sample]),
                "mean_context_recall": _clean_mean([s["context_recall"] for s in per_sample]),
                "mean_faithfulness": _clean_mean([s["faithfulness"] for s in gen_samples]),
                "mean_answer_relevancy": _clean_mean([s["answer_relevancy"] for s in gen_samples]),
                "mean_factual_correctness": _clean_mean([s["factual_correctness"] for s in gen_samples]),
                "evaluated_samples_count": len(samples_data),
                "llm_generation_count": len(gen_samples),
                "fallback_generation_count": len(samples_data) - len(gen_samples),
            }

            return {
                "status": "SUCCESS",
                "per_sample_scores": per_sample,
                "aggregate_scores": aggregate,
            }

        except Exception as exc:
            logger.error(f"RAGAS evaluation failed: {exc}", exc_info=True)
            return {
                "status": "ERROR",
                "reason": str(exc),
                "per_sample_scores": [],
                "aggregate_scores": {
                    "mean_context_precision": None,
                    "mean_context_recall": None,
                    "mean_faithfulness": None,
                    "mean_answer_relevancy": None,
                    "mean_factual_correctness": None,
                },
            }
