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

from ragas.embeddings.base import BaseRagasEmbedding
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


class ITDRRagasEmbeddings(BaseRagasEmbedding):
    """Adapter bridging ITDR EmbeddingService to Ragas modern BaseRagasEmbedding interface."""
    def __init__(self, service: Optional[EmbeddingService] = None):
        super().__init__()
        self.service = service or EmbeddingService()

    def embed_text(self, text: str, **kwargs: Any) -> List[float]:
        return self.service.embed_query(text)

    async def aembed_text(self, text: str, **kwargs: Any) -> List[float]:
        return self.embed_text(text, **kwargs)

    def embed_texts(self, texts: List[str], **kwargs: Any) -> List[List[float]]:
        return self.service.embed_documents(texts)

    async def aembed_texts(self, texts: List[str], **kwargs: Any) -> List[List[float]]:
        return self.embed_texts(texts, **kwargs)

    # Legacy method compatibility
    def embed_query(self, text: str) -> List[float]:
        return self.embed_text(text)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.embed_texts(texts)

    async def aembed_query(self, text: str) -> List[float]:
        return self.embed_text(text)

    async def aembed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.embed_texts(texts)


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
            backend_key = (
                env_dict.get("GROQ_API_KEY_NEW_FOR_TESTING")
                or env_dict.get("GROQ_API_KEY")
                or env_dict.get("XAI_API_KEY")
                or env_dict.get("OPENAI_API_KEY")
            )
            backend_base = env_dict.get("XAI_API_BASE")
            backend_model = env_dict.get("XAI_MODEL")
        except Exception:
            pass

        raw_key = (
            api_key
            or os.environ.get("EVALUATOR_LLM_API_KEY")
            or os.environ.get("GROQ_API_KEY_NEW_FOR_TESTING")
            or os.environ.get("GROQ_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or backend_key
            or (settings.effective_llm_key if settings.has_xai_key else None)
        )

        self.api_key = raw_key if (raw_key and not raw_key.startswith("replace-") and len(raw_key.strip()) > 5) else None

        self.is_groq = bool(
            os.environ.get("GROQ_API_KEY_NEW_FOR_TESTING")
            or os.environ.get("GROQ_API_KEY")
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
        self.context_precision = None
        self.context_recall = None
        self.faithfulness = None
        self.answer_relevancy = None
        self.factual_correctness = None

        if self.is_configured:
            self._init_ragas_components()

    def _init_ragas_components(self):
        """Initializes Ragas LLM factory, embeddings adapter, and collections metrics."""
        try:
            import instructor
            from openai import OpenAI
            from ragas.llms import llm_factory
            from ragas.metrics.collections import (
                ContextPrecision,
                ContextRecall,
                Faithfulness,
                AnswerRelevancy,
                FactualCorrectness,
            )

            client = OpenAI(api_key=self.api_key, base_url=self.base_url, max_retries=10, timeout=90)
            mode = instructor.Mode.MD_JSON if self.is_groq else instructor.Mode.JSON
            extra_kwargs = {"reasoning_effort": "low"} if ("oss" in self.model_name.lower() or "o1" in self.model_name.lower()) else {}
            self._llm_wrapper = llm_factory(
                self.model_name,
                client=client,
                mode=mode,
                max_tokens=600,
                **extra_kwargs,
            )
            self._embeddings_wrapper = ITDRRagasEmbeddings()

            # Initialize collections metrics
            self.context_precision = ContextPrecision(llm=self._llm_wrapper)
            self.context_recall = ContextRecall(llm=self._llm_wrapper)
            self.faithfulness = Faithfulness(llm=self._llm_wrapper)
            self.answer_relevancy = AnswerRelevancy(llm=self._llm_wrapper, embeddings=self._embeddings_wrapper)
            self.factual_correctness = FactualCorrectness(llm=self._llm_wrapper)

            logger.info(f"Initialized RAGAS evaluator LLM ({self.model_name} at {self.base_url}), embeddings, and collections metrics.")
        except Exception as e:
            logger.warning(f"Failed to initialize RAGAS components via llm_factory: {e}. Attempting fallback...")
            try:
                from langchain_openai import ChatOpenAI
                from ragas.llms import LangchainLLMWrapper
                from ragas.metrics.collections import (
                    ContextPrecision,
                    ContextRecall,
                    Faithfulness,
                    AnswerRelevancy,
                    FactualCorrectness,
                )
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
                self.context_precision = ContextPrecision(llm=self._llm_wrapper)
                self.context_recall = ContextRecall(llm=self._llm_wrapper)
                self.faithfulness = Faithfulness(llm=self._llm_wrapper)
                self.answer_relevancy = AnswerRelevancy(llm=self._llm_wrapper, embeddings=self._embeddings_wrapper)
                self.factual_correctness = FactualCorrectness(llm=self._llm_wrapper)
                logger.info(f"Initialized RAGAS evaluator fallback with Langchain wrapper ({self.model_name}).")
            except Exception as e2:
                logger.warning(f"Failed to initialize RAGAS components: {e2}")
                self.is_configured = False

    def get_metrics(self) -> List[Any]:
        """Loads and returns configured RAGAS collections metric instances."""
        from ragas.metrics.collections import (
            ContextPrecision,
            ContextRecall,
            Faithfulness,
            AnswerRelevancy,
            FactualCorrectness,
        )
        if not self.is_configured or not self._llm_wrapper:
            from unittest.mock import MagicMock
            from ragas.llms.base import InstructorBaseRagasLLM

            class _MockInstructorLLM(InstructorBaseRagasLLM):
                def generate(self, *args, **kwargs):
                    pass
                async def agenerate(self, *args, **kwargs):
                    pass

            llm = _MockInstructorLLM()
            emb = ITDRRagasEmbeddings()
            return [
                ContextPrecision(llm=llm),
                ContextRecall(llm=llm),
                Faithfulness(llm=llm),
                AnswerRelevancy(llm=llm, embeddings=emb),
                FactualCorrectness(llm=llm),
            ]

        if self.context_precision is None:
            self.context_precision = ContextPrecision(llm=self._llm_wrapper)
            self.context_recall = ContextRecall(llm=self._llm_wrapper)
            self.faithfulness = Faithfulness(llm=self._llm_wrapper)
            self.answer_relevancy = AnswerRelevancy(llm=self._llm_wrapper, embeddings=self._embeddings_wrapper)
            self.factual_correctness = FactualCorrectness(llm=self._llm_wrapper)

        return [
            self.context_precision,
            self.context_recall,
            self.faithfulness,
            self.answer_relevancy,
            self.factual_correctness,
        ]

    async def _aevaluate_samples(
        self,
        samples_data: List[Dict[str, Any]],
        skip_generation_metrics_for_fallback: bool = True,
    ) -> Dict[str, Any]:
        """
        Asynchronously evaluates samples across collections metrics with:
        - Explicit empty context handling (0.0 score, no placeholder strings).
        - Fallback generation exclusion from Faithfulness, Answer Relevancy, and Factual Correctness.
        - Strict isolation between retrieval and generation aggregates.
        """
        import asyncio

        def _to_float(res: Any) -> Optional[float]:
            if res is None:
                return None
            val = getattr(res, "value", res)
            try:
                f = float(val)
                if f == f and not (f == float("inf") or f == float("-inf")):
                    return round(f, 4)
            except (ValueError, TypeError):
                pass
            return None

        def _clean_mean(vals: List[Any]) -> Optional[float]:
            clean = [v for v in vals if v is not None]
            return round(sum(clean) / len(clean), 4) if clean else None

        async def _safe_score(coro_fn, metric_name: str, sample_id: str, max_retries: int = 5, initial_backoff: float = 6.0) -> Optional[float]:
            backoff = initial_backoff
            for attempt in range(max_retries + 1):
                try:
                    res = await coro_fn()
                    return _to_float(res)
                except Exception as exc:
                    exc_msg = str(exc).lower()
                    is_rate_limit = any(k in exc_msg for k in ("429", "rate limit", "tokens per minute", "too large", "tpd", "otpm"))
                    if is_rate_limit and attempt < max_retries:
                        logger.warning(
                            f"[{metric_name}] Rate limit for sample {sample_id} on attempt {attempt + 1}/{max_retries}. "
                            f"Backing off for {backoff:.1f}s: {exc}"
                        )
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 1.5, 35.0)
                    else:
                        logger.warning(f"[{metric_name}] Failed for sample {sample_id} (attempt {attempt + 1}): {exc}")
                        return None
            return None

        empty_context_count = 0
        per_sample = []
        metrics = self.get_metrics()
        cp_metric, cr_metric, faith_metric, ar_metric, fc_metric = metrics[:5]

        logger.info(f"Running RAGAS collections evaluation on {len(samples_data)} samples...")

        for idx, s in enumerate(samples_data, start=1):
            s_id = s.get("sample_id", f"sample-{idx}")
            raw_contexts = s.get("contexts") or []
            contexts = [c for c in raw_contexts if c and str(c).strip()]
            has_empty_context = len(contexts) == 0
            if has_empty_context:
                empty_context_count += 1

            is_fallback = bool(s.get("is_fallback_generation", False))

            raw_resp = s.get("response") or s.get("structured_report") or "Insufficient evidence to generate report."
            resp = format_report_for_evaluation(raw_resp) if isinstance(raw_resp, dict) else str(raw_resp)
            ref = s.get("reference") or s.get("reference_answer") or "Authoritative reference answer."
            q = s.get("question") or "Security advisory query."

            # 1. Retrieval Metrics Evaluation
            # Clearly distinguish assigned failure scores from actual RAGAS LLM calculations
            c_prec = None
            c_rec = None
            retrieval_status = "RETRIEVED"

            if has_empty_context:
                logger.info(f"[{idx}/{len(samples_data)}] Sample {s_id}: Empty context supplied -> assigning explicit failure score (0.0).")
                c_prec = 0.0
                c_rec = 0.0
                retrieval_status = "EMPTY_CONTEXT_ASSIGNED_FAILURE"
            else:
                c_prec = await _safe_score(
                    lambda: cp_metric.ascore(user_input=q, reference=ref, retrieved_contexts=contexts),
                    "ContextPrecision",
                    s_id,
                )
                await asyncio.sleep(1.5)

                c_rec = await _safe_score(
                    lambda: cr_metric.ascore(user_input=q, retrieved_contexts=contexts, reference=ref),
                    "ContextRecall",
                    s_id,
                )
                await asyncio.sleep(1.5)

            # 2. Generation Metrics Evaluation
            # Exclude fallback generations from Faithfulness, Answer Relevancy, and Factual Correctness.
            faith = None
            ans_rel = None
            fact_corr = None

            if is_fallback and skip_generation_metrics_for_fallback:
                logger.info(f"[{idx}/{len(samples_data)}] Sample {s_id}: Fallback generation -> excluding from generation metrics.")
                faith = None
                ans_rel = None
                fact_corr = None
            else:
                # Faithfulness evaluation
                if has_empty_context:
                    # Missing context means response cannot be faithful to retrieved evidence
                    faith = 0.0
                else:
                    faith = await _safe_score(
                        lambda: faith_metric.ascore(user_input=q, response=resp, retrieved_contexts=contexts),
                        "Faithfulness",
                        s_id,
                    )
                    await asyncio.sleep(1.5)

                # Answer Relevancy evaluation
                ans_rel = await _safe_score(
                    lambda: ar_metric.ascore(user_input=q, response=resp),
                    "AnswerRelevancy",
                    s_id,
                )
                await asyncio.sleep(1.5)

                # Factual Correctness evaluation
                fact_corr = await _safe_score(
                    lambda: fc_metric.ascore(response=resp, reference=ref),
                    "FactualCorrectness",
                    s_id,
                )

            per_sample.append({
                "sample_id": s_id,
                "has_empty_context": has_empty_context,
                "is_assigned_empty_context_failure": has_empty_context,
                "retrieval_context_status": retrieval_status,
                "is_fallback_generation": is_fallback,
                "context_precision": c_prec,
                "context_recall": c_rec,
                "faithfulness": faith,
                "answer_relevancy": ans_rel,
                "factual_correctness": fact_corr,
            })

            # Pacing to respect API rate limits
            if idx < len(samples_data):
                await asyncio.sleep(2.0)

        # 3. Aggregate Metrics Computation
        retrieved_samples = [s for s in per_sample if not s.get("has_empty_context")]
        gen_samples = [s for s in per_sample if not s.get("is_fallback_generation")] if skip_generation_metrics_for_fallback else per_sample

        aggregate = {
            # Overall retrieval metrics (includes 0.0 penalties for empty contexts)
            "mean_context_precision": _clean_mean([s["context_precision"] for s in per_sample]),
            "mean_context_recall": _clean_mean([s["context_recall"] for s in per_sample]),
            # Pure calculated RAGAS scores strictly on samples where context was present
            "mean_calculated_context_precision": _clean_mean([s["context_precision"] for s in retrieved_samples]) if retrieved_samples else None,
            "mean_calculated_context_recall": _clean_mean([s["context_recall"] for s in retrieved_samples]) if retrieved_samples else None,
            # Generation metrics (strictly excluding fallback synthesis)
            "mean_faithfulness": _clean_mean([s["faithfulness"] for s in gen_samples]) if gen_samples else None,
            "mean_answer_relevancy": _clean_mean([s["answer_relevancy"] for s in gen_samples]) if gen_samples else None,
            "mean_factual_correctness": _clean_mean([s["factual_correctness"] for s in gen_samples]) if gen_samples else None,
            # Sample counters
            "evaluated_samples_count": len(samples_data),
            "empty_context_count": empty_context_count,
            "retrieved_context_count": len(samples_data) - empty_context_count,
            "llm_generation_count": len(gen_samples),
            "fallback_generation_count": len(samples_data) - len(gen_samples),
        }

        return {
            "status": "SUCCESS",
            "per_sample_scores": per_sample,
            "aggregate_scores": aggregate,
        }

    def evaluate_samples(
        self,
        samples_data: List[Dict[str, Any]],
        skip_generation_metrics_for_fallback: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes RAGAS evaluation on prepared evaluation samples using the collections API.
        """
        if not self.is_configured or not self._llm_wrapper:
            logger.warning("RAGAS evaluator not configured (missing evaluator API key). Skipping RAGAS scores.")
            empty_count = sum(1 for s in samples_data if not (s.get("contexts") or []))
            return {
                "status": "SKIPPED",
                "reason": "Evaluator LLM API key not configured in environment.",
                "per_sample_scores": [
                    {
                        "sample_id": s.get("sample_id"),
                        "has_empty_context": not bool(s.get("contexts") or []),
                        "is_assigned_empty_context_failure": False,
                        "retrieval_context_status": "SKIPPED",
                        "is_fallback_generation": bool(s.get("is_fallback_generation", False)),
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
                    "mean_calculated_context_precision": None,
                    "mean_calculated_context_recall": None,
                    "mean_faithfulness": None,
                    "mean_answer_relevancy": None,
                    "mean_factual_correctness": None,
                    "evaluated_samples_count": len(samples_data),
                    "empty_context_count": empty_count,
                    "retrieved_context_count": len(samples_data) - empty_count,
                    "llm_generation_count": 0,
                    "fallback_generation_count": sum(1 for s in samples_data if s.get("is_fallback_generation")),
                },
            }

        try:
            import asyncio
            loop = None
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    return executor.submit(
                        lambda: asyncio.run(self._aevaluate_samples(samples_data, skip_generation_metrics_for_fallback))
                    ).result()
            else:
                return asyncio.run(self._aevaluate_samples(samples_data, skip_generation_metrics_for_fallback))
        except Exception as exc:
            logger.error(f"RAGAS evaluation failed: {exc}", exc_info=True)
            empty_count = sum(1 for s in samples_data if not (s.get("contexts") or []))
            return {
                "status": "ERROR",
                "reason": str(exc),
                "per_sample_scores": [],
                "aggregate_scores": {
                    "mean_context_precision": None,
                    "mean_context_recall": None,
                    "mean_calculated_context_precision": None,
                    "mean_calculated_context_recall": None,
                    "mean_faithfulness": None,
                    "mean_answer_relevancy": None,
                    "mean_factual_correctness": None,
                    "evaluated_samples_count": len(samples_data),
                    "empty_context_count": empty_count,
                    "retrieved_context_count": len(samples_data) - empty_count,
                    "llm_generation_count": 0,
                    "fallback_generation_count": 0,
                },
            }
