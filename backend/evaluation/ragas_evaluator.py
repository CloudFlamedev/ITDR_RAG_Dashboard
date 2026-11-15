"""
RAGAS Automated Evaluation Engine for the ITDR RAG Pipeline.
Implements:
- Retrieval Evaluation: Context Precision, Context Recall
- Generation Evaluation: Faithfulness, Answer Relevancy, Factual Correctness
Uses pinned RAGAS API, Groq/OpenAI compatible LLM wrapper, ITDR internal embedding wrapper,
and handles missing evaluator credentials and fallback-generated cases safely.
"""
import os
import sys
import types
import logging
from typing import List, Dict, Any, Optional

# Ensure compatibility shim for langchain_community.chat_models.vertexai
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

from langchain_core.embeddings import Embeddings
from app.core.config import get_settings
from app.services.embedding_service import EmbeddingService

logger = logging.getLogger(__name__)
settings = get_settings()


class ITDRLangchainEmbeddings(Embeddings):
    """Adapter bridging ITDR EmbeddingService to LangChain and Ragas Embeddings interface."""
    def __init__(self, service: Optional[EmbeddingService] = None):
        self.service = service or EmbeddingService()

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return self.service.embed_documents(texts)

    def embed_query(self, text: str) -> List[float]:
        return self.service.embed_query(text)


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
        # Priority: explicit arg -> EVALUATOR_LLM_API_KEY -> GROQ_API_KEY -> OPENAI_API_KEY -> settings.effective_llm_key
        raw_key = (
            api_key
            or os.environ.get("EVALUATOR_LLM_API_KEY")
            or os.environ.get("GROQ_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or (settings.effective_llm_key if settings.has_xai_key else None)
        )
        self.api_key = raw_key if (raw_key and not raw_key.startswith("replace-") and len(raw_key.strip()) > 5) else None

        self.is_groq = bool(
            os.environ.get("GROQ_API_KEY")
            or (settings.is_groq if settings.has_xai_key else False)
            or (self.api_key and self.api_key.startswith("gsk_"))
        )

        if self.is_groq:
            self.base_url = base_url or os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
            self.model_name = model_name or os.environ.get("EVALUATOR_LLM_MODEL", "llama-3.3-70b-versatile")
        else:
            self.base_url = base_url or os.environ.get("OPENAI_BASE_URL") or settings.effective_llm_base
            self.model_name = model_name or os.environ.get("EVALUATOR_LLM_MODEL", "gpt-4o-mini")

        self.is_configured = bool(self.api_key)

        self._llm_wrapper = None
        self._embeddings_wrapper = None
        if self.is_configured:
            self._init_ragas_components()

    def _init_ragas_components(self):
        """Initializes Langchain LLM and Embeddings wrapped for RAGAS evaluation."""
        try:
            from langchain_openai import ChatOpenAI
            from ragas.llms import LangchainLLMWrapper
            from ragas.embeddings import LangchainEmbeddingsWrapper

            lc_llm = ChatOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                model=self.model_name,
                temperature=0.0,
                timeout=25,
                max_retries=1,
            )
            self._llm_wrapper = LangchainLLMWrapper(lc_llm)
            self._embeddings_wrapper = LangchainEmbeddingsWrapper(ITDRLangchainEmbeddings())
            logger.info(f"Initialized RAGAS evaluator LLM ({self.model_name} at {self.base_url}) and ITDR embeddings.")
        except Exception as e:
            logger.warning(f"Failed to initialize RAGAS components: {e}")
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
        
        Args:
            samples_data: List of dicts, each with:
                - sample_id: str
                - question: str
                - contexts: List[str] (exact contexts passed to LLM)
                - response: str (generated report text/summary)
                - reference: str (ground-truth reference answer)
                - is_fallback_generation: bool
            skip_generation_metrics_for_fallback: whether to separate fallback reports
                from real LLM generation scores.
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
            from ragas import evaluate

            ragas_samples = []
            for s in samples_data:
                contexts = s.get("contexts") or []
                if not contexts:
                    contexts = ["No retrieved context supplied to model."]
                
                resp = s.get("response") or "Insufficient evidence to generate report."
                ref = s.get("reference") or "Authoritative reference answer."
                q = s.get("question") or "Security advisory query."

                sample = SingleTurnSample(
                    user_input=q,
                    retrieved_contexts=contexts,
                    response=resp,
                    reference=ref,
                )
                ragas_samples.append(sample)

            eval_dataset = EvaluationDataset(samples=ragas_samples)
            metrics = self.get_metrics()

            logger.info(f"Running RAGAS evaluation on {len(ragas_samples)} samples across 5 metrics...")
            eval_result = evaluate(
                dataset=eval_dataset,
                metrics=metrics,
                llm=self._llm_wrapper,
                embeddings=self._embeddings_wrapper,
            )

            df = eval_result.to_pandas()
            per_sample = []
            for idx, s in enumerate(samples_data):
                is_fallback = bool(s.get("is_fallback_generation", False))
                row = df.iloc[idx] if idx < len(df) else {}

                c_prec = float(row.get("context_precision", 0.0)) if "context_precision" in row and not (row.get("context_precision") != row.get("context_precision")) else None
                c_rec = float(row.get("context_recall", 0.0)) if "context_recall" in row and not (row.get("context_recall") != row.get("context_recall")) else None
                faith = float(row.get("faithfulness", 0.0)) if "faithfulness" in row and not (row.get("faithfulness") != row.get("faithfulness")) else None
                ans_rel = float(row.get("answer_relevancy", 0.0)) if "answer_relevancy" in row and not (row.get("answer_relevancy") != row.get("answer_relevancy")) else None
                fact_corr = float(row.get("factual_correctness", 0.0)) if "factual_correctness" in row and not (row.get("factual_correctness") != row.get("factual_correctness")) else None

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
