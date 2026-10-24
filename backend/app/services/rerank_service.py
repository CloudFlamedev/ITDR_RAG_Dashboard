import time
import logging
from typing import List, Dict, Any, Optional, Tuple
import requests
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class RerankService:
    """
    Cross-Encoder Reranking Service for the ITDR RAG Pipeline.
    
    Integrates with Jina AI's state-of-the-art cross-encoder reranker models
    (e.g., jina-reranker-v2-base-multilingual) to compute deep query-document
    cross-attention scores after bi-encoder vector similarity search.

    Design Principles:
    1. Accuracy: Re-scores candidate techniques by semantic cross-attention.
    2. Exact-match preservation: Anchors explicit ATT&CK/D3FEND indicators at top rank.
    3. Resilience: Non-breaking fallback. If network timeout, rate limit (429), or API error
       occurs, gracefully returns original bi-encoder order without disrupting the RAG pipeline.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        endpoint: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: int = 15,
    ):
        self.api_key = api_key or settings.JINA_API_KEY
        self.model_name = model_name or settings.effective_rerank_model
        self.endpoint = endpoint or settings.JINA_RERANK_BASE
        self.enabled = enabled if enabled is not None else settings.RERANK_ENABLED
        self.timeout = timeout

        self.is_configured = bool(
            self.enabled
            and self.api_key
            and not self.api_key.startswith("replace-")
            and len(self.api_key.strip()) > 5
        )

        if self.is_configured:
            logger.info(f"Initialized RerankService with Jina AI ({self.model_name})")
        else:
            logger.info("RerankService initialized in pass-through / fallback mode (unconfigured or disabled)")

    def rerank(
        self,
        query: str,
        documents: List[str],
        top_n: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Calls Jina AI Rerank API to compute cross-encoder relevance scores.

        Returns list of dicts:
        [
            {"index": int, "relevance_score": float, "document": str},
            ...
        ]
        Sorted by relevance_score descending.
        """
        if not documents:
            return []

        target_top_n = min(top_n or len(documents), len(documents))

        # Pass-through if not configured
        if not self.is_configured:
            return [
                {
                    "index": idx,
                    "relevance_score": round(max(0.05, 1.0 - (idx * 0.05)), 4),
                    "document": doc,
                }
                for idx, doc in enumerate(documents[:target_top_n])
            ]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ITDR-Platform/2.0-Reranker",
        }

        payload = {
            "model": self.model_name,
            "query": query,
            "documents": documents,
            "top_n": target_top_n,
        }

        self.last_api_succeeded = False
        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", [])
                    self.last_api_succeeded = True
                    return [
                        {
                            "index": item["index"],
                            "relevance_score": float(item["relevance_score"]),
                            "document": item.get("document", {}).get("text")
                            if isinstance(item.get("document"), dict)
                            else str(item.get("document", documents[item["index"]])),
                        }
                        for item in results
                    ]

                elif response.status_code == 429:
                    logger.warning(f"Jina rerank rate limit (429) on attempt {attempt}/{max_retries}")
                    if attempt < max_retries:
                        time.sleep(1.0)
                        continue
                    break
                else:
                    logger.warning(
                        f"Jina rerank API returned status {response.status_code}: {response.text[:200]}"
                    )
                    break

            except requests.RequestException as exc:
                logger.warning(f"Jina rerank request failed on attempt {attempt}: {exc}")
                if attempt < max_retries:
                    time.sleep(0.5)
                    continue
                break
            except Exception as exc:
                logger.warning(f"Unexpected error calling Jina reranker: {exc}")
                break

        # Fallback: Identity order with original scores preserved
        self.last_api_succeeded = False
        logger.info("Falling back to pre-rerank candidate ordering.")
        return [
            {
                "index": idx,
                "relevance_score": round(max(0.05, 1.0 - (idx * 0.05)), 4),
                "document": doc,
            }
            for idx, doc in enumerate(documents[:target_top_n])
        ]

    def rerank_candidates(
        self,
        query: str,
        candidates: List[Any],
        top_n: Optional[int] = None,
    ) -> Tuple[List[Any], Dict[str, Any]]:
        """
        Reranks a list of candidate techniques (CandidateTechnique objects or dicts).
        
        Preserves exact matches at highest priority, while cross-encoder re-ranking
        optimizes semantic candidates. Returns the re-ranked candidates and detailed
        execution telemetry for observability.
        """
        start = time.perf_counter()
        target_top_n = top_n or len(candidates)

        if not candidates:
            return [], {
                "rerank_enabled": self.enabled,
                "rerank_configured": self.is_configured,
                "rerank_performed": False,
                "rerank_model": self.model_name,
                "candidates_in": 0,
                "candidates_out": 0,
                "duration_ms": 0.0,
                "error": None,
            }

        # Build document text representations for candidate techniques
        doc_texts = []
        for c in candidates:
            if hasattr(c, "technique_id"):
                tid = c.technique_id
                name = c.name
                desc = (c.description or "")[:350]
                tactics = ", ".join(c.tactics) if c.tactics else ""
            else:
                tid = c.get("technique_id", "")
                name = c.get("name", "")
                desc = (c.get("description", "") or "")[:350]
                tactics = ", ".join(c.get("tactics", []))
            
            doc_texts.append(f"MITRE ATT&CK Technique {tid} - {name} ({tactics}): {desc}")

        performed = False
        error_msg = None

        try:
            rerank_results = self.rerank(query=query, documents=doc_texts, top_n=len(candidates))
            performed = self.is_configured and self.last_api_succeeded and len(rerank_results) > 0

            if performed:
                # Map results by original candidate index
                score_by_idx = {r["index"]: r["relevance_score"] for r in rerank_results}

                # Update scores with cross-encoder relevance scores
                for idx, c in enumerate(candidates):
                    rerank_score = score_by_idx.get(idx, 0.5)
                    is_exact = getattr(c, "is_exact_match", False) if hasattr(c, "is_exact_match") else c.get("is_exact_match", False)

                    if is_exact:
                        # Keep exact indicators locked at peak confidence
                        final_score = 1.0
                    else:
                        final_score = round(float(rerank_score), 4)

                    if hasattr(c, "score"):
                        c.score = final_score
                    elif "similarity_score" in c:
                        c["similarity_score"] = final_score
                    elif "score" in c:
                        c["score"] = final_score
            else:
                logger.info("Reranker did not run via API; keeping original candidate similarity scores.")

        except Exception as exc:
            error_msg = str(exc)
            logger.warning(f"Error during candidate reranking: {exc}")

        # Re-sort candidates: exact matches first, then descending by updated score
        def _sort_key(item):
            is_exact = getattr(item, "is_exact_match", False) if hasattr(item, "is_exact_match") else item.get("is_exact_match", False)
            score = getattr(item, "score", 0.0) if hasattr(item, "score") else item.get("similarity_score", item.get("score", 0.0))
            return (1 if is_exact else 0, score)

        reranked = sorted(candidates, key=_sort_key, reverse=True)[:target_top_n]
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        meta = {
            "rerank_enabled": self.enabled,
            "rerank_configured": self.is_configured,
            "rerank_performed": performed,
            "rerank_model": self.model_name,
            "candidates_in": len(candidates),
            "candidates_out": len(reranked),
            "duration_ms": duration_ms,
            "error": error_msg,
        }

        return reranked, meta
