import time
import json
import logging
import hashlib
import urllib.request
import urllib.error
import numpy as np
from typing import List, Dict, Any, Optional
from huggingface_hub import InferenceClient
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class EmbeddingService:
    """
    Multi-provider embedding service supporting Jina AI Embeddings API,
    Hugging Face Inference Providers, and deterministic offline fallback.
    Defaulting to 384 dimensions matching Neon pgvector vector(384).
    """

    def __init__(
        self,
        token: Optional[str] = None,
        model_name: Optional[str] = None,
        expected_dim: Optional[int] = None,
        timeout: Optional[int] = None,
    ):
        self.jina_key = settings.JINA_API_KEY if settings.has_jina_key else None
        self.hf_token = token or (settings.HF_TOKEN if settings.has_hf_token else None)
        self.expected_dim = expected_dim or settings.EMBEDDING_DIMENSIONS
        self.timeout = timeout or settings.HF_TIMEOUT_SECONDS

        if self.jina_key:
            self.provider = "Jina AI"
            self.model_name = model_name or settings.JINA_EMBEDDING_MODEL or "jina-embeddings-v5-text-small"
            self.is_configured = True
            logger.info(f"Initialized EmbeddingService with Jina AI API (model: {self.model_name}, dim: {self.expected_dim})")
        elif self.hf_token:
            self.provider = "Hugging Face"
            self.model_name = model_name or settings.HF_EMBEDDING_MODEL
            self.is_configured = True
            logger.info(f"Initialized EmbeddingService with Hugging Face (model: {self.model_name}, dim: {self.expected_dim})")
        else:
            self.provider = "Offline Deterministic"
            self.model_name = "offline-bge-384"
            self.is_configured = False

        self._hf_client: Optional[InferenceClient] = None
        if self.provider == "Hugging Face" and self.hf_token:
            try:
                self._hf_client = InferenceClient(
                    model=self.model_name,
                    token=self.hf_token,
                    timeout=self.timeout,
                )
            except Exception as e:
                logger.warning(f"Could not initialize Hugging Face InferenceClient: {e}")
                self._hf_client = None

    def test_connectivity(self) -> Dict[str, Any]:
        """Verify connectivity to active embedding provider and return status."""
        try:
            vec = self.embed_query("ITDR security test")
            if vec and len(vec) == self.expected_dim:
                return {
                    "status": "connected",
                    "provider": self.provider,
                    "model": self.model_name,
                    "dimension": len(vec),
                }
            return {
                "status": "degraded",
                "provider": self.provider,
                "model": self.model_name,
                "dimension": len(vec) if vec else 0,
            }
        except Exception as e:
            return {
                "status": "error",
                "provider": self.provider,
                "model": self.model_name,
                "error": str(e),
            }

    def embed_query(self, text: str) -> List[float]:
        """Generate embedding vector for a single query text (optimized for retrieval query)."""
        if self.provider == "Jina AI" and self.jina_key:
            vectors = self._embed_jina([text], task="retrieval.query")
            if vectors:
                return vectors[0]

        vectors = self.embed_documents([text])
        return vectors[0]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """
        Batch embed documents with bounded chunk size, retry logic,
        and dimension verification.
        """
        if not texts:
            return []

        if self.provider == "Jina AI" and self.jina_key:
            return self._embed_jina(texts, task="retrieval.passage")

        if self.provider == "Hugging Face" and self._hf_client:
            return self._embed_hf(texts)

        return [self._generate_offline_embedding(t) for t in texts]

    def _embed_jina(self, texts: List[str], task: str = "retrieval.passage", batch_size: int = 64) -> List[List[float]]:
        """Batch calls to Jina AI Embeddings endpoint (https://api.jina.ai/v1/embeddings)."""
        all_embeddings: List[List[float]] = []

        for i in range(0, len(texts), batch_size):
            chunk = texts[i : i + batch_size]
            payload = {
                "model": self.model_name,
                "task": task,
                "dimensions": self.expected_dim,
                "input": chunk,
            }

            req = urllib.request.Request(
                f"{settings.JINA_API_BASE}/embeddings",
                headers={
                    "Authorization": f"Bearer {self.jina_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "ITDR-Platform/2.0",
                },
                data=json.dumps(payload).encode("utf-8"),
            )

            retries = 3
            success = False
            for attempt in range(1, retries + 1):
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        vectors = [item["embedding"] for item in data["data"]]
                        
                        # Verify dimensions
                        for v in vectors:
                            if len(v) != self.expected_dim:
                                raise ValueError(f"Jina dimension mismatch: got {len(v)}, expected {self.expected_dim}")
                        all_embeddings.extend(vectors)
                        success = True
                        break

                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt < retries:
                        time.sleep(1.5 * attempt)
                        continue
                    logger.warning(f"Jina AI API call failed ({e}); falling back to offline embeddings for batch.")
                    break
                except Exception as e:
                    logger.warning(f"Jina AI API call failed ({e}); falling back to offline embeddings for batch.")
                    break

            if not success:
                all_embeddings.extend([self._generate_offline_embedding(t) for t in chunk])

        return all_embeddings

    def _embed_hf(self, texts: List[str], batch_size: int = 16) -> List[List[float]]:
        """Batch feature extraction using Hugging Face inference API."""
        results = []
        for i in range(0, len(texts), batch_size):
            chunk = texts[i : i + batch_size]
            batch_vectors = self._embed_batch_with_retry(chunk)
            results.extend(batch_vectors)
        return results

    def _embed_batch_with_retry(self, texts: List[str], max_retries: int = 3) -> List[List[float]]:
        delay = 2.0
        for attempt in range(1, max_retries + 1):
            try:
                raw_output = self._hf_client.feature_extraction(texts)
                arr = np.array(raw_output)

                if arr.ndim == 3:
                    arr = np.mean(arr, axis=1)
                elif arr.ndim == 1:
                    arr = np.expand_dims(arr, axis=0)

                norms = np.linalg.norm(arr, axis=1, keepdims=True)
                norms[norms == 0] = 1.0
                normalized = (arr / norms).tolist()

                for vec in normalized:
                    if len(vec) != self.expected_dim:
                        raise ValueError(f"Dimension mismatch: expected {self.expected_dim}, got {len(vec)}")

                return normalized

            except Exception as exc:
                exc_str = str(exc)
                if "402" in exc_str or "Payment Required" in exc_str or "401" in exc_str or "Unauthorized" in exc_str:
                    logger.warning(f"Hugging Face API quota or credit exhausted ({exc}); switching to offline embeddings.")
                    self._hf_client = None
                    return [self._generate_offline_embedding(t) for t in texts]

                logger.warning(f"Hugging Face feature extraction attempt {attempt}/{max_retries} failed: {exc}")
                if attempt == max_retries:
                    return [self._generate_offline_embedding(t) for t in texts]
                time.sleep(delay)
                delay *= 2.0

        return [self._generate_offline_embedding(t) for t in texts]

    def _generate_offline_embedding(self, text: str) -> List[float]:
        """
        Deterministic, offline, 384-dimensional pseudo-embedding.
        Constructs normalized feature projection using SHA-256 seed hashing.
        """
        dim = self.expected_dim
        vec = np.zeros(dim, dtype=np.float32)

        words = text.lower().split()
        if not words:
            vec[0] = 1.0
            return vec.tolist()

        for w in words:
            h = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            sign = 1.0 if ((h >> 8) & 1) else -1.0
            vec[idx] += sign

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return [round(float(x), 6) for x in vec.tolist()]
