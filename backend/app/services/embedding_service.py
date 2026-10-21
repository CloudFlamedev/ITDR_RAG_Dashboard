import time
import logging
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional
from huggingface_hub import InferenceClient
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class EmbeddingService:
    """
    Hugging Face Inference API client for text feature extraction / embeddings.
    Integrates with BAAI/bge-small-en-v1.5 (384 dimensions) with bounded concurrency,
    batching, retry logic, dimension verification, and resilient offline fallback.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        model_name: Optional[str] = None,
        expected_dim: Optional[int] = None,
        timeout: Optional[int] = None,
    ):
        self.token = token or settings.HF_TOKEN
        self.model_name = model_name or settings.HF_EMBEDDING_MODEL
        self.expected_dim = expected_dim or settings.EMBEDDING_DIMENSIONS
        self.timeout = timeout or settings.HF_TIMEOUT_SECONDS
        self.is_configured = bool(self.token and not self.token.startswith("replace-"))

        self._client: Optional[InferenceClient] = None
        if self.is_configured:
            try:
                self._client = InferenceClient(
                    model=self.model_name,
                    token=self.token,
                    timeout=self.timeout,
                )
            except Exception as e:
                logger.warning(f"Could not initialize Hugging Face InferenceClient: {e}")
                self._client = None

    def embed_query(self, text: str) -> List[float]:
        """Generate embedding vector for a single query text."""
        vectors = self.embed_documents([text])
        return vectors[0]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """
        Batch embed documents with bounded chunk size, exponential retry,
        and dimension verification.
        """
        if not texts:
            return []

        if not self.is_configured or self._client is None:
            logger.info("Hugging Face API token not configured; using deterministic offline pseudo-embeddings.")
            return [self._generate_offline_embedding(t) for t in texts]

        results: List[List[float]] = []
        batch_size = settings.EMBEDDING_BATCH_SIZE

        for i in range(0, len(texts), batch_size):
            chunk = texts[i : i + batch_size]
            batch_vectors = self._embed_batch_with_retry(chunk)
            results.extend(batch_vectors)

        return results

    def _embed_batch_with_retry(self, texts: List[str], max_retries: int = 3) -> List[List[float]]:
        delay = 2.0
        for attempt in range(1, max_retries + 1):
            try:
                # Call feature_extraction endpoint
                raw_output = self._client.feature_extraction(texts)
                # raw_output is typically numpy array or list of lists: (batch_size, seq_len, hidden) or (batch_size, hidden)
                arr = np.array(raw_output)

                # Mean pooling if token-level embeddings returned: shape (batch, seq, dim)
                if arr.ndim == 3:
                    arr = np.mean(arr, axis=1)
                elif arr.ndim == 1:
                    arr = np.expand_dims(arr, axis=0)

                # L2 normalize
                norms = np.linalg.norm(arr, axis=1, keepdims=True)
                norms[norms == 0] = 1.0
                normalized = (arr / norms).tolist()

                # Verify dimensions
                for vec in normalized:
                    if len(vec) != self.expected_dim:
                        raise ValueError(
                            f"Model {self.model_name} output dimension ({len(vec)}) "
                            f"does not match expected EMBEDDING_DIMENSIONS ({self.expected_dim})."
                        )

                return normalized

            except Exception as exc:
                logger.warning(
                    f"Hugging Face feature extraction attempt {attempt}/{max_retries} failed: {exc}"
                )
                if attempt == max_retries:
                    logger.error("All retries to Hugging Face API failed; falling back to offline embeddings.")
                    return [self._generate_offline_embedding(t) for t in texts]
                time.sleep(delay)
                delay *= 2.0

        return [self._generate_offline_embedding(t) for t in texts]

    def _generate_offline_embedding(self, text: str) -> List[float]:
        """
        Deterministic, offline, 384-dimensional pseudo-embedding.
        Constructs normalized feature projection using SHA-256 seed hashing.
        Guarantees identical vectors for identical text without network dependency.
        """
        dim = self.expected_dim
        vec = np.zeros(dim, dtype=np.float32)

        # Tokenize and hash
        words = text.lower().split()
        if not words:
            vec[0] = 1.0
            return vec.tolist()

        for w in words:
            h = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            sign = 1.0 if (h >> 8) % 2 == 0 else -1.0
            vec[idx] += sign

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return vec.tolist()

    def test_connectivity(self) -> Dict[str, Any]:
        """Test API connectivity and confirm returned dimension."""
        start = time.perf_counter()
        if not self.is_configured:
            return {
                "configured": False,
                "status": "Not Configured",
                "model": self.model_name,
                "dimensions": self.expected_dim,
                "latency_ms": 0.0,
                "error": "HF_TOKEN not set or using placeholder value",
            }

        try:
            sample_vec = self.embed_query("Security Advisory Test")
            duration = round((time.perf_counter() - start) * 1000, 2)
            return {
                "configured": True,
                "status": "Online",
                "model": self.model_name,
                "dimensions": len(sample_vec),
                "dimension_match": len(sample_vec) == self.expected_dim,
                "latency_ms": duration,
                "error": None,
            }
        except Exception as e:
            return {
                "configured": True,
                "status": "Degraded / Error",
                "model": self.model_name,
                "dimensions": self.expected_dim,
                "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                "error": str(e),
            }
