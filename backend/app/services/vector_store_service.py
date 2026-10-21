import logging
import datetime
import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.models.rag import RagDocument
from app.services.document_builder import RagDocumentDraft
from app.services.embedding_service import EmbeddingService
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class VectorStoreService:
    """
    Manages vector embeddings and similarity queries against Neon PostgreSQL.
    Leverages native pgvector (<=> cosine distance) when enabled, with transparent
    NumPy vector fallback for development and testing environments.
    """

    def __init__(self, db: Session, embedding_service: Optional[EmbeddingService] = None):
        self.db = db
        self.embedding_service = embedding_service or EmbeddingService()
        self._has_pgvector = self._detect_pgvector()

    def _detect_pgvector(self) -> bool:
        """Check if native vector extension is enabled in the active PostgreSQL session."""
        try:
            res = self.db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector';")).scalar()
            return bool(res)
        except Exception:
            return False

    def sync_documents(self, drafts: List[RagDocumentDraft], batch_size: int = 32) -> Dict[str, int]:
        """
        Idempotently synchronizes document drafts into rag_documents.
        Only generates embeddings for new or modified content hashes.
        """
        stats = {"total": len(drafts), "unchanged": 0, "embedded": 0, "inserted": 0, "updated": 0}

        # Query existing documents
        chunk_ids = [d.chunk_id for d in drafts]
        existing_docs = {
            doc.chunk_id: doc
            for doc in self.db.query(RagDocument).filter(RagDocument.chunk_id.in_(chunk_ids)).all()
        }

        to_embed: List[Tuple[RagDocumentDraft, Optional[RagDocument]]] = []

        for draft in drafts:
            doc = existing_docs.get(draft.chunk_id)
            if doc and doc.content_hash == draft.content_hash and doc.embedding_model == self.embedding_service.model_name and doc.embedding is not None:
                stats["unchanged"] += 1
            else:
                to_embed.append((draft, doc))

        if not to_embed:
            logger.info("All RAG documents are up to date.")
            return stats

        logger.info(f"Generating embeddings for {len(to_embed)} new/updated documents...")

        for i in range(0, len(to_embed), batch_size):
            batch = to_embed[i : i + batch_size]
            texts = [b[0].content for b in batch]
            vectors = self.embedding_service.embed_documents(texts)
            stats["embedded"] += len(vectors)

            now = datetime.datetime.now(datetime.timezone.utc)
            for (draft, existing_doc), vec in zip(batch, vectors):
                if existing_doc:
                    existing_doc.title = draft.title
                    existing_doc.content = draft.content
                    existing_doc.url = draft.url
                    existing_doc.version = draft.version
                    existing_doc.metadata_json = draft.metadata
                    existing_doc.content_hash = draft.content_hash
                    existing_doc.embedding_model = self.embedding_service.model_name
                    existing_doc.embedding = vec
                    existing_doc.updated_at = now
                    stats["updated"] += 1
                else:
                    new_doc = RagDocument(
                        chunk_id=draft.chunk_id,
                        source_kind=draft.source_kind,
                        document_type=draft.document_type,
                        source_object_id=draft.source_object_id,
                        external_id=draft.external_id,
                        title=draft.title,
                        content=draft.content,
                        url=draft.url,
                        version=draft.version,
                        metadata_json=draft.metadata,
                        content_hash=draft.content_hash,
                        embedding_model=self.embedding_service.model_name,
                        embedding=vec,
                        created_at=now,
                        updated_at=now,
                    )
                    self.db.add(new_doc)
                    stats["inserted"] += 1

            self.db.commit()

        logger.info(f"RAG vector sync completed: {stats}")
        return stats

    def similarity_search(
        self,
        query: str,
        top_k: int = 10,
        source_kind: Optional[str] = None,
        document_type: Optional[str] = None,
        min_score: float = 0.0,
    ) -> List[Tuple[RagDocument, float]]:
        """
        Execute semantic vector similarity search against rag_documents.
        Converts cosine distance to cosine similarity (1.0 - distance).
        """
        query_vec = self.embedding_service.embed_query(query)
        return self.similarity_search_by_vector(
            query_vec=query_vec,
            top_k=top_k,
            source_kind=source_kind,
            document_type=document_type,
            min_score=min_score,
        )

    def similarity_search_by_vector(
        self,
        query_vec: List[float],
        top_k: int = 10,
        source_kind: Optional[str] = None,
        document_type: Optional[str] = None,
        min_score: float = 0.0,
    ) -> List[Tuple[RagDocument, float]]:
        base_query = self.db.query(RagDocument).filter(RagDocument.embedding.isnot(None))

        if source_kind:
            base_query = base_query.filter(RagDocument.source_kind == source_kind)
        if document_type:
            base_query = base_query.filter(RagDocument.document_type == document_type)

        if self._has_pgvector:
            # Native Neon pgvector cosine distance operator
            results = (
                base_query
                .order_by(RagDocument.embedding.cosine_distance(query_vec))
                .limit(top_k)
                .all()
            )
            # Compute score from native vectors
            q_arr = np.array(query_vec)
            scored = []
            for doc in results:
                d_arr = np.array(doc.embedding)
                dot = np.dot(q_arr, d_arr)
                norm_q = np.linalg.norm(q_arr)
                norm_d = np.linalg.norm(d_arr)
                sim = float(dot / (norm_q * norm_d)) if (norm_q > 0 and norm_d > 0) else 0.0
                sim = max(0.0, min(1.0, sim))
                if sim >= min_score:
                    scored.append((doc, round(sim, 4)))
            return scored

        # Fallback in-memory search for local/testing without pgvector extension
        candidates = base_query.all()
        q_arr = np.array(query_vec, dtype=np.float32)
        norm_q = np.linalg.norm(q_arr)
        if norm_q == 0:
            return []

        scored = []
        for doc in candidates:
            if not doc.embedding:
                continue
            d_arr = np.array(doc.embedding, dtype=np.float32)
            norm_d = np.linalg.norm(d_arr)
            if norm_d == 0:
                continue
            sim = float(np.dot(q_arr, d_arr) / (norm_q * norm_d))
            sim = max(0.0, min(1.0, sim))
            if sim >= min_score:
                scored.append((doc, sim))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [(doc, round(score, 4)) for doc, score in scored[:top_k]]
