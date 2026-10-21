from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.retrieval_service import RetrievalService
from app.services.embedding_service import EmbeddingService
from app.services.vector_store_service import VectorStoreService
from app.core.config import get_settings

router = APIRouter(prefix="/api/rag", tags=["RAG & Vector Retrieval"])
settings = get_settings()


class RagSearchRequest(BaseModel):
    query: str = Field(..., min_length=3, description="Advisory text, incident narrative, or technique name/ID")
    top_k: int = Field(default=8, ge=1, le=30, description="Max candidate techniques to return")
    include_d3fend: bool = Field(default=True, description="Whether to include D3FEND countermeasures")
    source_kind: Optional[str] = Field(default=None, description="Filter by source kind: attack, d3fend, feed")


class RagSearchResponse(BaseModel):
    query_summary: str
    explicit_indicators: Dict[str, List[str]]
    candidate_count: int
    candidates: List[Dict[str, Any]]
    defensive_countermeasures: List[Dict[str, Any]]
    insufficient_evidence: bool
    highest_confidence: float


@router.post("/search", response_model=RagSearchResponse)
def search_rag_knowledge(
    req: RagSearchRequest,
    db: Session = Depends(get_db),
):
    """
    Transparent retrieval-only endpoint for debugging and inspecting candidate
    ATT&CK techniques and D3FEND defensive countermeasures before LLM generation.
    """
    retriever = RetrievalService(db)
    results = retriever.retrieve(
        advisory_text=req.query,
        max_candidates=req.top_k,
        include_d3fend=req.include_d3fend,
    )
    return results


@router.get("/health")
def get_rag_health(db: Session = Depends(get_db)):
    """
    Diagnostics endpoint verifying embedding provider, pgvector storage state,
    and dimension consistency.
    """
    embed_svc = EmbeddingService()
    connectivity = embed_svc.test_connectivity()
    vstore = VectorStoreService(db, embed_svc)

    from app.models.rag import RagDocument
    indexed_count = db.query(RagDocument).count()

    return {
        "embedding_provider": "Hugging Face Inference API",
        "embedding_model": settings.HF_EMBEDDING_MODEL,
        "configured_dimensions": settings.EMBEDDING_DIMENSIONS,
        "provider_status": connectivity,
        "storage": {
            "native_pgvector_active": vstore._has_pgvector,
            "total_indexed_chunks": indexed_count,
        }
    }
