import datetime
from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db.session import get_db, check_db_health
from app.core.config import get_settings
from app.models.attack import AttackTechnique, AttackTactic
from app.models.d3fend import D3fendTechnique
from app.models.coverage import DetectionRule
from app.models.rag import RagDocument

router = APIRouter(tags=["Health & Telemetry"])
settings = get_settings()


@router.get("/health")
def get_liveness() -> Dict[str, Any]:
    """Lightweight liveness check for orchestrators and container health probes."""
    return {
        "status": "healthy",
        "service": "itdr-platform-api",
        "version": settings.APP_VERSION,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


@router.get("/api/system/status")
def get_system_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Comprehensive multi-subsystem heartbeat telemetry.
    Checks Neon/PostgreSQL database, pgvector extension, Grok/xAI API readiness,
    Hugging Face inference embedding readiness, and knowledge base index volume.
    """
    db_health = check_db_health()

    # Query KB statistics from database
    kb_stats = {
        "techniques_count": 0,
        "tactics_count": 0,
        "d3fend_count": 0,
        "rules_count": 0,
        "rag_indexed_chunks": 0,
        "last_sync": None,
    }

    if db_health["connected"]:
        try:
            kb_stats["techniques_count"] = db.query(AttackTechnique).count()
            kb_stats["tactics_count"] = db.query(AttackTactic).count()
            kb_stats["d3fend_count"] = db.query(D3fendTechnique).count()
            kb_stats["rules_count"] = db.query(DetectionRule).count()
            kb_stats["rag_indexed_chunks"] = db.query(RagDocument).count()

            # Find latest update time in rag_documents
            latest_doc = db.query(RagDocument.updated_at).order_by(RagDocument.updated_at.desc()).first()
            if latest_doc and latest_doc[0]:
                kb_stats["last_sync"] = latest_doc[0].isoformat()
        except Exception as e:
            kb_stats["error"] = str(e)

    # Active LLM Status (Groq or xAI)
    llm_provider_name = "Groq" if settings.is_groq else "xAI Grok"
    llm_status = "Online" if settings.has_xai_key else "Not Configured"

    # Active Embedding Status (Jina AI or Hugging Face)
    emb_provider_name = settings.effective_embedding_provider
    emb_status = "Online" if (settings.has_jina_key or settings.has_hf_token) else "Not Configured"

    # Active Reranker Status (Jina AI)
    rerank_status = "Online" if settings.has_reranker else "Not Configured"

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "environment": settings.APP_ENV,
        "demo_mode": settings.DEMO_MODE,
        "subsystems": {
            "database": {
                "status": "Online" if db_health["connected"] else "Offline",
                "is_neon": settings.is_neon,
                "latency_ms": db_health["latency_ms"],
                "version": db_health["version"],
                "error": db_health["error"],
            },
            "pgvector": {
                "status": "Enabled" if db_health["pgvector_enabled"] else "Fallback / Not Detected",
                "enabled": db_health["pgvector_enabled"],
                "embedding_dimensions": settings.EMBEDDING_DIMENSIONS,
                "note": "Native pgvector active on Neon" if db_health["pgvector_enabled"] else "Using resilient array fallback; enable extension in Neon via CREATE EXTENSION vector",
            },
            "llm": {
                "provider": llm_provider_name,
                "status": llm_status,
                "model": settings.effective_llm_model,
                "base_url": settings.effective_llm_base,
                "configured": settings.has_xai_key,
            },
            "embedding": {
                "provider": emb_provider_name,
                "status": emb_status,
                "model": settings.effective_embedding_model,
                "dimensions": settings.EMBEDDING_DIMENSIONS,
                "configured": bool(settings.has_jina_key or settings.has_hf_token),
            },
            "reranker": {
                "provider": "Jina AI" if settings.has_jina_key else "Offline / Passthrough",
                "status": rerank_status,
                "model": settings.effective_rerank_model,
                "enabled": settings.RERANK_ENABLED,
                "configured": settings.has_reranker,
            },
            # Backward-compatibility aliases for frontend telemetry
            "xai_grok": {
                "provider": llm_provider_name,
                "status": llm_status,
                "model": settings.effective_llm_model,
                "base_url": settings.effective_llm_base,
                "configured": settings.has_xai_key,
            },
            "huggingface": {
                "provider": emb_provider_name,
                "status": emb_status,
                "model": settings.effective_embedding_model,
                "dimensions": settings.EMBEDDING_DIMENSIONS,
                "configured": bool(settings.has_jina_key or settings.has_hf_token),
            },
            "knowledge_base": kb_stats,
        }
    }
