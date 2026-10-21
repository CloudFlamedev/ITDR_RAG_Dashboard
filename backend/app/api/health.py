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

    # Grok xAI Status
    xai_status = "Online" if settings.has_xai_key else "Not Configured"
    if settings.has_xai_key and settings.XAI_API_KEY.startswith("replace-"):
        xai_status = "Not Configured"

    # Hugging Face Status
    hf_status = "Online" if settings.has_hf_token else "Not Configured"
    if settings.has_hf_token and settings.HF_TOKEN.startswith("replace-"):
        hf_status = "Not Configured"

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
            "xai_grok": {
                "status": xai_status,
                "model": settings.XAI_MODEL,
                "base_url": settings.XAI_API_BASE,
                "configured": settings.has_xai_key,
            },
            "huggingface": {
                "status": hf_status,
                "model": settings.HF_EMBEDDING_MODEL,
                "dimensions": settings.EMBEDDING_DIMENSIONS,
                "configured": settings.has_hf_token,
            },
            "knowledge_base": kb_stats,
        }
    }
