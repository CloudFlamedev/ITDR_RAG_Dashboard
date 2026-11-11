import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import get_settings
from app.api.health import router as health_router
from app.api.reports import router as reports_router
from app.api.coverage import router as coverage_router
from app.api.feeds import router as feeds_router
from app.api.threats import router as threats_router
from app.api.rag import router as rag_router
from app.api.auth import router as auth_router
from app.api.users import router as users_router

settings = get_settings()

# Centralized Langfuse telemetry client and lifecycle
from app.core.telemetry import (
    langfuse,
    langfuse_client,
    check_telemetry_auth,
    flush_telemetry,
    observe,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("itdr-platform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} in {settings.APP_ENV} mode")
    logger.info(f"Database target: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else 'configured'}")

    # Langfuse telemetry startup check
    if settings.has_langfuse_credentials:
        if check_telemetry_auth():
            logger.info(f"Langfuse observability layer authenticated and ready (host: {settings.effective_langfuse_host}).")
        else:
            logger.warning(f"Langfuse auth_check failed for host: {settings.effective_langfuse_host}; verify credentials and host region.")
    else:
        logger.info("Langfuse credentials not configured; telemetry runs in fallback mode.")

    # Pre-warm ATT&CK taxonomy cache in background thread/task to eliminate cold-start latency
    try:
        from app.db.session import SessionLocal
        from app.services.retrieval_service import prewarm_taxonomy_cache
        with SessionLocal() as db_session:
            prewarm_taxonomy_cache(db_session)
    except Exception as exc:
        logger.warning(f"Startup taxonomy cache pre-warming skipped: {exc}")

    yield

    # Langfuse flush on graceful shutdown to prevent data loss
    flush_telemetry()
    logger.info("Langfuse telemetry events flushed successfully.")


docs_url = None if settings.is_production else "/docs"
redoc_url = None if settings.is_production else "/redoc"
openapi_url = None if settings.is_production else "/openapi.json"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Identity Threat Detection & Response (ITDR) Platform with Grok, Hugging Face Embeddings, Neon pgvector, and Explainable RAG / GenAI Layer",
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
    lifespan=lifespan,
)

# Enable CORS for exact origins with credentials support (no wildcard origins)
origins = settings.cors_origins
logger.info(f"Configuring CORS for origins: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With", "Accept"],
    expose_headers=["Retry-After"],
)

# Mount Routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(health_router)
app.include_router(reports_router)
app.include_router(coverage_router)
app.include_router(feeds_router)
app.include_router(threats_router)
app.include_router(rag_router)


@app.get("/", tags=["Root"])
def get_root():
    """Root endpoint welcoming visitors and providing API discovery links."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "status": "online",
        "documentation": "/docs",
        "health": "/health",
        "telemetry": "/api/system/status",
    }
