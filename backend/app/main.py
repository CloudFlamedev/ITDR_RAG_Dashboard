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

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("itdr-platform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} in {settings.APP_ENV} mode")
    logger.info(f"Database target: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else 'configured'}")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Identity Threat Detection & Response (ITDR) Platform with Grok, Hugging Face Embeddings, Neon pgvector, and Explainable RAG / GenAI Layer",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Enable CORS for local Vite development and production origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
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

