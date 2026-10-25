import logging
import time
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Configure engine with connection pooling and pre-ping to handle cloud sleep/wake
engine = create_engine(
    settings.normalized_database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to provide a transactional database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_health() -> Dict[str, Any]:
    """
    Verify PostgreSQL connectivity and check whether the pgvector extension is enabled.
    Returns diagnostic telemetry for system health indicators.
    """
    start = time.perf_counter()
    status = {
        "connected": False,
        "database_type": "PostgreSQL",
        "is_neon": settings.is_neon,
        "pgvector_enabled": False,
        "latency_ms": 0.0,
        "version": None,
        "error": None,
    }

    try:
        with engine.connect() as conn:
            # Query database version
            ver_res = conn.execute(text("SELECT version();")).scalar()
            status["version"] = ver_res
            status["connected"] = True

            # Query pgvector extension
            vec_res = conn.execute(
                text("SELECT 1 FROM pg_extension WHERE extname = 'vector';")
            ).scalar()
            status["pgvector_enabled"] = bool(vec_res)

        status["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        status["error"] = str(exc)
        status["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)

    return status
