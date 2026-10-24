import datetime
import json
from typing import Optional, List
from sqlalchemy import (
    Integer,
    String,
    Text,
    DateTime,
    Index,
)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base
from app.core.config import get_settings

settings = get_settings()


from pgvector.sqlalchemy import Vector

class SafeVectorType(TypeDecorator):
    """
    Resilient vector column type supporting native Neon pgvector (vector(384)).
    Serializes Python float arrays consistently and parses database vector outputs.
    """
    impl = Vector(settings.EMBEDDING_DIMENSIONS)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if hasattr(value, "tolist"):
            return [float(x) for x in value.tolist()]
        if isinstance(value, (list, tuple)):
            return [float(x) for x in value]
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                clean = value.strip("[]").split(",")
                return [float(x.strip()) for x in clean if x.strip()]
        return list(value)


class RagDocument(Base):
    """
    RAG Knowledge Base Document chunks.
    Maintains semantic chunks of MITRE ATT&CK techniques, ATT&CK procedure usages,
    MITRE D3FEND defensive countermeasures, and security advisories.
    Stored in Neon PostgreSQL with pgvector for high-performance cosine similarity search.
    """
    __tablename__ = "rag_documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chunk_id: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    source_kind: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # attack, d3fend, feed
    document_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # technique, procedure, defensive, advisory
    source_object_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)  # STIX ID or raw ID
    external_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)  # e.g. T1078, D3-MFA
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    version: Mapped[Optional[str]] = mapped_column(String(50), default="1.0")
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    embedding_model: Mapped[str] = mapped_column(String(150), default=settings.HF_EMBEDDING_MODEL)

    # Embedding column with SafeVectorType (works with both pgvector and JSONB storage)
    embedding: Mapped[Optional[List[float]]] = mapped_column(SafeVectorType, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    __table_args__ = (
        Index("idx_rag_source_ext", "source_kind", "external_id"),
        Index("idx_rag_doc_type", "document_type"),
    )
