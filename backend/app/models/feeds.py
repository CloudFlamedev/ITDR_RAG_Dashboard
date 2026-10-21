import datetime
from typing import Optional
from sqlalchemy import (
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    Float,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class ThreatFeed(Base):
    """
    Threat Intelligence Bulletins and Feeds ingested from RSS, CTI feeds, and analyst uploads.
    Used for Screen 5 (Threat Intelligence Feeds) and Screen 7 (Completed Reports / Bulletins).
    """
    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bulletin_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)  # e.g., TB-2026-0010
    source: Mapped[str] = mapped_column(String(100), index=True, nullable=False)  # e.g., CISA, MS Threat Intel, Okta Advisory
    title: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    content: Mapped[Optional[str]] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    published_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    status: Mapped[str] = mapped_column(String(50), default="New", index=True)  # New, Analyzed, Review
    related_ttps: Mapped[Optional[list]] = mapped_column(JSONB, default=list)  # ["T1078", "T1110"]
    threat_actors: Mapped[Optional[list]] = mapped_column(JSONB, default=list)  # ["APT29", "Scattered Spider"]
    severity: Mapped[str] = mapped_column(String(50), default="High")  # Critical, High, Medium, Low
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    raw_payload: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)

    __table_args__ = (
        Index("idx_feed_status_pub", "status", "published_at"),
    )


class ThreatScenario(Base):
    """
    Pre-configured or evaluated multi-stage identity threat attack scenarios
    mapped onto the 2D Resilience Quadrant (Detection % vs Mitigation %).
    """
    __tablename__ = "threat_scenarios"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scenario_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(150), default="Internal ITDR Assessment")
    detection_rate: Mapped[float] = mapped_column(Float, default=0.0)   # Y-axis in Quadrant (0.0 to 100.0)
    mitigation_rate: Mapped[float] = mapped_column(Float, default=0.0)  # X-axis in Quadrant (0.0 to 100.0)
    status: Mapped[str] = mapped_column(String(50), default="Resilient", index=True)  # Resilient, Paper Tiger, High Risk, Silent Well
    scope: Mapped[str] = mapped_column(String(50), default="ITDR Scope Only")
    client_restriction: Mapped[str] = mapped_column(String(50), default="ALL")
    attack_chain_ttps: Mapped[Optional[list]] = mapped_column(JSONB, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
