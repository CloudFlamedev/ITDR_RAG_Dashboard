import datetime
from typing import Optional, List
from sqlalchemy import (
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.db.base import Base


class D3fendTechnique(Base):
    """MITRE D3FEND Defensive Techniques / Countermeasures (e.g. D3-MFA, D3-LAM)."""
    __tablename__ = "d3fend_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    d3fend_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)  # e.g., D3-MFA
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    definition: Mapped[Optional[str]] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    taxonomy_path: Mapped[Optional[str]] = mapped_column(String(255), index=True)  # e.g., Defend:Model:Credential Hardening
    parent_id: Mapped[Optional[str]] = mapped_column(String(50))
    raw_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Relationships
    attack_mappings: Mapped[List["AttackDefenceMapping"]] = relationship(
        "AttackDefenceMapping", back_populates="d3fend_technique", cascade="all, delete-orphan"
    )


class AttackDefenceMapping(Base):
    """
    Explicit offensive-to-defensive relationships supported by official MITRE D3FEND
    ontology mappings. Never synthesized or guessed.
    """
    __tablename__ = "attack_defence_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_technique_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_technique_external_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    d3fend_technique_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("d3fend_techniques.id", ondelete="CASCADE"), nullable=False, index=True
    )
    d3fend_external_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(100), default="mitigates")  # mitigates, detects, protects
    provenance_url: Mapped[Optional[str]] = mapped_column(String(500))
    mapping_source: Mapped[str] = mapped_column(String(100), default="MITRE D3FEND")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Relationships
    technique: Mapped["AttackTechnique"] = relationship("AttackTechnique", back_populates="d3fend_defences")  # noqa: F821
    d3fend_technique: Mapped[D3fendTechnique] = relationship(D3fendTechnique, back_populates="attack_mappings")

    __table_args__ = (
        Index("idx_att_d3f_pair", "attack_technique_external_id", "d3fend_external_id", unique=True),
    )
