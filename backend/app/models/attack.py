import datetime
from typing import List, Optional
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Table,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.db.base import Base

# Many-to-many association between Techniques and Tactics
technique_tactic_map = Table(
    "technique_tactic_map",
    Base.metadata,
    Column("technique_id", Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), primary_key=True),
    Column("tactic_id", Integer, ForeignKey("attack_tactics.id", ondelete="CASCADE"), primary_key=True),
)


class StixObject(Base):
    """Stores raw MITRE ATT&CK STIX 2.1 objects with versioning and audit timestamps."""
    __tablename__ = "stix_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    object_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    spec_version: Mapped[Optional[str]] = mapped_column(String(50), default="2.1")
    created: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True))
    modified: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_stix: Mapped[dict] = mapped_column(JSONB, nullable=False)
    ingested_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    __table_args__ = (
        Index("idx_stix_type_id", "object_type", "stix_id"),
    )


class AttackTactic(Base):
    """MITRE ATT&CK Tactics (e.g. Initial Access, Persistence, Credential Access)."""
    __tablename__ = "attack_tactics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    external_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)  # e.g., TA0001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    short_name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)  # e.g., initial-access
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Relationships
    techniques: Mapped[List["AttackTechnique"]] = relationship(
        "AttackTechnique", secondary=technique_tactic_map, back_populates="tactics"
    )


class AttackTechnique(Base):
    """MITRE ATT&CK Techniques & Sub-techniques (e.g. T1078 Valid Accounts, T1098)."""
    __tablename__ = "attack_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    technique_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)  # e.g., T1078
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_technique_id: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    platforms: Mapped[Optional[list]] = mapped_column(JSONB, default=list)
    is_identity_relevant: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Relationships
    tactics: Mapped[List[AttackTactic]] = relationship(
        AttackTactic, secondary=technique_tactic_map, back_populates="techniques"
    )
    rule_mappings: Mapped[List["DetectionRuleTechnique"]] = relationship(  # noqa: F821
        "DetectionRuleTechnique", back_populates="technique", cascade="all, delete-orphan"
    )
    d3fend_defences: Mapped[List["AttackDefenceMapping"]] = relationship(  # noqa: F821
        "AttackDefenceMapping", back_populates="technique", cascade="all, delete-orphan"
    )
    procedures: Mapped[List["TechniqueProcedure"]] = relationship(
        "TechniqueProcedure", back_populates="technique", cascade="all, delete-orphan"
    )


class AttackSoftware(Base):
    """Adversary Groups, Malware, and Tools tracked in ATT&CK."""
    __tablename__ = "attack_software"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    external_id: Mapped[Optional[str]] = mapped_column(String(50), index=True)  # e.g., G0016 or S0002
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    software_type: Mapped[str] = mapped_column(String(50), index=True)  # intrusion-set, malware, tool
    description: Mapped[Optional[str]] = mapped_column(Text)
    aliases: Mapped[Optional[list]] = mapped_column(JSONB, default=list)


class TechniqueProcedure(Base):
    """Concrete usage of techniques by software/groups (ATT&CK procedure examples)."""
    __tablename__ = "technique_procedures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    relationship_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False)
    source_software_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("attack_software.id", ondelete="SET NULL"))
    source_name: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    external_references: Mapped[Optional[list]] = mapped_column(JSONB, default=list)

    # Relationships
    technique: Mapped[AttackTechnique] = relationship(AttackTechnique, back_populates="procedures")
    software: Mapped[Optional[AttackSoftware]] = relationship(AttackSoftware)
