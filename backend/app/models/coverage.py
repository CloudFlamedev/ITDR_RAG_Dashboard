import datetime
from typing import Optional, List
from sqlalchemy import (
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.db.base import Base


class DetectionRule(Base):
    """
    Security detection rules and controls from connected identity & endpoint tools
    (e.g., CrowdStrike Falcon, Microsoft Defender for Identity, Okta, Wiz, In-House).
    """
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    client_restriction: Mapped[str] = mapped_column(String(50), default="ALL", index=True)  # ALL, Client Restricted, Unrestricted
    itdr_scope: Mapped[str] = mapped_column(String(50), default="ITDR Scope Only", index=True)  # ALL, ITDR Scope Only, Non-ITDR
    rule_type: Mapped[str] = mapped_column(String(50), default="Detection")  # Detection, Prevention, Control Validation
    fidelity: Mapped[str] = mapped_column(String(50), default="High")  # High, Medium, Low
    severity: Mapped[str] = mapped_column(String(50), default="High")  # Critical, High, Medium, Low
    last_observed: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    raw_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # Relationships
    technique_mappings: Mapped[List["DetectionRuleTechnique"]] = relationship(
        "DetectionRuleTechnique", back_populates="rule", cascade="all, delete-orphan"
    )


class DetectionRuleTechnique(Base):
    """
    Many-to-many mapping between active rules and ATT&CK techniques.
    One technique can be defended by multiple rules from multiple tools.
    """
    __tablename__ = "detection_rule_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_external_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    coverage_level: Mapped[str] = mapped_column(String(50), default="Complete")  # Complete, Partial, Testing
    validation_status: Mapped[str] = mapped_column(String(50), default="Verified")

    # Relationships
    rule: Mapped[DetectionRule] = relationship(DetectionRule, back_populates="technique_mappings")
    technique: Mapped["AttackTechnique"] = relationship("AttackTechnique", back_populates="rule_mappings")  # noqa: F821

    __table_args__ = (
        Index("idx_rule_tech_pair", "rule_id", "technique_id", unique=True),
    )
