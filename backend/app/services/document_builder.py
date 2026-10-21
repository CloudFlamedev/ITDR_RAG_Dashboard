import hashlib
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.attack import AttackTechnique, TechniqueProcedure
from app.models.d3fend import D3fendTechnique
from app.models.feeds import ThreatFeed
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def compute_content_hash(text: str) -> str:
    """Calculate deterministic SHA-256 hash of document text content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RagDocumentDraft:
    def __init__(
        self,
        chunk_id: str,
        source_kind: str,
        document_type: str,
        source_object_id: Optional[str],
        external_id: str,
        title: str,
        content: str,
        url: Optional[str],
        version: str = "1.0",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.chunk_id = chunk_id
        self.source_kind = source_kind
        self.document_type = document_type
        self.source_object_id = source_object_id
        self.external_id = external_id
        self.title = title
        self.content = content.strip()
        self.url = url
        self.version = version
        self.metadata = metadata or {}
        self.content_hash = compute_content_hash(self.content)


class DocumentBuilderService:
    """
    Constructs high-fidelity, semantic, source-linked text documents for RAG.
    Favors clear field labeling and rich contextual metadata over arbitrary text chunking.
    """

    def __init__(self, db: Session):
        self.db = db

    def build_attack_technique_documents(self, identity_only: bool = False) -> List[RagDocumentDraft]:
        query = self.db.query(AttackTechnique).filter_by(revoked=False, deprecated=False)
        if identity_only:
            query = query.filter_by(is_identity_relevant=True)

        techniques = query.all()
        drafts = []

        for tech in techniques:
            tactics_str = ", ".join([f"{t.name} ({t.external_id})" for t in tech.tactics])
            platforms_str = ", ".join(tech.platforms or [])

            content_parts = [
                f"MITRE ATT&CK Technique: {tech.technique_id} - {tech.name}",
                f"Tactics: {tactics_str or 'Enterprise ATT&CK'}",
                f"Platforms: {platforms_str or 'Universal'}",
                f"Sub-technique: {'Yes (Parent: ' + (tech.parent_technique_id or 'None') + ')' if tech.is_subtechnique else 'No'}",
                f"Identity Relevant: {'Yes' if tech.is_identity_relevant else 'General'}",
                f"Description:\n{tech.description or 'No official description available.'}",
                f"Official Reference: {tech.url or f'https://attack.mitre.org/techniques/{tech.technique_id}'}"
            ]
            content = "\n\n".join(content_parts)

            drafts.append(
                RagDocumentDraft(
                    chunk_id=f"att-tech-{tech.technique_id}",
                    source_kind="attack",
                    document_type="technique",
                    source_object_id=tech.stix_id,
                    external_id=tech.technique_id,
                    title=f"ATT&CK {tech.technique_id}: {tech.name}",
                    content=content,
                    url=tech.url or f"https://attack.mitre.org/techniques/{tech.technique_id}",
                    metadata={
                        "technique_id": tech.technique_id,
                        "name": tech.name,
                        "tactics": [t.short_name for t in tech.tactics],
                        "is_subtechnique": tech.is_subtechnique,
                        "is_identity_relevant": tech.is_identity_relevant,
                    },
                )
            )

        logger.info(f"Built {len(drafts)} ATT&CK technique documents.")
        return drafts

    def build_attack_procedure_documents(self, max_procedures: int = 500) -> List[RagDocumentDraft]:
        # Prioritize procedures linked to identity-relevant techniques
        procedures = (
            self.db.query(TechniqueProcedure)
            .join(AttackTechnique)
            .filter(AttackTechnique.is_identity_relevant.is_(True))
            .limit(max_procedures)
            .all()
        )

        drafts = []
        for proc in procedures:
            tech = proc.technique
            actor = proc.source_name or "Adversary"
            content = (
                f"ATT&CK In-the-Wild Procedure Example\n"
                f"Technique: {tech.technique_id} ({tech.name})\n"
                f"Threat Actor / Tool: {actor}\n"
                f"Procedure Execution Details:\n{proc.description}\n"
                f"Official Reference: https://attack.mitre.org/techniques/{tech.technique_id}"
            )

            drafts.append(
                RagDocumentDraft(
                    chunk_id=f"att-proc-{proc.relationship_id}",
                    source_kind="attack",
                    document_type="procedure",
                    source_object_id=proc.relationship_id,
                    external_id=tech.technique_id,
                    title=f"Procedure: {actor} using {tech.technique_id} ({tech.name})",
                    content=content,
                    url=tech.url or f"https://attack.mitre.org/techniques/{tech.technique_id}",
                    metadata={
                        "technique_id": tech.technique_id,
                        "source_name": actor,
                    },
                )
            )

        logger.info(f"Built {len(drafts)} ATT&CK procedure documents.")
        return drafts

    def build_d3fend_defensive_documents(self) -> List[RagDocumentDraft]:
        d3f_records = self.db.query(D3fendTechnique).all()
        drafts = []

        for d3f in d3f_records:
            # Check mappings to ATT&CK
            mapped_att = [m.attack_technique_external_id for m in d3f.attack_mappings]
            mapped_str = ", ".join(mapped_att) if mapped_att else "General Defensive Countermeasure"

            content = (
                f"MITRE D3FEND Defensive Technique: {d3f.d3fend_id} - {d3f.name}\n"
                f"Taxonomy Classification: {d3f.taxonomy_path or 'Defend Ontology'}\n"
                f"Official Definition:\n{d3f.definition or 'No official definition available.'}\n"
                f"Mapped ATT&CK Techniques: {mapped_str}\n"
                f"Official Reference: {d3f.url or f'https://d3fend.mitre.org/technique/{d3f.d3fend_id}'}"
            )

            drafts.append(
                RagDocumentDraft(
                    chunk_id=f"d3f-tech-{d3f.d3fend_id}",
                    source_kind="d3fend",
                    document_type="defensive",
                    source_object_id=d3f.d3fend_id,
                    external_id=d3f.d3fend_id,
                    title=f"D3FEND {d3f.d3fend_id}: {d3f.name}",
                    content=content,
                    url=d3f.url or f"https://d3fend.mitre.org/technique/{d3f.d3fend_id}",
                    metadata={
                        "d3fend_id": d3f.d3fend_id,
                        "name": d3f.name,
                        "taxonomy": d3f.taxonomy_path,
                        "mapped_attack_techniques": mapped_att,
                    },
                )
            )

        logger.info(f"Built {len(drafts)} D3FEND defensive documents.")
        return drafts

    def build_feed_advisory_documents(self) -> List[RagDocumentDraft]:
        feeds = self.db.query(ThreatFeed).all()
        drafts = []

        for feed in feeds:
            content = (
                f"Threat Intelligence Bulletin: {feed.bulletin_id}\n"
                f"Publisher / Source: {feed.source}\n"
                f"Published: {feed.published_at.strftime('%Y-%m-%d %H:%M UTC') if feed.published_at else 'Recent'}\n"
                f"Severity: {feed.severity}\n"
                f"Title: {feed.title}\n"
                f"Related ATT&CK TTPs: {', '.join(feed.related_ttps or [])}\n"
                f"Advisory Description & Narrative:\n{feed.content or feed.description}\n"
                f"Source Reference: {feed.url or 'Internal CTI Feed'}"
            )

            drafts.append(
                RagDocumentDraft(
                    chunk_id=f"feed-{feed.bulletin_id}",
                    source_kind="feed",
                    document_type="advisory",
                    source_object_id=feed.bulletin_id,
                    external_id=feed.bulletin_id,
                    title=f"CTI Bulletin: {feed.bulletin_id} ({feed.source})",
                    content=content,
                    url=feed.url,
                    metadata={
                        "bulletin_id": feed.bulletin_id,
                        "source": feed.source,
                        "severity": feed.severity,
                        "related_ttps": feed.related_ttps,
                    },
                )
            )

        logger.info(f"Built {len(drafts)} threat feed documents.")
        return drafts

    def build_all_knowledge_documents(self, identity_only_techniques: bool = False) -> List[RagDocumentDraft]:
        """Aggregate all semantic RAG documents across ATT&CK, D3FEND, and CTI feeds."""
        all_drafts = []
        all_drafts.extend(self.build_attack_technique_documents(identity_only=identity_only_techniques))
        all_drafts.extend(self.build_attack_procedure_documents())
        all_drafts.extend(self.build_d3fend_defensive_documents())
        all_drafts.extend(self.build_feed_advisory_documents())
        logger.info(f"Total knowledge documents compiled for RAG: {len(all_drafts)}")
        return all_drafts
