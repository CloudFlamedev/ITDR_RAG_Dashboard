import re
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.attack import AttackTechnique
from app.models.d3fend import D3fendTechnique, AttackDefenceMapping
from app.models.rag import RagDocument
from app.services.vector_store_service import VectorStoreService
from app.services.rerank_service import RerankService

logger = logging.getLogger(__name__)

ATTACK_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
D3FEND_ID_PATTERN = re.compile(r"\b(D3(?:A)?-[A-Z0-9]+)\b", re.IGNORECASE)


class CandidateTechnique:
    def __init__(
        self,
        technique_id: str,
        name: str,
        score: float,
        is_exact_match: bool,
        tactics: List[str],
        url: Optional[str],
        description: str,
        evidence_snippets: List[Dict[str, Any]],
    ):
        self.technique_id = technique_id
        self.name = name
        self.score = score
        self.is_exact_match = is_exact_match
        self.tactics = tactics
        self.url = url
        self.description = description
        self.evidence_snippets = evidence_snippets

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "similarity_score": round(self.score, 4),
            "is_exact_match": self.is_exact_match,
            "tactics": self.tactics,
            "url": self.url,
            "description": self.description,
            "evidence_snippets": self.evidence_snippets,
        }


class RetrievalService:
    """
    Hybrid RAG retrieval engine combining:
    - Rule-based regex extraction of explicit ATT&CK/D3FEND indicators
    - Exact-ID boost
    - Semantic vector similarity search over ATT&CK techniques, procedures, and CTI feeds
    - Authentic D3FEND defensive mapping resolution
    - Deduplication, technique-level evidence aggregation, and confidence gating.
    """

    def __init__(
        self,
        db: Session,
        vector_store: Optional[VectorStoreService] = None,
        rerank_service: Optional[RerankService] = None,
    ):
        self.db = db
        self.vector_store = vector_store or (VectorStoreService(db) if db else None)
        self.rerank_service = rerank_service or RerankService()

    def extract_explicit_entities(self, text: str) -> Dict[str, List[str]]:
        """Safely extract explicit MITRE ATT&CK and D3FEND identifiers from user text."""
        raw_attack_ids = [m.upper() for m in ATTACK_ID_PATTERN.findall(text)]
        raw_d3fend_ids = [m.upper() for m in D3FEND_ID_PATTERN.findall(text)]

        return {
            "attack_ids": sorted(list(set(raw_attack_ids))),
            "d3fend_ids": sorted(list(set(raw_d3fend_ids))),
        }

    def retrieve(
        self,
        advisory_text: str,
        max_candidates: int = 8,
        include_d3fend: bool = True,
        min_similarity_threshold: float = 0.20,
    ) -> Dict[str, Any]:
        """
        Execute full hybrid retrieval pipeline.
        Returns candidate ATT&CK techniques with grounded evidence and relevant D3FEND countermeasures.
        """
        extracted = self.extract_explicit_entities(advisory_text)
        explicit_attack_ids = extracted["attack_ids"]
        explicit_d3fend_ids = extracted["d3fend_ids"]

        candidates_by_id: Dict[str, CandidateTechnique] = {}

        # 1. Exact-ID Lookup Boost
        if self.db:
            for att_id in explicit_attack_ids:
                tech = self.db.query(AttackTechnique).filter(
                    (AttackTechnique.technique_id == att_id) |
                    (AttackTechnique.technique_id.like(f"{att_id}%"))
                ).first()

                if tech:
                    tactics = [t.name for t in tech.tactics]
                    candidates_by_id[tech.technique_id] = CandidateTechnique(
                        technique_id=tech.technique_id,
                        name=tech.name,
                        score=1.0,
                        is_exact_match=True,
                        tactics=tactics,
                        url=tech.url or f"https://attack.mitre.org/techniques/{tech.technique_id}",
                        description=tech.description or "",
                        evidence_snippets=[{
                            "source_id": f"att-tech-{tech.technique_id}",
                            "title": f"Explicit indicator matched in submitted advisory: {tech.technique_id}",
                            "excerpt": f"Advisory explicitly mentions {tech.technique_id}. {tech.description[:250]}...",
                            "score": 1.0,
                            "url": tech.url,
                        }]
                    )
        else:
            # Fallback for offline testing or without database session
            for att_id in explicit_attack_ids:
                candidates_by_id[att_id] = CandidateTechnique(
                    technique_id=att_id,
                    name=f"Technique {att_id}",
                    score=1.0,
                    is_exact_match=True,
                    tactics=["Initial Access"],
                    url=f"https://attack.mitre.org/techniques/{att_id}",
                    description=f"Offline indicator match for {att_id}",
                    evidence_snippets=[{
                        "source_id": f"att-tech-{att_id}",
                        "title": f"Explicit indicator matched: {att_id}",
                        "excerpt": f"Advisory explicitly mentions {att_id}.",
                        "score": 1.0,
                        "url": None,
                    }]
                )

        # 2. Semantic Vector Similarity Search for ATT&CK Techniques & Procedures
        vector_results = []
        if self.vector_store and self.db:
            vector_results = self.vector_store.similarity_search(
                query=advisory_text,
                top_k=max_candidates * 3,
                source_kind="attack",
            )

        for doc, score in vector_results:
            tech_id = doc.external_id
            tech_rec = self.db.query(AttackTechnique).filter_by(technique_id=tech_id).first()
            if not tech_rec:
                continue

            tactics = [t.name for t in tech_rec.tactics]

            if tech_id not in candidates_by_id:
                candidates_by_id[tech_id] = CandidateTechnique(
                    technique_id=tech_id,
                    name=tech_rec.name,
                    score=score,
                    is_exact_match=False,
                    tactics=tactics,
                    url=tech_rec.url or f"https://attack.mitre.org/techniques/{tech_id}",
                    description=tech_rec.description or "",
                    evidence_snippets=[],
                )
            else:
                # Update score if higher
                candidates_by_id[tech_id].score = max(candidates_by_id[tech_id].score, score)

            # Append evidence snippet
            if len(candidates_by_id[tech_id].evidence_snippets) < 3:
                candidates_by_id[tech_id].evidence_snippets.append({
                    "source_id": doc.chunk_id,
                    "title": doc.title,
                    "excerpt": doc.content[:300] + "...",
                    "score": score,
                    "url": doc.url,
                })

        # 3. Cross-Encoder Reranking
        # Re-score candidates using Jina AI's multilingual cross-encoder reranker
        raw_candidates = list(candidates_by_id.values())
        ranked_candidates, rerank_meta = self.rerank_service.rerank_candidates(
            query=advisory_text,
            candidates=raw_candidates,
            top_n=max_candidates,
        )

        # 4. Retrieve D3FEND Defensive Knowledge
        defensive_countermeasures = []
        if include_d3fend:
            defensive_countermeasures = self._retrieve_d3fend_countermeasures(
                query_text=advisory_text,
                candidate_technique_ids=[c.technique_id for c in ranked_candidates],
                explicit_d3fend_ids=explicit_d3fend_ids,
            )

        # 5. Check confidence / sufficiency
        highest_score = ranked_candidates[0].score if ranked_candidates else 0.0
        insufficient_evidence = (highest_score < min_similarity_threshold and not explicit_attack_ids)

        return {
            "query_summary": advisory_text[:150] + ("..." if len(advisory_text) > 150 else ""),
            "explicit_indicators": extracted,
            "candidate_count": len(ranked_candidates),
            "candidates": [c.to_dict() for c in ranked_candidates],
            "defensive_countermeasures": defensive_countermeasures,
            "insufficient_evidence": insufficient_evidence,
            "highest_confidence": round(highest_score, 4),
            "rerank_applied": rerank_meta.get("rerank_performed", False),
            "rerank_model": rerank_meta.get("rerank_model"),
            "rerank_latency_ms": rerank_meta.get("duration_ms", 0.0),
        }

    def _retrieve_d3fend_countermeasures(
        self,
        query_text: str,
        candidate_technique_ids: List[str],
        explicit_d3fend_ids: List[str],
    ) -> List[Dict[str, Any]]:
        if not self.db:
            return []

        countermeasures = []
        seen_d3f_ids = set()

        # A. Exact MITRE D3FEND mappings for the candidate techniques
        for att_id in candidate_technique_ids:
            mappings = self.db.query(AttackDefenceMapping).filter(
                (AttackDefenceMapping.attack_technique_external_id == att_id) |
                (AttackDefenceMapping.attack_technique_external_id == att_id.split(".")[0])
            ).all()

            for m in mappings:
                d3f = m.d3fend_technique
                if d3f.d3fend_id not in seen_d3f_ids:
                    seen_d3f_ids.add(d3f.d3fend_id)
                    countermeasures.append({
                        "d3fend_id": d3f.d3fend_id,
                        "name": d3f.name,
                        "relationship_type": m.relationship_type,
                        "provenance": m.mapping_source,
                        "provenance_url": m.provenance_url,
                        "definition": d3f.definition or "",
                        "url": d3f.url,
                        "matched_via": f"Official mapping to {att_id}",
                    })

        # B. Semantic vector search over D3FEND documents
        d3f_vector_results = self.vector_store.similarity_search(
            query=query_text,
            top_k=5,
            source_kind="d3fend",
            min_score=0.15,
        )

        for doc, score in d3f_vector_results:
            d3f_id = doc.external_id
            if d3f_id not in seen_d3f_ids:
                seen_d3f_ids.add(d3f_id)
                countermeasures.append({
                    "d3fend_id": d3f_id,
                    "name": doc.title.split(": ")[-1] if ": " in doc.title else doc.title,
                    "relationship_type": "recommended countermeasure",
                    "provenance": "Semantic RAG match",
                    "provenance_url": doc.url,
                    "definition": doc.content[:250] + "...",
                    "url": doc.url,
                    "matched_via": f"Semantic similarity ({round(score, 3)})",
                })

        return countermeasures[:8]
