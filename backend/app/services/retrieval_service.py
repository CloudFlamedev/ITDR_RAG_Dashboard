import re
import logging
import threading
from typing import List, Dict, Any, Optional
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload, joinedload
from app.models.attack import AttackTechnique
from app.models.d3fend import D3fendTechnique, AttackDefenceMapping
from app.models.rag import RagDocument
from app.services.vector_store_service import VectorStoreService
from app.services.rerank_service import RerankService
from app.core.telemetry import observe, langfuse_client, mask_sensitive_data
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

ATTACK_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
D3FEND_ID_PATTERN = re.compile(r"\b(D3(?:A)?-[A-Z0-9]+)\b", re.IGNORECASE)

# In-memory fast cache for static MITRE ATT&CK taxonomy
_tech_cache_lock = threading.Lock()
_TECH_TAXONOMY_CACHE: Dict[str, Dict[str, Any]] = {}


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
        vector_score: Optional[float] = None,
        rerank_score: Optional[float] = None,
    ):
        self.technique_id = technique_id
        self.name = name
        self.vector_score = vector_score if vector_score is not None else score
        self.rerank_score = rerank_score
        self.score = self.vector_score  # score is strictly alias for vector_score, never rerank_score
        self.is_exact_match = is_exact_match
        self.tactics = tactics
        self.url = url
        self.description = description
        self.evidence_snippets = evidence_snippets

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "similarity_score": round(self.vector_score, 4),
            "vector_score": round(self.vector_score, 4),
            "rerank_score": round(self.rerank_score, 4) if self.rerank_score is not None else None,
            "is_exact_match": self.is_exact_match,
            "tactics": self.tactics,
            "url": self.url,
            "description": self.description,
            "evidence_snippets": self.evidence_snippets,
        }


def prewarm_taxonomy_cache(db: Session) -> int:
    """Pre-warm in-memory ATT&CK taxonomy cache at application startup or on demand."""
    global _TECH_TAXONOMY_CACHE
    with _tech_cache_lock:
        if not _TECH_TAXONOMY_CACHE and db:
            try:
                techs = (
                    db.query(AttackTechnique)
                    .options(selectinload(AttackTechnique.tactics))
                    .all()
                )
                for t in techs:
                    _TECH_TAXONOMY_CACHE[t.technique_id] = {
                        "id": t.id,
                        "technique_id": t.technique_id,
                        "name": t.name,
                        "tactics": [tac.name for tac in t.tactics],
                        "url": t.url,
                        "description": t.description or "",
                    }
                logger.info(f"Pre-warmed ATT&CK taxonomy cache with {len(_TECH_TAXONOMY_CACHE)} techniques.")
            except Exception as e:
                logger.warning(f"Failed to pre-warm ATT&CK taxonomy cache: {e}")
    return len(_TECH_TAXONOMY_CACHE)


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
        self.rerank_service = rerank_service or RerankService(timeout=4)

    def extract_explicit_entities(self, text: str) -> Dict[str, List[str]]:
        """Safely extract explicit MITRE ATT&CK and D3FEND identifiers from user text."""
        raw_attack_ids = [m.upper() for m in ATTACK_ID_PATTERN.findall(text)]
        raw_d3fend_ids = [m.upper() for m in D3FEND_ID_PATTERN.findall(text)]

        return {
            "attack_ids": sorted(list(set(raw_attack_ids))),
            "d3fend_ids": sorted(list(set(raw_d3fend_ids))),
        }

    def _get_technique_dict(self, tech_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve technique from fast in-memory taxonomy cache, pre-warming on first access."""
        global _TECH_TAXONOMY_CACHE
        if not _TECH_TAXONOMY_CACHE and self.db:
            prewarm_taxonomy_cache(self.db)

        entry = _TECH_TAXONOMY_CACHE.get(tech_id)
        if not entry and "." in tech_id:
            entry = _TECH_TAXONOMY_CACHE.get(tech_id.split(".")[0])

        if not entry and self.db:
            try:
                t = (
                    self.db.query(AttackTechnique)
                    .options(selectinload(AttackTechnique.tactics))
                    .filter(AttackTechnique.technique_id == tech_id)
                    .first()
                )
                if not t and "." in tech_id:
                    t = (
                        self.db.query(AttackTechnique)
                        .options(selectinload(AttackTechnique.tactics))
                        .filter(AttackTechnique.technique_id == tech_id.split(".")[0])
                        .first()
                    )
                if t:
                    entry = {
                        "id": t.id,
                        "technique_id": t.technique_id,
                        "name": t.name,
                        "tactics": [tac.name for tac in t.tactics],
                        "url": t.url,
                        "description": t.description or "",
                    }
                    with _tech_cache_lock:
                        _TECH_TAXONOMY_CACHE[t.technique_id] = entry
            except Exception as e:
                logger.debug(f"Direct DB technique lookup failed: {e}")

        return entry

    @observe(as_type="span", name="hybrid_retrieval_pipeline")
    def retrieve(
        self,
        advisory_text: str,
        max_candidates: int = 8,
        include_d3fend: bool = True,
        min_similarity_threshold: Optional[float] = None,
        min_rerank_threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Execute full hybrid retrieval pipeline.
        Returns candidate ATT&CK techniques with grounded evidence and relevant D3FEND countermeasures.
        """
        effective_min_sim = (
            min_similarity_threshold
            if min_similarity_threshold is not None
            else settings.RETRIEVAL_MIN_SIMILARITY_THRESHOLD
        )
        effective_min_rerank = (
            min_rerank_threshold
            if min_rerank_threshold is not None
            else settings.RETRIEVAL_MIN_RERANK_THRESHOLD
        )

        extracted = self.extract_explicit_entities(advisory_text)
        explicit_attack_ids = extracted["attack_ids"]
        explicit_d3fend_ids = extracted["d3fend_ids"]

        candidates_by_id: Dict[str, CandidateTechnique] = {}

        # 1. Exact-ID Lookup Boost (from in-memory taxonomy cache)
        for att_id in explicit_attack_ids:
            tech = self._get_technique_dict(att_id)
            if tech:
                candidates_by_id[tech["technique_id"]] = CandidateTechnique(
                    technique_id=tech["technique_id"],
                    name=tech["name"],
                    score=1.0,
                    is_exact_match=True,
                    tactics=tech["tactics"],
                    url=tech["url"] or f"https://attack.mitre.org/techniques/{tech['technique_id']}",
                    description=tech["description"],
                    evidence_snippets=[{
                        "source_id": f"att-tech-{tech['technique_id']}",
                        "title": f"Explicit indicator matched in submitted advisory: {tech['technique_id']}",
                        "excerpt": f"Advisory explicitly mentions {tech['technique_id']}. {tech['description'][:250]}...",
                        "score": 1.0,
                        "url": tech["url"],
                    }]
                )
            else:
                candidates_by_id[att_id] = CandidateTechnique(
                    technique_id=att_id,
                    name=f"Technique {att_id}",
                    score=1.0,
                    is_exact_match=True,
                    tactics=["Initial Access"],
                    url=f"https://attack.mitre.org/techniques/{att_id}",
                    description=f"Indicator match for {att_id}",
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
                min_score=effective_min_sim,
            )

        for doc, score in vector_results:
            if score < effective_min_sim:
                continue

            tech_id = doc.external_id
            tech_rec = self._get_technique_dict(tech_id)
            if not tech_rec:
                continue

            tactics = tech_rec["tactics"]

            if tech_id not in candidates_by_id:
                candidates_by_id[tech_id] = CandidateTechnique(
                    technique_id=tech_id,
                    name=tech_rec["name"],
                    score=score,
                    is_exact_match=False,
                    tactics=tactics,
                    url=tech_rec["url"] or f"https://attack.mitre.org/techniques/{tech_id}",
                    description=tech_rec["description"],
                    evidence_snippets=[],
                )
            else:
                # Update score if higher
                candidates_by_id[tech_id].score = max(candidates_by_id[tech_id].score, score)
                candidates_by_id[tech_id].vector_score = max(candidates_by_id[tech_id].vector_score, score)

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
        raw_candidates = list(candidates_by_id.values())
        ranked_candidates, rerank_meta = self.rerank_service.rerank_candidates(
            query=advisory_text,
            candidates=raw_candidates,
            top_n=max_candidates,
        )

        if rerank_meta.get("rerank_performed"):
            filtered_ranked = []
            for c in ranked_candidates:
                if c.is_exact_match or (c.rerank_score is not None and c.rerank_score >= effective_min_rerank):
                    filtered_ranked.append(c)
            ranked_candidates = filtered_ranked

        # 4. Check confidence / sufficiency & preserve separate score types
        highest_vector_score = max((c.vector_score for c in raw_candidates), default=0.0)
        rerank_scores = [c.rerank_score for c in ranked_candidates if c.rerank_score is not None]
        highest_rerank_score = max(rerank_scores, default=None) if (rerank_meta.get("rerank_performed") and rerank_scores) else None

        if rerank_meta.get("rerank_performed") and highest_rerank_score is not None:
            highest_confidence = highest_rerank_score
        else:
            highest_confidence = highest_vector_score

        # Calibrated vector similarity score used for cosine-based evidence threshold
        # (CRITICAL: Never compare Jina cross-encoder relevance scores against cosine similarity threshold)
        insufficient_evidence = (highest_vector_score < effective_min_sim and not explicit_attack_ids)

        if insufficient_evidence:
            ranked_candidates = []

        # 5. Retrieve D3FEND Defensive Knowledge
        defensive_countermeasures = []
        if include_d3fend and not insufficient_evidence:
            defensive_countermeasures = self._retrieve_d3fend_countermeasures(
                query_text=advisory_text,
                candidate_technique_ids=[c.technique_id for c in ranked_candidates],
                explicit_d3fend_ids=explicit_d3fend_ids,
            )
        elif include_d3fend and explicit_d3fend_ids:
            defensive_countermeasures = self._retrieve_d3fend_countermeasures(
                query_text=advisory_text,
                candidate_technique_ids=[],
                explicit_d3fend_ids=explicit_d3fend_ids,
            )

        # Vector score distribution metrics for drift detection
        vector_scores = [c.vector_score for c in ranked_candidates]
        avg_vector_score = round(sum(vector_scores) / max(len(vector_scores), 1), 4)

        try:
            langfuse_client.update_current_span(
                input={
                    "advisory_text": mask_sensitive_data(advisory_text[:500]),
                    "max_candidates": max_candidates,
                    "include_d3fend": include_d3fend,
                    "min_similarity_threshold": effective_min_sim,
                    "min_rerank_threshold": effective_min_rerank,
                    "query_type": "explicit_id" if explicit_attack_ids else "natural_language",
                },
                output={
                    "explicit_attack_indicators": explicit_attack_ids,
                    "candidate_techniques_count": len(ranked_candidates),
                    "d3fend_countermeasures_count": len(defensive_countermeasures),
                    "highest_vector_similarity": round(highest_vector_score, 4),
                    "highest_rerank_score": round(highest_rerank_score, 4) if highest_rerank_score is not None else None,
                    "highest_confidence": round(highest_confidence, 4),
                    "avg_vector_score": avg_vector_score,
                    "insufficient_evidence": insufficient_evidence,
                },
                metadata={
                    "rerank_applied": rerank_meta.get("rerank_performed", False),
                    "rerank_model": rerank_meta.get("rerank_model"),
                    "rerank_latency_ms": rerank_meta.get("duration_ms", 0.0),
                    "embedding_model": "BAAI/bge-m3",
                }
            )
        except Exception as e:
            logger.debug(f"Langfuse hybrid retrieval span update skipped: {e}")

        return {
            "query_summary": advisory_text[:150] + ("..." if len(advisory_text) > 150 else ""),
            "explicit_indicators": extracted,
            "candidate_count": len(ranked_candidates),
            "candidates": [c.to_dict() for c in ranked_candidates],
            "defensive_countermeasures": defensive_countermeasures,
            "insufficient_evidence": insufficient_evidence,
            "highest_confidence": round(highest_confidence, 4),
            "highest_vector_similarity": round(highest_vector_score, 4),
            "highest_rerank_score": round(highest_rerank_score, 4) if highest_rerank_score is not None else None,
            "has_explicit_attack_id": bool(explicit_attack_ids),
            "rerank_applied": rerank_meta.get("rerank_performed", False),
            "rerank_model": rerank_meta.get("rerank_model"),
            "rerank_latency_ms": rerank_meta.get("duration_ms", 0.0),
        }

    def _retrieve_d3fend_countermeasures(
        self,
        query_text: str,
        candidate_technique_ids: List[str],
        explicit_d3fend_ids: List[str],
        min_d3fend_score: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        if not self.db:
            return []

        # If no identified attack techniques and no explicit D3FEND indicator,
        # there is no defensive context to retrieve.
        if not candidate_technique_ids and not explicit_d3fend_ids:
            return []

        effective_min_d3f = (
            min_d3fend_score
            if min_d3fend_score is not None
            else settings.RETRIEVAL_MIN_D3FEND_SCORE
        )

        countermeasures = []
        seen_d3f_ids = set()

        # A. Official & Inferred MITRE D3FEND mappings for candidate techniques
        all_att_ids = set()
        for att_id in candidate_technique_ids:
            all_att_ids.add(att_id)
            if "." in att_id:
                all_att_ids.add(att_id.split(".")[0])

        if all_att_ids:
            mappings = (
                self.db.query(AttackDefenceMapping)
                .options(joinedload(AttackDefenceMapping.d3fend_technique))
                .filter(AttackDefenceMapping.attack_technique_external_id.in_(all_att_ids))
                .all()
            )

            for m in mappings:
                d3f = m.d3fend_technique
                if d3f and d3f.d3fend_id not in seen_d3f_ids:
                    seen_d3f_ids.add(d3f.d3fend_id)
                    countermeasures.append({
                        "d3fend_id": d3f.d3fend_id,
                        "name": d3f.name,
                        "relationship_type": m.relationship_type,
                        "provenance": m.mapping_source or "MITRE D3FEND Ontology",
                        "provenance_url": m.provenance_url,
                        "definition": d3f.definition or "",
                        "url": d3f.url,
                        "matched_via": f"Official mapping to {m.attack_technique_external_id}",
                    })

        # B. Direct lookup for explicit D3FEND IDs mentioned in narrative
        if explicit_d3fend_ids:
            explicit_records = (
                self.db.query(D3fendTechnique)
                .filter(D3fendTechnique.d3fend_id.in_(explicit_d3fend_ids))
                .all()
            )
            for d3f in explicit_records:
                if d3f.d3fend_id not in seen_d3f_ids:
                    seen_d3f_ids.add(d3f.d3fend_id)
                    countermeasures.append({
                        "d3fend_id": d3f.d3fend_id,
                        "name": d3f.name,
                        "relationship_type": "explicit countermeasure indicator",
                        "provenance": "MITRE D3FEND Ontology",
                        "provenance_url": d3f.url,
                        "definition": d3f.definition or "",
                        "url": d3f.url,
                        "matched_via": "Explicit D3FEND indicator in advisory",
                    })

        # C. Concept & Keyword matching for identity threat domains
        if len(countermeasures) < 6 and candidate_technique_ids:
            lower_query = query_text.lower()
            key_concepts = [
                ("certificate", ["certificate", "ad cs", "esc1", "esc", "pki", "san"]),
                ("authentication", ["authentication", "mfa", "logon", "login", "sso"]),
                ("account", ["account", "active directory", "domain admin", "user account", "group"]),
                ("credential", ["credential", "password", "hash", "ntlm", "kerberos", "ticket", "token"]),
                ("session", ["session", "cookie", "token"]),
            ]
            active_terms = []
            for term, triggers in key_concepts:
                if any(trig in lower_query for trig in triggers):
                    active_terms.append(term)

            if active_terms:
                or_clauses = [D3fendTechnique.name.ilike(f"%{t}%") for t in active_terms]
                concept_matches = self.db.query(D3fendTechnique).filter(or_(*or_clauses)).limit(10).all()
                for d3f in concept_matches:
                    if d3f.d3fend_id not in seen_d3f_ids:
                        seen_d3f_ids.add(d3f.d3fend_id)
                        countermeasures.append({
                            "d3fend_id": d3f.d3fend_id,
                            "name": d3f.name,
                            "relationship_type": "identity defensive countermeasure",
                            "provenance": "MITRE D3FEND Ontology",
                            "provenance_url": d3f.url,
                            "definition": d3f.definition or "",
                            "url": d3f.url,
                            "matched_via": "Identity defense concept match",
                        })
                    if len(countermeasures) >= 6:
                        break

        # D. Semantic vector search over D3FEND documents
        if len(countermeasures) < 8 and self.vector_store and (candidate_technique_ids or explicit_d3fend_ids):
            d3f_vector_results = self.vector_store.similarity_search(
                query=query_text[:300],
                top_k=5,
                source_kind="d3fend",
                min_score=effective_min_d3f,
            )

            for doc, score in d3f_vector_results:
                if score < effective_min_d3f:
                    continue
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
                if len(countermeasures) >= 8:
                    break

        return countermeasures[:8]
