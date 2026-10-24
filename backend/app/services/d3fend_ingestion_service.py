import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.d3fend import D3fendTechnique, AttackDefenceMapping
from app.models.attack import AttackTechnique

logger = logging.getLogger(__name__)


class D3fendIngestionService:
    """
    Ingests official MITRE D3FEND ontology JSON knowledge graph into normalized
    relational models and maps authentic offensive-to-defensive relationships.
    Optimized for batch operations and remote database latency minimization.
    """

    def __init__(self, db: Session):
        self.db = db

    def ingest_from_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"MITRE D3FEND file not found at {file_path}")

        logger.info(f"Loading MITRE D3FEND ontology from {file_path}...")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return self.ingest_data(data)

    def ingest_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(data, dict) or "@graph" not in data:
            raise ValueError("Invalid D3FEND ontology: missing '@graph' array")

        graph = data["@graph"]
        stats = {
            "total_graph_nodes": len(graph),
            "defensive_techniques_created": 0,
            "defensive_techniques_updated": 0,
            "attack_defence_mappings_created": 0,
        }

        # 1. Parse restrictions first to extract relation triples from blank nodes
        restrictions: Dict[str, tuple] = {}
        for item in graph:
            if item.get("@type") == "owl:Restriction":
                prop = item.get("owl:onProperty", {}).get("@id") if isinstance(item.get("owl:onProperty"), dict) else item.get("owl:onProperty")
                val = item.get("owl:someValuesFrom", {}).get("@id") if isinstance(item.get("owl:someValuesFrom"), dict) else item.get("owl:someValuesFrom")
                if prop and val:
                    restrictions[item.get("@id")] = (str(prop), str(val))

        # 2. Extract defensive techniques (nodes with d3f:d3fend-id)
        candidate_mappings: List[tuple] = []
        existing_d3f = {t.d3fend_id: t for t in self.db.query(D3fendTechnique).all()}

        for item in graph:
            d3f_id = item.get("d3f:d3fend-id")
            if not d3f_id:
                continue

            name = item.get("rdfs:label", d3f_id)
            definition = item.get("d3f:definition") or item.get("d3f:kb-abstract")
            taxonomy = None
            parent_id = None

            sub_classes = item.get("rdfs:subClassOf")
            subs = sub_classes if isinstance(sub_classes, list) else ([sub_classes] if sub_classes else [])
            for sub in subs:
                if isinstance(sub, dict) and "@id" in sub:
                    sub_id = sub["@id"]
                    if not sub_id.startswith("_:"):
                        taxonomy = sub_id.replace("d3f:", "")
                        parent_id = taxonomy

                    if sub_id in restrictions:
                        prop, val = restrictions[sub_id]
                        clean_prop = prop.replace("d3f:", "")
                        clean_val = val.replace("d3f:", "")
                        if clean_val.startswith("T1"):
                            candidate_mappings.append((
                                d3f_id,
                                clean_val,
                                clean_prop,
                                f"https://d3fend.mitre.org/technique/{d3f_id}"
                            ))

            for k, v in item.items():
                if k.startswith("d3f:") and any(term in k for term in ["restricts", "counters", "mitigates", "detects", "isolates", "verifies"]):
                    rel_name = k.replace("d3f:", "")
                    targets = v if isinstance(v, list) else [v]
                    for tgt in targets:
                        if isinstance(tgt, dict) and "@id" in tgt:
                            tgt_id = tgt["@id"].replace("d3f:", "")
                            if tgt_id.startswith("T1"):
                                candidate_mappings.append((
                                    d3f_id,
                                    tgt_id,
                                    rel_name,
                                    f"https://d3fend.mitre.org/technique/{d3f_id}"
                                ))

            url = f"https://d3fend.mitre.org/technique/{d3f_id}"
            
            if d3f_id in existing_d3f:
                d3f_rec = existing_d3f[d3f_id]
                d3f_rec.name = name
                d3f_rec.definition = definition
                d3f_rec.url = url
                d3f_rec.taxonomy_path = taxonomy
                d3f_rec.parent_id = parent_id
                stats["defensive_techniques_updated"] += 1
            else:
                d3f_rec = D3fendTechnique(
                    d3fend_id=d3f_id,
                    name=name,
                    definition=definition,
                    url=url,
                    taxonomy_path=taxonomy,
                    parent_id=parent_id,
                    raw_metadata=item,
                )
                self.db.add(d3f_rec)
                existing_d3f[d3f_id] = d3f_rec
                stats["defensive_techniques_created"] += 1

        self.db.commit()

        # 3. Batch Insert AttackDefenceMappings
        att_techniques_by_ext_id = {t.technique_id: t for t in self.db.query(AttackTechnique).all()}
        existing_map_keys = {
            (m.attack_technique_external_id, m.d3fend_external_id)
            for m in self.db.query(AttackDefenceMapping.attack_technique_external_id, AttackDefenceMapping.d3fend_external_id).all()
        }

        mappings_to_create = []
        for d3f_id, att_ext_id, rel_type, prov_url in set(candidate_mappings):
            if att_ext_id not in att_techniques_by_ext_id or d3f_id not in existing_d3f:
                continue

            pair = (att_ext_id, d3f_id)
            if pair in existing_map_keys:
                continue

            att_tech = att_techniques_by_ext_id[att_ext_id]
            d3f_obj = existing_d3f[d3f_id]

            adm = AttackDefenceMapping(
                attack_technique_id=att_tech.id,
                attack_technique_external_id=att_ext_id,
                d3fend_technique_id=d3f_obj.id,
                d3fend_external_id=d3f_id,
                relationship_type=rel_type,
                provenance_url=prov_url,
                mapping_source="MITRE D3FEND Ontology",
            )
            mappings_to_create.append(adm)
            existing_map_keys.add(pair)

        if mappings_to_create:
            self.db.bulk_save_objects(mappings_to_create)
            self.db.commit()

        stats["attack_defence_mappings_created"] = len(mappings_to_create)
        logger.info(f"D3FEND Ingestion complete: {stats}")
        return stats
