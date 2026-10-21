import json
import logging
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.attack import (
    StixObject,
    AttackTactic,
    AttackTechnique,
    AttackSoftware,
    TechniqueProcedure,
    technique_tactic_map,
)

logger = logging.getLogger(__name__)

IDENTITY_KEYWORDS = {
    "account", "credential", "password", "kerberos", "token", "ticket",
    "oauth", "saml", "mfa", "authentication", "privilege", "identity",
    "certificate", "session", "ldap", "domain", "active directory",
    "azure ad", "entra", "brute force", "user", "group", "access key",
    "impersonat", "forged ticket", "golden ticket", "silver ticket",
    "pass the hash", "pass the ticket", "okta", "iam"
}

IDENTITY_TACTICS = {"credential-access", "initial-access", "persistence", "privilege-escalation"}


def evaluate_identity_relevance(name: str, description: Optional[str], platforms: List[str], tactic_names: List[str]) -> bool:
    """Determine if an ATT&CK technique has direct identity-plane relevance."""
    text_corpus = f"{name} {description or ''}".lower()
    
    # Check platforms
    for plat in platforms:
        if any(p in plat.lower() for p in ["azure ad", "active directory", "saas", "office 365", "google workspace", "identity"]):
            return True

    # Check for direct identity keywords
    for kw in IDENTITY_KEYWORDS:
        if kw in text_corpus:
            return True

    return False


class AttackIngestionService:
    """
    Ingests official MITRE ATT&CK Enterprise STIX 2.1 bundles into normalized
    relational entities with idempotent upserts and audit metadata.
    """

    def __init__(self, db: Session):
        self.db = db

    def ingest_from_file(self, file_path: str, limit_stix_raw: int = 5000) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK file not found at {file_path}")

        logger.info(f"Loading ATT&CK STIX 2.1 bundle from {file_path}...")
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        return self.ingest_bundle(bundle, limit_stix_raw=limit_stix_raw)

    def ingest_bundle(self, bundle: Dict[str, Any], limit_stix_raw: int = 5000) -> Dict[str, Any]:
        if bundle.get("type") != "bundle" or "objects" not in bundle:
            raise ValueError("Invalid STIX 2.1 bundle: missing 'bundle' type or 'objects' array")

        objects = bundle["objects"]
        stats = {
            "total_stix_objects": len(objects),
            "tactics_created": 0,
            "tactics_updated": 0,
            "techniques_created": 0,
            "techniques_updated": 0,
            "software_created": 0,
            "software_updated": 0,
            "procedures_created": 0,
            "stix_raw_stored": 0,
        }

        # 1. Store StixObject audit records (limited to prevent gigantic raw storage if needed)
        stix_raw_batch = []
        for obj in objects[:limit_stix_raw]:
            stix_id = obj.get("id")
            if not stix_id:
                continue
            existing = self.db.query(StixObject).filter_by(stix_id=stix_id).first()
            if not existing:
                stix_obj = StixObject(
                    stix_id=stix_id,
                    object_type=obj.get("type", "unknown"),
                    spec_version=obj.get("spec_version", "2.1"),
                    revoked=obj.get("revoked", False),
                    deprecated=obj.get("x_mitre_deprecated", False),
                    raw_stix=obj,
                )
                stix_raw_batch.append(stix_obj)
        if stix_raw_batch:
            self.db.bulk_save_objects(stix_raw_batch)
            self.db.commit()
            stats["stix_raw_stored"] = len(stix_raw_batch)

        # 2. Ingest Tactics (x-mitre-tactic)
        tactic_map_by_shortname: Dict[str, AttackTactic] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                stix_id = obj["id"]
                short_name = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                desc = obj.get("description", "")
                ext_id = "TA0000"
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", ext_id)

                tactic = self.db.query(AttackTactic).filter_by(external_id=ext_id).first()
                if tactic:
                    tactic.stix_id = stix_id
                    tactic.name = name
                    tactic.short_name = short_name
                    tactic.description = desc
                    stats["tactics_updated"] += 1
                else:
                    tactic = AttackTactic(
                        stix_id=stix_id,
                        external_id=ext_id,
                        name=name,
                        short_name=short_name,
                        description=desc,
                    )
                    self.db.add(tactic)
                    stats["tactics_created"] += 1
                self.db.flush()
                tactic_map_by_shortname[short_name] = tactic

        self.db.commit()

        # 3. Ingest Software & Adversary Groups (intrusion-set, malware, tool)
        software_by_stix_id: Dict[str, AttackSoftware] = {}
        for obj in objects:
            obj_type = obj.get("type")
            if obj_type in ("intrusion-set", "malware", "tool"):
                stix_id = obj["id"]
                name = obj.get("name", "")
                desc = obj.get("description", "")
                aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])
                ext_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id")

                soft = self.db.query(AttackSoftware).filter_by(stix_id=stix_id).first()
                if soft:
                    soft.name = name
                    soft.description = desc
                    soft.software_type = obj_type
                    soft.external_id = ext_id
                    soft.aliases = aliases
                    stats["software_updated"] += 1
                else:
                    soft = AttackSoftware(
                        stix_id=stix_id,
                        external_id=ext_id,
                        name=name,
                        software_type=obj_type,
                        description=desc,
                        aliases=aliases,
                    )
                    self.db.add(soft)
                    stats["software_created"] += 1
                self.db.flush()
                software_by_stix_id[stix_id] = soft

        self.db.commit()

        # 4. Ingest Techniques & Sub-techniques (attack-pattern)
        technique_by_stix_id: Dict[str, AttackTechnique] = {}
        technique_tactics_to_link: List[tuple] = []  # (technique_id, tactic_id)

        for obj in objects:
            if obj.get("type") == "attack-pattern":
                stix_id = obj["id"]
                name = obj.get("name", "")
                desc = obj.get("description", "")
                is_sub = obj.get("x_mitre_is_subtechnique", False)
                platforms = obj.get("x_mitre_platforms", [])
                revoked = obj.get("revoked", False)
                deprecated = obj.get("x_mitre_deprecated", False)

                ext_id = "T0000"
                url = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", ext_id)
                        url = ref.get("url")

                parent_id = None
                if is_sub and "." in ext_id:
                    parent_id = ext_id.split(".")[0]

                phases = [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]

                is_identity = evaluate_identity_relevance(name, desc, platforms, phases)

                tech = self.db.query(AttackTechnique).filter_by(technique_id=ext_id).first()
                if tech:
                    tech.stix_id = stix_id
                    tech.name = name
                    tech.description = desc
                    tech.url = url
                    tech.is_subtechnique = is_sub
                    tech.parent_technique_id = parent_id
                    tech.platforms = platforms
                    tech.is_identity_relevant = is_identity
                    tech.revoked = revoked
                    tech.deprecated = deprecated
                    stats["techniques_updated"] += 1
                else:
                    tech = AttackTechnique(
                        stix_id=stix_id,
                        technique_id=ext_id,
                        name=name,
                        description=desc,
                        url=url,
                        is_subtechnique=is_sub,
                        parent_technique_id=parent_id,
                        platforms=platforms,
                        is_identity_relevant=is_identity,
                        revoked=revoked,
                        deprecated=deprecated,
                    )
                    self.db.add(tech)
                    stats["techniques_created"] += 1

                self.db.flush()
                technique_by_stix_id[stix_id] = tech

                # Associate with tactics
                for phase in phases:
                    if phase in tactic_map_by_shortname:
                        technique_tactics_to_link.append((tech.id, tactic_map_by_shortname[phase].id))

        self.db.commit()

        # Link technique_tactic_map
        for tech_id, tac_id in set(technique_tactics_to_link):
            exists = self.db.execute(
                technique_tactic_map.select().where(
                    (technique_tactic_map.c.technique_id == tech_id) &
                    (technique_tactic_map.c.tactic_id == tac_id)
                )
            ).first()
            if not exists:
                self.db.execute(
                    technique_tactic_map.insert().values(technique_id=tech_id, tactic_id=tac_id)
                )
        self.db.commit()

        # 5. Ingest Procedures (relationship where relationship_type == 'uses' and target is attack-pattern)
        procedure_batch = []
        for obj in objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                rel_id = obj["id"]
                target_ref = obj.get("target_ref")
                source_ref = obj.get("source_ref")
                desc = obj.get("description", "")

                if not desc or not target_ref or target_ref not in technique_by_stix_id:
                    continue

                tech = technique_by_stix_id[target_ref]
                software = software_by_stix_id.get(source_ref)

                existing = self.db.query(TechniqueProcedure).filter_by(relationship_id=rel_id).first()
                if not existing:
                    proc = TechniqueProcedure(
                        relationship_id=rel_id,
                        technique_id=tech.id,
                        source_software_id=software.id if software else None,
                        source_name=software.name if software else (source_ref.split("--")[0] if source_ref else None),
                        description=desc,
                        external_references=obj.get("external_references", []),
                    )
                    procedure_batch.append(proc)

                if len(procedure_batch) >= 500:
                    self.db.bulk_save_objects(procedure_batch)
                    self.db.commit()
                    stats["procedures_created"] += len(procedure_batch)
                    procedure_batch = []

        if procedure_batch:
            self.db.bulk_save_objects(procedure_batch)
            self.db.commit()
            stats["procedures_created"] += len(procedure_batch)

        logger.info(f"ATT&CK Ingestion complete: {stats}")
        return stats
