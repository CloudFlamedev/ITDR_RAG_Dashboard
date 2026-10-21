import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.attack import AttackTechnique, AttackTactic, TechniqueProcedure
from app.models.coverage import DetectionRule, DetectionRuleTechnique
from app.models.d3fend import AttackDefenceMapping

logger = logging.getLogger(__name__)


class CoverageService:
    """
    Computes real ITDR coverage metrics from database records.
    Evaluates rule mappings against MITRE ATT&CK techniques across tool toggles and scopes.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_coverage_matrix(
        self,
        view_scope: str = "identity",  # "identity" or "enterprise"
        status_filter: str = "all",    # "all", "covered", "uncovered"
        active_tools: Optional[List[str]] = None,
        client_restriction: str = "ALL",
        itdr_scope: str = "ITDR Scope Only",
    ) -> Dict[str, Any]:
        """
        Builds the complete columnar ATT&CK matrix and calculated KPIs.
        """
        # 1. Base Techniques Query
        tech_query = self.db.query(AttackTechnique).filter_by(revoked=False, deprecated=False)
        if view_scope == "identity" or itdr_scope == "ITDR Scope Only":
            tech_query = tech_query.filter(AttackTechnique.is_identity_relevant.is_(True))

        all_techniques = tech_query.all()
        total_in_scope = len(all_techniques)

        # 2. Rule Mappings Query
        rule_map_query = (
            self.db.query(DetectionRuleTechnique)
            .join(DetectionRule)
            .filter(DetectionRule.enabled.is_(True))
        )
        if active_tools:
            rule_map_query = rule_map_query.filter(DetectionRule.tool.in_(active_tools))
        if client_restriction != "ALL":
            rule_map_query = rule_map_query.filter(
                (DetectionRule.client_restriction == client_restriction) |
                (DetectionRule.client_restriction == "ALL")
            )

        rule_mappings = rule_map_query.all()

        # Map techniques to their protecting rules and tools
        rules_by_tech_id: Dict[str, List[DetectionRule]] = {}
        for rm in rule_mappings:
            tid = rm.technique_external_id
            rules_by_tech_id.setdefault(tid, []).append(rm.rule)
            # Also associate parent technique if sub-technique
            if "." in tid:
                parent_id = tid.split(".")[0]
                rules_by_tech_id.setdefault(parent_id, []).append(rm.rule)

        # 3. Categorize Techniques (Covered vs Exposed)
        covered_techniques_list = []
        exposed_techniques_list = []

        technique_cards_by_tactic: Dict[str, List[Dict[str, Any]]] = {}

        for tech in all_techniques:
            protecting_rules = rules_by_tech_id.get(tech.technique_id, [])
            is_covered = len(protecting_rules) > 0

            # Filter by status
            if status_filter == "covered" and not is_covered:
                continue
            if status_filter == "uncovered" and is_covered:
                continue

            card = {
                "id": tech.id,
                "technique_id": tech.technique_id,
                "name": tech.name,
                "is_subtechnique": tech.is_subtechnique,
                "parent_id": tech.parent_technique_id,
                "is_covered": is_covered,
                "status": "covered" if is_covered else "exposed",
                "active_rules_count": len(protecting_rules),
                "mapped_tools": sorted(list(set(r.tool for r in protecting_rules))),
                "url": tech.url,
                "is_identity_relevant": tech.is_identity_relevant,
            }

            if is_covered:
                covered_techniques_list.append(tech)
            else:
                exposed_techniques_list.append(tech)

            # Assign to primary tactics
            for tactic in tech.tactics:
                technique_cards_by_tactic.setdefault(tactic.name, []).append(card)

        # 4. Global Coverage Rate
        covered_count = len(covered_techniques_list)
        uncovered_count = total_in_scope - covered_count if total_in_scope >= covered_count else 0
        coverage_rate = round((covered_count / total_in_scope * 100), 1) if total_in_scope > 0 else 0.0

        # Total active rules deployed
        active_rules_count = (
            self.db.query(DetectionRule)
            .filter_by(enabled=True)
            .count()
        )

        # 5. Tool Summary Cards
        all_tools = ["CrowdStrike", "Defender for Identity", "Okta", "Wiz", "In-House", "Third-Party"]
        tool_metrics = []
        for tool_name in all_tools:
            tool_rules = self.db.query(DetectionRule).filter_by(tool=tool_name, enabled=True).all()
            rule_ids = [r.id for r in tool_rules]
            techs_covered = (
                self.db.query(func.count(func.distinct(DetectionRuleTechnique.technique_external_id)))
                .filter(DetectionRuleTechnique.rule_id.in_(rule_ids))
                .scalar() or 0
            )
            tool_metrics.append({
                "tool": tool_name,
                "active_rules": len(tool_rules),
                "techniques_covered": techs_covered,
                "is_active": active_tools is None or tool_name in active_tools,
                "status": "Demo data" if any(r.is_demo for r in tool_rules) else "Active",
            })

        # 6. Format Columns sorted by canonical ATT&CK tactic order
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
        ]
        columns = []
        for tac_name in tactic_order:
            if tac_name in technique_cards_by_tactic:
                cards = technique_cards_by_tactic[tac_name]
                columns.append({
                    "tactic_name": tac_name,
                    "total_techniques": len(cards),
                    "covered_count": sum(1 for c in cards if c["is_covered"]),
                    "exposed_count": sum(1 for c in cards if not c["is_covered"]),
                    "techniques": cards,
                })

        return {
            "view_scope": view_scope,
            "status_filter": status_filter,
            "filters_applied": {
                "client_restriction": client_restriction,
                "itdr_scope": itdr_scope,
                "active_tools": active_tools or all_tools,
            },
            "summary": {
                "total_in_scope": total_in_scope,
                "covered_techniques": covered_count,
                "uncovered_gaps": uncovered_count,
                "coverage_rate": coverage_rate,
                "active_rules_deployed": active_rules_count,
            },
            "tools": tool_metrics,
            "columns": columns,
        }

    def get_ttp_detail(self, technique_id: str) -> Dict[str, Any]:
        """
        Retrieves in-depth technical detail, mapped detection rules, D3FEND countermeasures,
        and procedures for the Technique Detail Drawer modal.
        """
        tech = self.db.query(AttackTechnique).filter(
            (AttackTechnique.technique_id == technique_id) |
            (AttackTechnique.technique_id.like(f"{technique_id}%"))
        ).first()

        if not tech:
            return {"error": f"Technique {technique_id} not found"}

        # Mapped rules
        rule_mappings = (
            self.db.query(DetectionRuleTechnique)
            .join(DetectionRule)
            .filter(
                (DetectionRuleTechnique.technique_external_id == tech.technique_id) |
                (DetectionRuleTechnique.technique_external_id == tech.technique_id.split(".")[0])
            )
            .all()
        )
        mapped_rules = [
            {
                "rule_id": rm.rule.rule_id,
                "name": rm.rule.name,
                "tool": rm.rule.tool,
                "enabled": rm.rule.enabled,
                "fidelity": rm.rule.fidelity,
                "severity": rm.rule.severity,
                "coverage_level": rm.coverage_level,
                "validation_status": rm.validation_status,
                "is_demo": rm.rule.is_demo,
            }
            for rm in rule_mappings
        ]

        # Mapped D3FEND defenses
        defences = (
            self.db.query(AttackDefenceMapping)
            .filter(
                (AttackDefenceMapping.attack_technique_external_id == tech.technique_id) |
                (AttackDefenceMapping.attack_technique_external_id == tech.technique_id.split(".")[0])
            )
            .all()
        )
        mapped_defences = [
            {
                "d3fend_id": d.d3fend_external_id,
                "name": d.d3fend_technique.name,
                "relationship": d.relationship_type,
                "provenance": d.mapping_source,
                "url": d.d3fend_technique.url,
                "definition": d.d3fend_technique.definition,
            }
            for d in defences
        ]

        # Procedures
        procedures = (
            self.db.query(TechniqueProcedure)
            .filter_by(technique_id=tech.id)
            .limit(5)
            .all()
        )
        proc_examples = [
            {
                "source": p.source_name or "Adversary",
                "description": p.description,
            }
            for p in procedures
        ]

        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "description": tech.description,
            "url": tech.url,
            "is_subtechnique": tech.is_subtechnique,
            "parent_id": tech.parent_technique_id,
            "platforms": tech.platforms or [],
            "tactics": [t.name for t in tech.tactics],
            "is_identity_relevant": tech.is_identity_relevant,
            "is_covered": len(mapped_rules) > 0,
            "coverage_rationale": (
                f"Defended by {len(mapped_rules)} active detection rules across "
                f"{', '.join(sorted(list(set(r['tool'] for r in mapped_rules))))}"
                if mapped_rules else "No active detection rules currently deployed. Critical coverage gap."
            ),
            "mapped_rules": mapped_rules,
            "mapped_defences": mapped_defences,
            "procedures": proc_examples,
        }
