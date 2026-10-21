#!/usr/bin/env python3
"""
Seed deterministic demo records for ITDR Platform.
Marks all records clearly with is_demo=True.
Provides realistic data reflecting the functional specification screenshots:
- Active detection rules across CrowdStrike, MDI, Okta, Wiz, In-House, Third-Party
- Mappings to ATT&CK techniques demonstrating multi-rule coverage and identified gaps
- Multi-stage attack scenarios for the 2D Resilience Quadrant
- CTI bulletins and feeds for Screen 5 and Screen 7
"""
import sys
import os
import datetime
import logging
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import SessionLocal
from app.models.attack import AttackTechnique
from app.models.coverage import DetectionRule, DetectionRuleTechnique
from app.models.feeds import ThreatFeed, ThreatScenario

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_demo_data")


def seed():
    db = SessionLocal()
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        logger.info("Starting demo data seeding...")

        # 1. Clean existing demo data to ensure idempotency
        db.query(DetectionRuleTechnique).filter(
            DetectionRuleTechnique.rule_id.in_(
                db.query(DetectionRule.id).filter(DetectionRule.is_demo.is_(True))
            )
        ).delete(synchronize_session=False)
        db.query(DetectionRule).filter_by(is_demo=True).delete(synchronize_session=False)
        db.query(ThreatFeed).filter_by(is_demo=True).delete(synchronize_session=False)
        db.query(ThreatScenario).filter_by(is_demo=True).delete(synchronize_session=False)
        db.commit()

        # 2. Seed Detection Rules & Controls
        # Tools: CrowdStrike, Defender for Identity, Okta, Wiz, In-House, Third-Party
        rules_def = [
            # CrowdStrike
            {"id": "CS-ID-101", "name": "Falcon IDP - Suspicious Domain Controller Directory Replication", "tool": "CrowdStrike", "techs": ["T1003", "T1003.006"], "itdr": "ITDR Scope Only"},
            {"id": "CS-ID-102", "name": "Falcon IDP - Kerberoasting Sighted via Abnormal Service Ticket Request", "tool": "CrowdStrike", "techs": ["T1558", "T1558.003"], "itdr": "ITDR Scope Only"},
            {"id": "CS-ID-103", "name": "Falcon Identity - Abnormal Interactive Logon from Workstation to DC", "tool": "CrowdStrike", "techs": ["T1078", "T1078.002"], "itdr": "ITDR Scope Only"},
            {"id": "CS-ID-104", "name": "Falcon Endpoint - LSASS Process Memory Dump Attempt", "tool": "CrowdStrike", "techs": ["T1003", "T1003.001"], "itdr": "ALL"},
            {"id": "CS-ID-105", "name": "Falcon Identity - Pass-the-Hash Detected Over SMB", "tool": "CrowdStrike", "techs": ["T1550", "T1550.002"], "itdr": "ITDR Scope Only"},
            
            # Microsoft Defender for Identity (MDI)
            {"id": "MDI-R-201", "name": "MDI - Suspected Golden Ticket Usage (Non-existent Ticket Granting Service)", "tool": "Defender for Identity", "techs": ["T1558", "T1558.001"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-202", "name": "MDI - Malicious Addition of Sensitive Group Member in Active Directory", "tool": "Defender for Identity", "techs": ["T1098", "T1098.002"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-203", "name": "MDI - User and Computer Account Reconnaissance via LDAP", "tool": "Defender for Identity", "techs": ["T1087", "T1087.002"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-204", "name": "MDI - Suspected DCSync Attack (Replication of Directory Changes)", "tool": "Defender for Identity", "techs": ["T1003", "T1003.006"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-205", "name": "MDI - Account Manipulation: Primary Group ID Tampering", "tool": "Defender for Identity", "techs": ["T1098"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-206", "name": "MDI - Kerberos AS-REP Roasting Sighted without Pre-Authentication", "tool": "Defender for Identity", "techs": ["T1558", "T1558.004"], "itdr": "ITDR Scope Only"},
            {"id": "MDI-R-207", "name": "MDI - Brute Force Password Spraying Against Active Directory Accounts", "tool": "Defender for Identity", "techs": ["T1110", "T1110.003"], "itdr": "ITDR Scope Only"},

            # Okta Identity Threat Protection
            {"id": "OKTA-POL-301", "name": "Okta - High-Risk Session Token Anomaly / Impossible Travel", "tool": "Okta", "techs": ["T1078", "T1078.004"], "itdr": "ITDR Scope Only"},
            {"id": "OKTA-POL-302", "name": "Okta - Multiple Fast Multi-Factor Authentication Denials (Push Fatigue)", "tool": "Okta", "techs": ["T1110", "T1621"], "itdr": "ITDR Scope Only"},
            {"id": "OKTA-POL-303", "name": "Okta - Suspicious Admin Privilege Elevation & API Token Issuance", "tool": "Okta", "techs": ["T1098", "T1136"], "itdr": "ITDR Scope Only"},
            {"id": "OKTA-POL-304", "name": "Okta - MFA Reset / Device Registration from Unrecognized ASN", "tool": "Okta", "techs": ["T1556", "T1556.006"], "itdr": "ITDR Scope Only"},

            # Wiz Cloud Identity Posture
            {"id": "WIZ-IAM-401", "name": "Wiz - Overprivileged AWS IAM Role Assumed from Non-Corporate IP", "tool": "Wiz", "techs": ["T1078", "T1078.004"], "itdr": "ITDR Scope Only"},
            {"id": "WIZ-IAM-402", "name": "Wiz - Azure Service Principal Credential Addition with Global Administrator", "tool": "Wiz", "techs": ["T1098", "T1098.001"], "itdr": "ITDR Scope Only"},
            {"id": "WIZ-IAM-403", "name": "Wiz - Cloud Service Dashboard Access with Inactive API Key", "tool": "Wiz", "techs": ["T1078"], "itdr": "ITDR Scope Only"},

            # In-House Custom SCB Rules
            {"id": "SCB-RULE-501", "name": "SCB In-House - Privileged Service Account Interactive Shell Spawn", "tool": "In-House", "techs": ["T1078", "T1059"], "itdr": "ITDR Scope Only"},
            {"id": "SCB-RULE-502", "name": "SCB In-House - Dual-Control Approval Bypass for Core Banking IAM", "tool": "In-House", "techs": ["T1098"], "itdr": "ITDR Scope Only"},
            {"id": "SCB-RULE-503", "name": "SCB In-House - Emergency Break-Glass Account Invocation Audit", "tool": "In-House", "techs": ["T1078", "T1136"], "itdr": "ITDR Scope Only"},
            {"id": "SCB-RULE-504", "name": "SCB In-House - Dormant Domain Admin Usage in Off-Hours", "tool": "In-House", "techs": ["T1078", "T1078.002"], "itdr": "ITDR Scope Only"},

            # Third-Party / Others
            {"id": "TP-SEC-601", "name": "CyberArk PAM - Unmanaged Privileged Credential Discovery", "tool": "Third-Party", "techs": ["T1087", "T1069"], "itdr": "ITDR Scope Only"},
            {"id": "TP-SEC-602", "name": "BeyondTrust - Privilege Escalation via Sudo Delegation Anomaly", "tool": "Third-Party", "techs": ["T1548", "T1548.003"], "itdr": "ALL"},
        ]

        created_rules = []
        for r_spec in rules_def:
            rule = DetectionRule(
                rule_id=r_spec["id"],
                name=r_spec["name"],
                tool=r_spec["tool"],
                description=f"Automated detection check evaluating identity telemetry: {r_spec['name']}",
                enabled=True,
                client_restriction="ALL",
                itdr_scope=r_spec["itdr"],
                rule_type="Detection",
                fidelity="High",
                severity="High",
                last_observed=now - datetime.timedelta(hours=2),
                is_demo=True,
                raw_metadata={"synthetic": True, "vendor": r_spec["tool"]},
            )
            db.add(rule)
            db.flush()
            created_rules.append((rule, r_spec["techs"]))

        # Link rules to ATT&CK techniques
        linked_mappings = 0
        seen_pairs = set()
        for rule, tech_ids in created_rules:
            for tid in tech_ids:
                # Find matching attack technique record in db
                tech_recs = db.query(AttackTechnique).filter(
                    (AttackTechnique.technique_id == tid) |
                    (AttackTechnique.technique_id.like(f"{tid}.%"))
                ).all()

                for tech_rec in tech_recs:
                    pair = (rule.id, tech_rec.id)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        mapping = DetectionRuleTechnique(
                            rule_id=rule.id,
                            technique_id=tech_rec.id,
                            technique_external_id=tech_rec.technique_id,
                            coverage_level="Complete",
                            validation_status="Verified",
                        )
                        db.add(mapping)
                        linked_mappings += 1

        db.commit()
        logger.info(f"Seeded {len(created_rules)} detection rules and {linked_mappings} technique mappings.")

        # 3. Seed Threat Scenarios (Screen 4: Identity Threat Scenarios)
        scenarios_spec = [
            {
                "id": "SCEN-01",
                "name": "Golden SAML Token Forgery & Federation Abuse",
                "desc": "Adversary extracts token-signing certificate to mint arbitrary SAML assertions bypassing MFA across all cloud federated apps.",
                "det": 85.0,
                "mit": 90.0,
                "status": "Resilient",
                "ttps": ["T1558", "T1078.004", "T1606.002"],
                "source": "MITRE ATT&CK / CISA Advisory",
            },
            {
                "id": "SCEN-02",
                "name": "Kerberoasting on Service Accounts with Weak Encryption",
                "desc": "Offline password cracking of service ticket hashes requested by domain-authenticated user against legacy Kerberos RC4 SPNs.",
                "det": 92.0,
                "mit": 78.0,
                "status": "Resilient",
                "ttps": ["T1558.003", "T1110.002"],
                "source": "Active Directory Internal Assessment",
            },
            {
                "id": "SCEN-03",
                "name": "AD CS ESC1 Vulnerable Certificate Template Exploitation",
                "desc": "Adversary requests authentication certificate enrolling as high-privileged Domain Admin using misconfigured CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.",
                "det": 78.0,
                "mit": 35.0,
                "status": "Paper Tiger",
                "ttps": ["T1649", "T1078.002"],
                "source": "SpecterOps BloodHound Research",
            },
            {
                "id": "SCEN-04",
                "name": "MFA Fatigue & Push Exhaustion Campaign",
                "desc": "Repeated secondary authentication challenges pushed to victim mobile devices during night hours to force accidental consent.",
                "det": 30.0,
                "mit": 25.0,
                "status": "High Risk",
                "ttps": ["T1621", "T1110.001"],
                "source": "Okta & Microsoft Threat Intelligence",
            },
            {
                "id": "SCEN-05",
                "name": "OAuth Application Consent Grant & Mailbox Read Delegation",
                "desc": "Malicious cloud application tricks employee into granting offline Mail.Read permissions without administrator review.",
                "det": 45.0,
                "mit": 80.0,
                "status": "Silent Well",
                "ttps": ["T1528", "T1098.005"],
                "source": "Microsoft 365 Defender Telemetry",
            },
            {
                "id": "SCEN-06",
                "name": "Dormant Domain Administrator Reactivation & Shadow Admin Creation",
                "desc": "Adversary reactivates legacy contractor account, grants DCSync rights via ACL modification on the domain root object.",
                "det": 88.0,
                "mit": 82.0,
                "status": "Resilient",
                "ttps": ["T1078.002", "T1098", "T1003.006"],
                "source": "Standard Chartered Internal Audit",
            }
        ]

        for s_spec in scenarios_spec:
            scen = ThreatScenario(
                scenario_id=s_spec["id"],
                name=s_spec["name"],
                description=s_spec["desc"],
                source=s_spec["source"],
                detection_rate=s_spec["det"],
                mitigation_rate=s_spec["mit"],
                status=s_spec["status"],
                scope="ITDR Scope Only",
                client_restriction="ALL",
                attack_chain_ttps=s_spec["ttps"],
                is_demo=True,
                metadata_json={"quadrant": s_spec["status"]},
                updated_at=now,
            )
            db.add(scen)

        logger.info(f"Seeded {len(scenarios_spec)} threat scenarios.")

        # 4. Seed Threat Feeds & Bulletins (Screen 5: Threat Feeds & Screen 7: Completed Reports)
        feeds_spec = [
            {
                "id": "TB-2026-0010",
                "source": "CISA / Threat Intel",
                "title": "Adversaries used T1078.004 and T1003 to compromise USER_JD01 and DC-PRIMARY-01. Attackers bypassed MFA via session hijacking.",
                "desc": "An adversary obtained valid cloud credentials and performed LSASS dumping on hybrid domain controller, moving laterally to cloud storage.",
                "status": "New",
                "severity": "Critical",
                "published_at": now - datetime.timedelta(hours=4),
                "ttps": ["T1078.004", "T1003.001", "T1550"],
                "actors": ["APT29", "Midnight Blizzard"],
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a",
            },
            {
                "id": "TB-2026-0011",
                "source": "MS Threat Intel",
                "title": "EMERGENCY ADVISORY: APT29 Cloud Token & Privilege Escalation Campaign (TD-2026-0088)",
                "desc": "Actors abused OAuth app registrations with Exchange.ManageAsApp permissions, generating high-volume API requests.",
                "status": "Analyzed",
                "severity": "High",
                "published_at": now - datetime.timedelta(hours=12),
                "ttps": ["T1528", "T1098.005", "T1078"],
                "actors": ["APT29"],
                "url": "https://www.microsoft.com/security/blog/2026/01/apt29-cloud-tokens",
            },
            {
                "id": "TB-2026-0019",
                "source": "Okta Security Advisory",
                "title": "Adversaries targeted IT Service Desk with Vishing to Execute Self-Service Password Reset",
                "desc": "Social engineering campaign impersonating executives to reset MFA authenticators and gain administrative access.",
                "status": "Review",
                "severity": "High",
                "published_at": now - datetime.timedelta(days=1),
                "ttps": ["T1078", "T1098", "T1110"],
                "actors": ["Scattered Spider", "UNC3944"],
                "url": "https://sec.okta.com/articles/2026/service-desk-social-engineering",
            },
            {
                "id": "TB-2026-0024",
                "source": "CrowdStrike Threat Research",
                "title": "T1078.004 Cloud Accounts compromised via token abuse; T1003.001 LSASS Memory dump observed on staging tier",
                "desc": "Observed execution of mimikatz variant dumping credentials from lsass.exe process on perimeter Windows jump-host.",
                "status": "New",
                "severity": "High",
                "published_at": now - datetime.timedelta(days=2),
                "ttps": ["T1078.004", "T1003.001", "T1059.001"],
                "actors": ["Volt Typhoon"],
                "url": "https://www.crowdstrike.com/blog/hybrid-identity-lateral-movement-2026",
            },
            {
                "id": "TB-2026-0030",
                "source": "Wiz Cloud Security",
                "title": "Wiz Research Sights Unrestricted AWS STS Session Assumption Bypassing Org SCPs",
                "desc": "IAM role misconfiguration allowed external federated identity to assume cross-account management role without MFA constraint.",
                "status": "Analyzed",
                "severity": "Medium",
                "published_at": now - datetime.timedelta(days=3),
                "ttps": ["T1078.004", "T1550"],
                "actors": ["Unknown FinCrim"],
                "url": "https://www.wiz.io/blog/aws-sts-federation-misconfiguration",
            },
            {
                "id": "TB-2026-0035",
                "source": "CSA / Threat Intel",
                "title": "Pass-the-PRT Attack on Windows 11 Azure AD Joined Endpoints via Stolen Cloud Token",
                "desc": "Analysis of Primary Refresh Token (PRT) extraction using browser cookie injection and SSO token replay.",
                "status": "Review",
                "severity": "High",
                "published_at": now - datetime.timedelta(days=4),
                "ttps": ["T1550", "T1539", "T1078"],
                "actors": ["LAPSUS$"],
                "url": "https://cloudsecurityalliance.org/artifacts/prt-token-theft-analysis",
            },
            {
                "id": "TB-2026-0040",
                "source": "Internal ITDR SOC",
                "title": "Active Directory DCSync Replication from Unknown Workstation Subnet (T1003.006)",
                "desc": "DRSUAPI RPC calls received by DC01 originating from unauthorized developer subnet IP 10.14.22.88.",
                "status": "New",
                "severity": "Critical",
                "published_at": now - datetime.timedelta(hours=1),
                "ttps": ["T1003.006", "T1078.002"],
                "actors": ["Internal Assessment"],
                "url": "https://internal.soc.scb/bulletins/tb-2026-0040",
            }
        ]

        for f_spec in feeds_spec:
            feed = ThreatFeed(
                bulletin_id=f_spec["id"],
                source=f_spec["source"],
                title=f_spec["title"],
                description=f_spec["desc"],
                content=f_spec["desc"],
                url=f_spec["url"],
                published_at=f_spec["published_at"],
                ingested_at=now,
                status=f_spec["status"],
                related_ttps=f_spec["ttps"],
                threat_actors=f_spec["actors"],
                severity=f_spec["severity"],
                is_demo=True,
                raw_payload={"demo": True, "feed_id": f_spec["id"]},
            )
            db.add(feed)

        db.commit()
        logger.info(f"Seeded {len(feeds_spec)} threat intelligence feed bulletins.")
        logger.info("Demo data seeding completed successfully.")

    except Exception as e:
        db.rollback()
        logger.error(f"Error seeding demo data: {e}", exc_info=True)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
