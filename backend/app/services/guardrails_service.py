"""
AI Security Guardrails Service for ITDR Platform.
Provides multi-layer defense against:
1. Direct prompt injection and jailbreak attacks in user advisories.
2. Indirect prompt injection inside retrieved ATT&CK, D3FEND, and threat-feed contexts.
3. Unsafe, ungrounded, or leaking LLM-generated reports.

Distinguishes between malicious instructions targeting the LLM and legitimate
cybersecurity advisories containing quoted attack commands or malware analysis payloads.
Supports 'monitor' and 'enforce' operational modes.
"""
import re
import time
import logging
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Direct Injection & Jailbreak Signatures
# ------------------------------------------------------------------------------

# Imperative instruction overrides targeting the LLM assistant
INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"\b(?:ignore|disregard|forget|override|bypass|cancel)\b(?:\s+\w+){0,4}\s+\b(?:previous|all|prior|above|system)\b\s+\b(?:instructions|prompts?|rules?|directives?|constraints?)\b", re.IGNORECASE),
    re.compile(r"\b(?:disregard|ignore)\b\s+(?:the\s+)?(?:system\s+)?(?:prompt|rules|instructions)\b", re.IGNORECASE),
    re.compile(r"\b(?:do\s+not|nevermind)\s+follow\s+(?:the\s+)?(?:system|previous)\s+instructions\b", re.IGNORECASE),
    re.compile(r"\b(?:you\s+must\s+now|from\s+now\s+on\s+you\s+(?:will|must))\b\s+(?:ignore|disregard|forget)\b", re.IGNORECASE),
]

# Persona / Role-switch & Jailbreak patterns
JAILBREAK_PATTERNS = [
    re.compile(r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|jailbreak|chaos|evil|root|god\s+mode)\b", re.IGNORECASE),
    re.compile(r"\b(?:developer|maintenance|debug|admin|unrestricted)\s+mode\s+(?:is\s+)?(?:enabled|activated|on)\b", re.IGNORECASE),
    re.compile(r"\bjailbreak(?:ed)?\s+mode\b", re.IGNORECASE),
    re.compile(r"\bswitch\s+to\s+(?:unrestricted|unfiltered|jailbreak)\s+mode\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+you\s+have\s+no\s+(?:rules|guidelines|safety|filters?|restrictions?)\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(?:your\s+)?(?:safety|content|ethical|security)\s+(?:filters?|guidelines?|protocols?|checks?)\b", re.IGNORECASE),
]

# System prompt leakage and secret exfiltration patterns
PROMPT_LEAKAGE_PATTERNS = [
    re.compile(r"\b(?:print|show|reveal|display|output|echo|repeat|quote)\b(?:\s+\w+){0,3}\s+\b(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|developer\s+prompt|hidden\s+prompt|secret\s+key|api\s+key)\b", re.IGNORECASE),
    re.compile(r"\bwhat\s+(?:is|are)\s+your\s+(?:system\s+prompt|initial\s+instructions?|original\s+prompt)\b", re.IGNORECASE),
    re.compile(r"\boutput\s+the\s+exact\s+text\s+above\b", re.IGNORECASE),
]

# Delimiter / Conversational turn injection patterns
DELIMITER_INJECTION_PATTERNS = [
    re.compile(r"<\s*\|\s*im_start\s*\|\s*>\s*system", re.IGNORECASE),
    re.compile(r"\[\s*SYSTEM(?:_MESSAGE)?\s*\]", re.IGNORECASE),
    re.compile(r"\{\s*\"role\"\s*:\s*\"system\"\s*\}", re.IGNORECASE),
    re.compile(r"###\s*System\s*:", re.IGNORECASE),
    re.compile(r"===\s*SYSTEM\s*INSTRUCTIONS?\s*===", re.IGNORECASE),
]

# ------------------------------------------------------------------------------
# Context-Aware Security Evidence Indicators
# ------------------------------------------------------------------------------

# Identifies that the text is legitimately describing an adversary or cyber incident
CYBER_INCIDENT_CONTEXT_INDICATORS = [
    re.compile(r"\b(?:cisa|cert|fbi|nsa|mitre|cve-\d{4}-\d{4,8}|apt\d+|fin\d+|lazarus|scatter\s+swine|midnight\s+blizzard)\b", re.IGNORECASE),
    re.compile(r"\b(?:threat\s+actor|adversary|attacker|malware|ransomware|trojan|backdoor|phishing|payload)\b", re.IGNORECASE),
    re.compile(r"\b(?:t\d{4}(?:\.\d{3})?|d3(?:a)?-[a-z0-9]+)\b", re.IGNORECASE),
    re.compile(r"\b(?:lsass|mimikatz|kerberos|kerberoast|dcsync|ntlm|golden\s+saml|oauth|token\s+theft|pass-the-hash)\b", re.IGNORECASE),
    re.compile(r"\b(?:event\s+id\s+\d{4}|active\s+directory|domain\s+controller|powershell\.exe|cmd\.exe)\b", re.IGNORECASE),
    re.compile(r"\b(?:incident\s+response|forensic|soc\s+alert|detection\s+rule|telemetry|ioc)\b", re.IGNORECASE),
]

# Identifies that the suspicious instruction is quoted as evidence, not directed at the assistant
QUOTED_PAYLOAD_INDICATORS = [
    re.compile(r"(?:contained|included|observed|sent|injected|payload|subject|body|string|message|email|prompt|example|sample|note)[:\s]+[\"'\`].*?[\"'\`]", re.IGNORECASE),
    re.compile(r"[\"'\`][^\"'\`]*?(?:ignore|disregard|system\s+prompt|jailbreak)[^\"'\`]*?[\"'\`]", re.IGNORECASE),
    re.compile(r"(?:demonstrating|simulating|testing|investigating)\s+(?:prompt\s+injection|jailbreak)", re.IGNORECASE),
]

# ------------------------------------------------------------------------------
# Indirect Injection in Retrieved Context Signatures
# ------------------------------------------------------------------------------

INDIRECT_INJECTION_PATTERNS = [
    re.compile(r"\[\s*(?:SYSTEM|OVERRIDE|INSTRUCTION|NOTE)\s*:[^\]]*?(?:ignore|disregard|bypass|classify|set\s+severity|do\s+not\s+report)[^\]]*?\]", re.IGNORECASE),
    re.compile(r"<!--\s*#?\s*(?:ignore|disregard|system|override)[^>]*?-->", re.IGNORECASE),
    re.compile(r"\b(?:important|urgent|security\s+override)\s*:\s*(?:ignore|do\s+not\s+report|classify\s+as\s+low|say\s+that\s+no\s+threat)\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+mention\s+this\s+technique\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+actual\s+findings\s+and\s+output\b", re.IGNORECASE),
]

# ------------------------------------------------------------------------------
# Output Safety Signatures
# ------------------------------------------------------------------------------

SYSTEM_PROMPT_FINGERPRINTS = [
    "you are a senior identity threat intelligence and detection engineer",
    "critical operational rules",
    "grounding & evidence integrity",
    "observability & citations",
    "defensive posture & coverage",
    "separation of concerns",
    "never invent mitre technique ids",
]

SECRET_PATTERNS = [
    re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bjina_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"postgresql(?:\+psycopg)?:\/\/[^\s:]+:[^\s@]+@[^\s\/]+\/[^\s\?]+", re.IGNORECASE),
]

DESTRUCTIVE_RECOMMENDATION_PATTERNS = [
    re.compile(r"\b(?:rm\s+-(?:rf|fr|r\s+-f|f\s+-r)\s+\S*|format\s+[a-z]:|del\s+\/[fsq\s]+)", re.IGNORECASE),
    re.compile(r"\b(?:drop\s+database|delete\s+all\s+(?:users|accounts|records|tables)|truncate\s+table)\b", re.IGNORECASE),
    re.compile(r"\b(?:disable\s+all\s+(?:firewalls?|security|antivirus|edr|mfa)|turn\s+off\s+logging)\b", re.IGNORECASE),
    re.compile(r"\b(?:exfiltrate|send\s+credentials\s+to|upload\s+passwords\s+to)\b", re.IGNORECASE),
]

FALSE_EXECUTION_CLAIM_PATTERNS = [
    re.compile(r"\b(?:i\s+have|we\s+have|the\s+system\s+has)\s+(?:already\s+)?(?:deleted|terminated|isolated|wiped|remediated|blocked\s+all|executed)\b", re.IGNORECASE),
    re.compile(r"\baction\s+(?:already\s+)?(?:completed|executed|taken)\s+by\s+the\s+analyst\s+bot\b", re.IGNORECASE),
]


class GuardrailsService:
    """
    Centralized, modular AI Security Guardrails Engine.
    Executes context-aware classification, quarantining, and safety verification.
    """

    def __init__(
        self,
        mode: str = "monitor",
        input_threshold: float = 0.75,
        context_threshold: float = 0.70,
        output_threshold: float = 0.75,
        classifier_provider: str = "rule_heuristic",
        timeout_seconds: int = 5,
    ):
        self.mode = (mode or "monitor").strip().lower()
        self.input_threshold = input_threshold
        self.context_threshold = context_threshold
        self.output_threshold = output_threshold
        self.classifier_provider = classifier_provider
        self.timeout_seconds = timeout_seconds

    @property
    def is_enforce(self) -> bool:
        """Returns True if the engine is running in active enforcement mode."""
        return self.mode == "enforce"

    # ==========================================================================
    # 1. Direct Input Screening
    # ==========================================================================

    def screen_input(self, text: str) -> Dict[str, Any]:
        """
        Inspects user advisory text for direct prompt injection and jailbreak attempts.
        Context-aware: Differentiates malicious directives targeting the LLM from
        legitimate threat advisories reporting quoted injection attacks or attack evidence.
        """
        if not text or not text.strip():
            return {
                "status": "CLEAN",
                "risk_score": 0.0,
                "is_suspicious": False,
                "is_blocked": False,
                "findings": [],
                "quarantine_applied": False,
            }

        start_time = time.perf_counter()
        raw_text = text.strip()
        findings: List[Dict[str, Any]] = []

        # Check for direct instruction overrides
        for pat in INSTRUCTION_OVERRIDE_PATTERNS:
            match = pat.search(raw_text)
            if match:
                findings.append({
                    "category": "instruction_override",
                    "severity": "HIGH",
                    "match": match.group(0),
                    "confidence": 0.85,
                    "description": "Attempted override of system instructions or operational constraints",
                })
                break

        # Check for jailbreak and role-override patterns
        for pat in JAILBREAK_PATTERNS:
            match = pat.search(raw_text)
            if match:
                findings.append({
                    "category": "jailbreak_attempt",
                    "severity": "CRITICAL",
                    "match": match.group(0),
                    "confidence": 0.95,
                    "description": "Attempted role override, persona bypass, or jailbreak mode activation",
                })
                break

        # Check for prompt extraction / leakage patterns
        for pat in PROMPT_LEAKAGE_PATTERNS:
            match = pat.search(raw_text)
            if match:
                findings.append({
                    "category": "prompt_leakage_attempt",
                    "severity": "HIGH",
                    "match": match.group(0),
                    "confidence": 0.90,
                    "description": "Attempted exfiltration or disclosure of system prompt instructions",
                })
                break

        # Check for delimiter / artificial turn injection
        for pat in DELIMITER_INJECTION_PATTERNS:
            match = pat.search(raw_text)
            if match:
                findings.append({
                    "category": "delimiter_injection",
                    "severity": "CRITICAL",
                    "match": match.group(0),
                    "confidence": 0.95,
                    "description": "Artificial conversational turn or system boundary delimiter injection",
                })
                break

        # Context-Aware False Positive Adjustment:
        # Check if the advisory represents legitimate security intelligence describing attacks
        has_incident_context = any(pat.search(raw_text) for pat in CYBER_INCIDENT_CONTEXT_INDICATORS)
        is_quoted_or_evidentiary = any(pat.search(raw_text) for pat in QUOTED_PAYLOAD_INDICATORS)

        adjusted_findings = []
        for finding in findings:
            confidence = finding["confidence"]
            # If the suspicious string is enclosed in quotes or in an incident report context,
            # it is likely reported attack evidence rather than a direct exploit targeting this pipeline.
            if is_quoted_or_evidentiary and has_incident_context:
                confidence = max(0.15, confidence - 0.60)
                finding["context_assessment"] = "QUOTED_ATTACK_EVIDENCE"
                finding["confidence"] = round(confidence, 2)
            elif has_incident_context:
                confidence = max(0.30, confidence - 0.35)
                finding["context_assessment"] = "REPORTED_INCIDENT_CONTEXT"
                finding["confidence"] = round(confidence, 2)
            else:
                finding["context_assessment"] = "DIRECT_DIRECTIVE_TARGETING_ASSISTANT"

            adjusted_findings.append(finding)

        # Aggregate risk score
        risk_score = max([f["confidence"] for f in adjusted_findings], default=0.0)
        is_suspicious = risk_score >= 0.50
        is_blocked = (risk_score >= self.input_threshold) and self.is_enforce

        if is_blocked:
            status = "BLOCKED"
        elif is_suspicious:
            status = "SUSPICIOUS" if self.is_enforce else "MONITORED"
        else:
            status = "CLEAN"

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "status": status,
            "risk_score": round(risk_score, 4),
            "is_suspicious": is_suspicious,
            "is_blocked": is_blocked,
            "findings": adjusted_findings,
            "has_incident_context": has_incident_context,
            "is_quoted_or_evidentiary": is_quoted_or_evidentiary,
            "duration_ms": duration_ms,
        }

    # ==========================================================================
    # 2. Retrieved Context Indirect Injection Screening
    # ==========================================================================

    def screen_retrieved_context(
        self,
        candidate_techniques: List[Dict[str, Any]],
        d3fend_countermeasures: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Inspects retrieved ATT&CK, D3FEND, and CTI feed documents for indirect prompt injection.
        Identifies suspicious embedded instructions, tracks document IDs, and sanitizes/quarantines
        untrusted context in enforce mode while preserving clean evidence.
        """
        start_time = time.perf_counter()
        suspicious_document_ids: List[str] = []
        quarantined_document_ids: List[str] = []
        findings: List[Dict[str, Any]] = []

        trusted_candidates: List[Dict[str, Any]] = []
        trusted_d3fend: List[Dict[str, Any]] = []

        # 1. Inspect ATT&CK candidate techniques and their evidence snippets
        for cand in candidate_techniques:
            tid = cand.get("technique_id", "unknown")
            doc_id = f"att-tech-{tid}"
            desc = cand.get("description", "")
            cand_suspicious = False

            # Check description for indirect injection
            for pat in INDIRECT_INJECTION_PATTERNS + INSTRUCTION_OVERRIDE_PATTERNS:
                match = pat.search(desc)
                if match:
                    cand_suspicious = True
                    suspicious_document_ids.append(doc_id)
                    findings.append({
                        "source_id": doc_id,
                        "technique_id": tid,
                        "type": "ATTACK_TECHNIQUE_DESCRIPTION",
                        "match": match.group(0),
                        "description": "Indirect injection pattern detected in technique description",
                    })
                    break

            # Check evidence snippets
            clean_snippets = []
            for snip in cand.get("evidence_snippets", []):
                snip_id = snip.get("source_id", f"{doc_id}-snippet")
                excerpt = snip.get("excerpt", "")
                snip_suspicious = False
                for pat in INDIRECT_INJECTION_PATTERNS + INSTRUCTION_OVERRIDE_PATTERNS:
                    match = pat.search(excerpt)
                    if match:
                        snip_suspicious = True
                        cand_suspicious = True
                        suspicious_document_ids.append(snip_id)
                        findings.append({
                            "source_id": snip_id,
                            "technique_id": tid,
                            "type": "RETRIEVED_EVIDENCE_SNIPPET",
                            "match": match.group(0),
                            "description": "Indirect prompt injection detected in retrieved evidence snippet",
                        })
                        break

                if snip_suspicious and self.is_enforce:
                    quarantined_document_ids.append(snip_id)
                else:
                    clean_snippets.append(snip)

            # In enforce mode, quarantine candidate if primary description is hostile
            if cand_suspicious and self.is_enforce:
                quarantined_document_ids.append(doc_id)
                # Keep candidate only if clean snippets remain and description is sanitized
                if clean_snippets:
                    cand_copy = dict(cand)
                    cand_copy["evidence_snippets"] = clean_snippets
                    cand_copy["description"] = "[Content Sanitized: Untrusted instruction excluded from LLM context]"
                    cand_copy["guardrail_sanitized"] = True
                    trusted_candidates.append(cand_copy)
            else:
                trusted_candidates.append(cand)

        # 2. Inspect D3FEND countermeasures
        for d in d3fend_countermeasures:
            did = d.get("d3fend_id", "unknown")
            doc_id = f"d3f-tech-{did}"
            definition = d.get("definition") or d.get("rationale") or ""
            d3f_suspicious = False

            for pat in INDIRECT_INJECTION_PATTERNS + INSTRUCTION_OVERRIDE_PATTERNS:
                match = pat.search(definition)
                if match:
                    d3f_suspicious = True
                    suspicious_document_ids.append(doc_id)
                    findings.append({
                        "source_id": doc_id,
                        "d3fend_id": did,
                        "type": "D3FEND_COUNTERMEASURE",
                        "match": match.group(0),
                        "description": "Indirect prompt injection detected in defensive countermeasure definition",
                    })
                    break

            if d3f_suspicious and self.is_enforce:
                quarantined_document_ids.append(doc_id)
            else:
                trusted_d3fend.append(d)

        # Deduplicate document IDs
        suspicious_document_ids = sorted(list(set(suspicious_document_ids)))
        quarantined_document_ids = sorted(list(set(quarantined_document_ids)))

        has_suspicious_content = len(suspicious_document_ids) > 0
        has_quarantined_content = len(quarantined_document_ids) > 0

        # Evaluate if sufficient trusted evidence remains after quarantine
        sufficient_trusted_evidence = len(trusted_candidates) > 0

        if has_suspicious_content and self.is_enforce and not sufficient_trusted_evidence:
            status = "BLOCKED"
        elif has_quarantined_content:
            status = "SANITIZED"
        elif has_suspicious_content:
            status = "UNTRUSTED_CONTENT_DETECTED"
        else:
            status = "CLEAN"

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "status": status,
            "has_suspicious_content": has_suspicious_content,
            "has_quarantined_content": has_quarantined_content,
            "suspicious_document_ids": suspicious_document_ids,
            "quarantined_document_ids": quarantined_document_ids,
            "trusted_candidates": trusted_candidates,
            "trusted_d3fend": trusted_d3fend,
            "sufficient_trusted_evidence": sufficient_trusted_evidence,
            "findings": findings,
            "duration_ms": duration_ms,
        }

    # ==========================================================================
    # 3. Output Safety and Trust Validation
    # ==========================================================================

    def validate_output_safety(self, report_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects generated threat report for:
        1. System prompt or internal instruction disclosure / leakage.
        2. Credential or API secret disclosure.
        3. Destructive or dangerous recommendations (e.g. format C:, rm -rf /).
        4. False claims that remediation actions were already executed.
        5. Adoption of untrusted directives.
        """
        start_time = time.perf_counter()
        if not report_dict or not isinstance(report_dict, dict):
            return {
                "status": "UNSAFE",
                "risk_score": 1.0,
                "is_safe": False,
                "findings": [{"category": "empty_report", "description": "Report object is empty or malformed"}],
                "duration_ms": 0.0,
            }

        findings: List[Dict[str, Any]] = []

        # Flatten report text for holistic inspection
        text_corpus = []
        for field in ["report_title", "executive_summary", "incident_overview", "severity_rationale"]:
            val = report_dict.get(field)
            if val:
                text_corpus.append(str(val))

        for rec in report_dict.get("recommended_actions", []):
            if isinstance(rec, dict):
                text_corpus.append(str(rec.get("action", "")))
                text_corpus.append(str(rec.get("rationale", "")))

        full_output_text = " ".join(text_corpus).lower()

        # 1. System Prompt Leakage Check
        for fp in SYSTEM_PROMPT_FINGERPRINTS:
            if fp in full_output_text:
                findings.append({
                    "category": "system_prompt_leakage",
                    "severity": "CRITICAL",
                    "match": fp,
                    "confidence": 0.95,
                    "description": "Generated report contains verbatim system prompt instruction text",
                })
                break

        # 2. Secret / Credential Leakage Check
        for pat in SECRET_PATTERNS:
            match = pat.search(" ".join(text_corpus))
            if match:
                findings.append({
                    "category": "credential_disclosure",
                    "severity": "CRITICAL",
                    "match": match.group(0)[:15] + "...",
                    "confidence": 0.99,
                    "description": "Sensitive API key or database connection string detected in output",
                })
                break

        # 3. Destructive Recommendations Check
        for rec in report_dict.get("recommended_actions", []):
            if isinstance(rec, dict):
                action_text = f"{rec.get('action', '')} {rec.get('rationale', '')}"
                for pat in DESTRUCTIVE_RECOMMENDATION_PATTERNS:
                    match = pat.search(action_text)
                    if match:
                        findings.append({
                            "category": "destructive_recommendation",
                            "severity": "CRITICAL",
                            "match": match.group(0),
                            "confidence": 0.90,
                            "description": "Potentially destructive or harmful recommendation detected",
                        })
                        break

        # 4. False Execution Claims Check
        for pat in FALSE_EXECUTION_CLAIM_PATTERNS:
            match = pat.search(full_output_text)
            if match:
                findings.append({
                    "category": "false_execution_claim",
                    "severity": "HIGH",
                    "match": match.group(0),
                    "confidence": 0.85,
                    "description": "Report claims automated actions were already executed on enterprise infrastructure",
                })
                break

        risk_score = max([f["confidence"] for f in findings], default=0.0)
        is_unsafe = (risk_score >= self.output_threshold) and self.is_enforce

        if is_unsafe:
            status = "UNSAFE"
        elif findings:
            status = "LEAKAGE_DETECTED" if any(f["category"] in ["system_prompt_leakage", "credential_disclosure"] for f in findings) else "FLAGGED"
        else:
            status = "VERIFIED"

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "status": status,
            "risk_score": round(risk_score, 4),
            "is_safe": not is_unsafe,
            "findings": findings,
            "duration_ms": duration_ms,
        }

    # ==========================================================================
    # 4. Security Review Brief Synthesizer
    # ==========================================================================

    def create_security_review_brief(
        self,
        reason: str,
        stage: str,
        findings: List[Dict[str, Any]],
        advisory_text: str,
        extracted_indicators: Optional[Dict[str, Any]] = None,
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Produces a safe, informative threat brief for advisories or reports
        diverted to security review. Avoids re-executing or repeating hostile instructions.
        """
        sanitized_findings = [
            f"{f.get('category', 'security_violation')}: {f.get('description', 'Detected policy violation')}"
            for f in findings[:5]
        ]
        if not sanitized_findings:
            sanitized_findings = [f"Security review triggered during {stage}: {reason}"]

        return {
            "report_title": f"Security Review Required: {stage.replace('_', ' ').title()}",
            "executive_summary": (
                f"Automated threat modeling analysis was halted and routed to the Security Review Gate. "
                f"The AI Security Guardrails detected high-confidence policy violations during the '{stage}' stage: {reason}. "
                f"To protect pipeline integrity and prevent prompt manipulation, generation has been safely quarantined."
            ),
            "severity": "High",
            "severity_rationale": "High-confidence adversarial input or unsafe output pattern detected by guardrails engine.",
            "incident_overview": (
                f"Advisory Submission ID: Quarantined ({len(advisory_text)} characters).\n"
                f"Triggering Stage: {stage}\n"
                f"Primary Reason: {reason}\n"
                f"Detected Flags: {', '.join(sanitized_findings)}"
            ),
            "extracted_indicators": extracted_indicators or {},
            "technique_candidates": [],
            "defensive_techniques": [],
            "coverage_assessment": [],
            "recommended_actions": [
                {
                    "priority": "High",
                    "category": "SOC Governance",
                    "action": "Review the raw advisory text in an isolated administrative sandbox.",
                    "rationale": "Verify whether submission represents a real attack or intentional pipeline prompt injection.",
                },
                {
                    "priority": "Medium",
                    "category": "Threat Intelligence",
                    "action": "Audit connected threat feeds and external sources for indicator poisoning.",
                    "rationale": "Prevent indirect injection payloads from contaminating vector knowledge collections.",
                },
            ],
            "uncertainties": [
                f"Analysis halted due to guardrail security gate: {reason}",
                "No external LLM inference was executed on the quarantined payload",
            ],
            "citations": [],
            "model_metadata": {
                "provider": "ITDR Security Guardrails",
                "stage": stage,
                "reason": reason,
                "quarantined": True,
            },
        }
