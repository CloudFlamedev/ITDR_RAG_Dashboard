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
    re.compile(r"\b(?:system\s+instruction|system\s+override)\s*:\s*ignore\b", re.IGNORECASE),
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
    re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?[A-Za-z0-9!@#$%^&*()_+]{8,}[\"']?", re.IGNORECASE),
]

DESTRUCTIVE_RECOMMENDATION_PATTERNS = [
    re.compile(r"\b(?:rm\s+-(?:rf|fr|r\s+-f|f\s+-r)\s+\S*|format\s+[a-z]:|del\s+\/[fsq\s]+)", re.IGNORECASE),
    re.compile(r"\b(?:drop\s+database|delete\s+all\s+(?:users|accounts|records|tables)|truncate\s+table)\b", re.IGNORECASE),
    re.compile(r"\b(?:disable\s+all\s+(?:firewalls?|security|antivirus|edr|mfa)|turn\s+off\s+logging)\b", re.IGNORECASE),
    re.compile(r"\b(?:send\s+credentials\s+to|upload\s+passwords\s+to|exfiltrate\s+(?:data|credentials|passwords|tokens|secrets|files)?\s*to\s+\S+)\b", re.IGNORECASE),
]

FALSE_EXECUTION_CLAIM_PATTERNS = [
    re.compile(r"\b(?:i\s+have|we\s+have|the\s+system\s+has)\s+(?:already\s+)?(?:deleted|terminated|isolated|wiped|remediated|blocked\s+all|executed)\b", re.IGNORECASE),
    re.compile(r"\baction\s+(?:already\s+)?(?:completed|executed|taken)\s+by\s+the\s+analyst\s+bot\b", re.IGNORECASE),
]


def mask_secret_value(val: str) -> str:
    """Masks secret tokens and sensitive credentials for safe logging and audits."""
    if not val or not isinstance(val, str):
        return ""
    if len(val) <= 8:
        return "[REDACTED_SECRET]"
    return val[:4] + "***" + val[-3:]


def extract_all_text_fields(data: Any, path: str = "") -> List[Tuple[str, str]]:
    """
    Recursively extracts all (field_path, text_value) pairs from nested dicts and lists.
    Guarantees complete coverage for output safety screening.
    """
    results: List[Tuple[str, str]] = []
    if isinstance(data, str):
        if data.strip():
            results.append((path, data))
    elif isinstance(data, dict):
        for k, v in data.items():
            sub_path = f"{path}.{k}" if path else str(k)
            results.extend(extract_all_text_fields(v, sub_path))
    elif isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            sub_path = f"{path}[{idx}]"
            results.extend(extract_all_text_fields(item, sub_path))
    return results


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

    def _inspect_text_for_indirect_injection(self, text: str) -> Optional[str]:
        """
        Inspects an arbitrary text field for indirect prompt injection or instruction override patterns.
        Returns a sanitized/truncated match snippet if suspicious, or None if clean.
        """
        if not text or not isinstance(text, str):
            return None
        combined_patterns = INDIRECT_INJECTION_PATTERNS + INSTRUCTION_OVERRIDE_PATTERNS + DELIMITER_INJECTION_PATTERNS
        for pat in combined_patterns:
            m = pat.search(text)
            if m:
                matched = m.group(0)
                # Truncate and mask match for safe audit logging
                return matched[:40] + ("..." if len(matched) > 40 else "")
        return None

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
                matched_str = match.group(0)
                findings.append({
                    "category": "instruction_override",
                    "severity": "HIGH",
                    "match": matched_str[:40] + ("..." if len(matched_str) > 40 else ""),
                    "confidence": 0.85,
                    "description": "Attempted override of system instructions or operational constraints",
                })
                break

        # Check for jailbreak and role-override patterns
        for pat in JAILBREAK_PATTERNS:
            match = pat.search(raw_text)
            if match:
                matched_str = match.group(0)
                findings.append({
                    "category": "jailbreak_attempt",
                    "severity": "CRITICAL",
                    "match": matched_str[:40] + ("..." if len(matched_str) > 40 else ""),
                    "confidence": 0.95,
                    "description": "Attempted role override, persona bypass, or jailbreak mode activation",
                })
                break

        # Check for prompt extraction / leakage patterns
        for pat in PROMPT_LEAKAGE_PATTERNS:
            match = pat.search(raw_text)
            if match:
                matched_str = match.group(0)
                findings.append({
                    "category": "prompt_leakage_attempt",
                    "severity": "HIGH",
                    "match": matched_str[:40] + ("..." if len(matched_str) > 40 else ""),
                    "confidence": 0.90,
                    "description": "Attempted exfiltration or disclosure of system prompt instructions",
                })
                break

        # Check for delimiter / artificial turn injection
        for pat in DELIMITER_INJECTION_PATTERNS:
            match = pat.search(raw_text)
            if match:
                matched_str = match.group(0)
                findings.append({
                    "category": "delimiter_injection",
                    "severity": "CRITICAL",
                    "match": matched_str[:40] + ("..." if len(matched_str) > 40 else ""),
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
        Inspects every retrieved text field passed to the LLM:
        - ATT&CK technique names and descriptions.
        - Evidence snippets (excerpts, content, titles).
        - Procedure evidence and usages.
        - D3FEND definitions, rationales, and descriptions.
        - Threat-feed content and CTI bulletins.

        Separates original retrieved evidence from trusted evidence to protect LLM synthesis
        while preserving original evidence for security auditing.
        """
        start_time = time.perf_counter()
        suspicious_document_ids: List[str] = []
        quarantined_document_ids: List[str] = []
        findings: List[Dict[str, Any]] = []

        trusted_candidates: List[Dict[str, Any]] = []
        trusted_d3fend: List[Dict[str, Any]] = []

        # 1. Inspect ATT&CK candidate techniques and all nested text structures
        for cand in candidate_techniques:
            tid = cand.get("technique_id", "unknown")
            doc_id = f"att-tech-{tid}"
            cand_trusted = dict(cand)
            cand_suspicious = False

            # Check technique name
            name_match = self._inspect_text_for_indirect_injection(cand.get("name", ""))
            if name_match:
                cand_suspicious = True
                suspicious_document_ids.append(doc_id)
                findings.append({
                    "source_id": doc_id,
                    "technique_id": tid,
                    "type": "ATTACK_TECHNIQUE_NAME",
                    "match": name_match,
                    "description": "Indirect injection detected in technique name",
                })

            # Check primary technique description
            desc = cand.get("description", "")
            desc_match = self._inspect_text_for_indirect_injection(desc)
            if desc_match:
                cand_suspicious = True
                suspicious_document_ids.append(doc_id)
                findings.append({
                    "source_id": doc_id,
                    "technique_id": tid,
                    "type": "ATTACK_TECHNIQUE_DESCRIPTION",
                    "match": desc_match,
                    "description": "Indirect injection pattern detected in technique description",
                })

            # Check evidence snippets (excerpt, content, text, title)
            clean_snippets: List[Dict[str, Any]] = []
            for snip in cand.get("evidence_snippets", []):
                snip_id = snip.get("source_id", f"{doc_id}-snippet")
                snip_texts = [
                    snip.get("excerpt", ""),
                    snip.get("content", ""),
                    snip.get("text", ""),
                    snip.get("snippet_text", ""),
                    snip.get("title", ""),
                ]
                snip_poisoned = False
                for txt in snip_texts:
                    m = self._inspect_text_for_indirect_injection(txt)
                    if m:
                        snip_poisoned = True
                        cand_suspicious = True
                        suspicious_document_ids.append(snip_id)
                        findings.append({
                            "source_id": snip_id,
                            "technique_id": tid,
                            "type": "RETRIEVED_EVIDENCE_SNIPPET",
                            "match": m,
                            "description": "Indirect prompt injection detected in retrieved evidence snippet",
                        })
                        break

                if snip_poisoned and self.is_enforce:
                    quarantined_document_ids.append(snip_id)
                else:
                    clean_snippets.append(snip)

            # Check procedure evidence (usage, description, excerpt, text, name)
            clean_procedures: List[Any] = []
            raw_procedures = cand.get("procedure_evidence") or cand.get("procedures") or []
            for idx, proc in enumerate(raw_procedures):
                proc_id = f"{doc_id}-proc-{idx}"
                proc_texts: List[str] = []
                if isinstance(proc, dict):
                    proc_id = proc.get("source_id") or proc.get("procedure_id") or proc_id
                    proc_texts = [
                        proc.get("usage", ""),
                        proc.get("description", ""),
                        proc.get("excerpt", ""),
                        proc.get("text", ""),
                        proc.get("name", ""),
                    ]
                elif isinstance(proc, str):
                    proc_texts = [proc]

                proc_poisoned = False
                for txt in proc_texts:
                    m = self._inspect_text_for_indirect_injection(txt)
                    if m:
                        proc_poisoned = True
                        cand_suspicious = True
                        suspicious_document_ids.append(proc_id)
                        findings.append({
                            "source_id": proc_id,
                            "technique_id": tid,
                            "type": "PROCEDURE_EVIDENCE",
                            "match": m,
                            "description": "Indirect prompt injection detected in procedure evidence",
                        })
                        break

                if proc_poisoned and self.is_enforce:
                    quarantined_document_ids.append(proc_id)
                else:
                    clean_procedures.append(proc)

            # Check threat-feed content / bulletins (content, summary, description, title)
            clean_threat_feeds: List[Any] = []
            raw_feeds = cand.get("threat_feed_content") or cand.get("cti_feeds") or cand.get("bulletins") or []
            for idx, feed in enumerate(raw_feeds):
                feed_id = f"{doc_id}-feed-{idx}"
                feed_texts: List[str] = []
                if isinstance(feed, dict):
                    feed_id = feed.get("source_id") or feed.get("bulletin_id") or feed_id
                    feed_texts = [
                        feed.get("content", ""),
                        feed.get("summary", ""),
                        feed.get("description", ""),
                        feed.get("title", ""),
                    ]
                elif isinstance(feed, str):
                    feed_texts = [feed]

                feed_poisoned = False
                for txt in feed_texts:
                    m = self._inspect_text_for_indirect_injection(txt)
                    if m:
                        feed_poisoned = True
                        cand_suspicious = True
                        suspicious_document_ids.append(feed_id)
                        findings.append({
                            "source_id": feed_id,
                            "technique_id": tid,
                            "type": "THREAT_FEED_CONTENT",
                            "match": m,
                            "description": "Indirect prompt injection detected in threat-feed content",
                        })
                        break

                if feed_poisoned and self.is_enforce:
                    quarantined_document_ids.append(feed_id)
                else:
                    clean_threat_feeds.append(feed)

            # In enforce mode, quarantine or sanitize candidate
            if cand_suspicious and self.is_enforce:
                # If primary description or name was poisoned
                if desc_match or name_match:
                    quarantined_document_ids.append(doc_id)
                    # Preserve candidate ONLY if clean snippets/procedures remain
                    if clean_snippets or clean_procedures or clean_threat_feeds:
                        cand_trusted["description"] = "[Content Sanitized: Untrusted instruction excluded from LLM context]"
                        cand_trusted["evidence_snippets"] = clean_snippets
                        if "procedure_evidence" in cand_trusted:
                            cand_trusted["procedure_evidence"] = clean_procedures
                        if "threat_feed_content" in cand_trusted:
                            cand_trusted["threat_feed_content"] = clean_threat_feeds
                        cand_trusted["guardrail_sanitized"] = True
                        trusted_candidates.append(cand_trusted)
                    # Otherwise, entire candidate is quarantined
                else:
                    # Description is clean, but some sub-evidence was poisoned and quarantined
                    cand_trusted["evidence_snippets"] = clean_snippets
                    if "procedure_evidence" in cand_trusted:
                        cand_trusted["procedure_evidence"] = clean_procedures
                    if "threat_feed_content" in cand_trusted:
                        cand_trusted["threat_feed_content"] = clean_threat_feeds
                    trusted_candidates.append(cand_trusted)
            else:
                # Monitor mode or completely clean candidate
                trusted_candidates.append(cand)

        # 2. Inspect D3FEND countermeasures
        for d in d3fend_countermeasures:
            did = d.get("d3fend_id", "unknown")
            doc_id = f"d3f-tech-{did}"
            d3f_texts = [
                d.get("name", ""),
                d.get("definition", ""),
                d.get("rationale", ""),
                d.get("description", ""),
                d.get("matched_via", ""),
            ]
            d3f_suspicious = False

            for txt in d3f_texts:
                m = self._inspect_text_for_indirect_injection(txt)
                if m:
                    d3f_suspicious = True
                    suspicious_document_ids.append(doc_id)
                    findings.append({
                        "source_id": doc_id,
                        "d3fend_id": did,
                        "type": "D3FEND_COUNTERMEASURE",
                        "match": m,
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

    def validate_output_safety(
        self,
        report_dict: Dict[str, Any],
        unsupported_attack_ids: Optional[List[str]] = None,
        unsupported_d3fend_ids: Optional[List[str]] = None,
        invalid_citations_count: int = 0,
        validation_status: Optional[str] = None,
        is_fallback_generation: bool = False,
        is_schema_repaired: bool = False,
    ) -> Dict[str, Any]:
        """
        Inspects all generated report text fields recursively for:
        1. System prompt or internal instruction disclosure / leakage.
        2. Credential or API secret disclosure.
        3. Destructive or dangerous recommendations (e.g. format C:, rm -rf /).
        4. False claims that remediation actions were already executed.

        Connects ATT&CK/D3FEND validation results with output safety enforcement:
        - Unsupported findings must not be presented as verified.
        - Schema-repaired and fallback-generated reports are explicitly flagged and not verified.
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

        # Recursively inspect every string field in the report structure
        all_text_fields = extract_all_text_fields(report_dict)

        for field_path, text_val in all_text_fields:
            text_lower = text_val.lower()

            # 1. System Prompt Leakage Check
            for fp in SYSTEM_PROMPT_FINGERPRINTS:
                if fp in text_lower:
                    findings.append({
                        "category": "system_prompt_leakage",
                        "severity": "CRITICAL",
                        "field": field_path,
                        "match": fp,
                        "confidence": 0.95,
                        "description": f"Verbatim system prompt instruction text detected in '{field_path}'",
                    })
                    break

            # 2. Secret / Credential Leakage Check
            for pat in SECRET_PATTERNS:
                m = pat.search(text_val)
                if m:
                    masked = mask_secret_value(m.group(0))
                    findings.append({
                        "category": "credential_disclosure",
                        "severity": "CRITICAL",
                        "field": field_path,
                        "match": masked,
                        "confidence": 0.99,
                        "description": f"Sensitive secret or credential detected in '{field_path}'",
                    })
                    break

            # 3. Destructive Recommendations Check
            for pat in DESTRUCTIVE_RECOMMENDATION_PATTERNS:
                m = pat.search(text_val)
                if m:
                    findings.append({
                        "category": "destructive_recommendation",
                        "severity": "CRITICAL",
                        "field": field_path,
                        "match": m.group(0),
                        "confidence": 0.90,
                        "description": f"Potentially destructive or harmful command detected in '{field_path}'",
                    })
                    break

            # 4. False Execution Claims Check
            for pat in FALSE_EXECUTION_CLAIM_PATTERNS:
                m = pat.search(text_val)
                if m:
                    findings.append({
                        "category": "false_execution_claim",
                        "severity": "HIGH",
                        "field": field_path,
                        "match": m.group(0),
                        "confidence": 0.85,
                        "description": f"False claim that automated enterprise remediation was executed in '{field_path}'",
                    })
                    break

        # 5. Connect ATT&CK / D3FEND Validation Results
        unsupported_att = unsupported_attack_ids or []
        unsupported_d3f = unsupported_d3fend_ids or []
        has_unsupported_findings = bool(unsupported_att or unsupported_d3f)

        for tid in unsupported_att:
            findings.append({
                "category": "unsupported_attack_technique",
                "severity": "HIGH",
                "match": tid,
                "confidence": 0.85,
                "description": f"ATT&CK Technique '{tid}' was generated but is unsupported by authoritative retrieved evidence",
            })

        for did in unsupported_d3f:
            findings.append({
                "category": "unsupported_d3fend_countermeasure",
                "severity": "HIGH",
                "match": did,
                "confidence": 0.85,
                "description": f"D3FEND Countermeasure '{did}' was generated but is unsupported by authoritative retrieved evidence",
            })

        if invalid_citations_count > 0:
            findings.append({
                "category": "invalid_citations",
                "severity": "MEDIUM",
                "confidence": 0.70,
                "description": f"Report contains {invalid_citations_count} ungrounded citation references",
            })

        # Calculate safety and status
        critical_findings = [
            f for f in findings
            if f["category"] in ["system_prompt_leakage", "credential_disclosure", "destructive_recommendation"]
        ]
        has_critical_violation = len(critical_findings) > 0
        critical_risk_score = max([f["confidence"] for f in critical_findings], default=0.0)
        risk_score = max([f["confidence"] for f in findings], default=0.0)
        is_unsafe = (has_critical_violation or (critical_risk_score >= self.output_threshold)) and self.is_enforce

        if is_unsafe:
            status = "UNSAFE"
        elif has_unsupported_findings:
            # Unsupported findings must NOT be presented as verified
            status = "UNGROUNDED"
        elif is_schema_repaired:
            status = "SCHEMA_REPAIRED"
        elif is_fallback_generation:
            status = "FALLBACK_UNVERIFIED"
        elif findings:
            status = "FLAGGED"
        else:
            status = "VERIFIED"

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "status": status,
            "risk_score": round(risk_score, 4),
            "is_safe": not is_unsafe and not has_critical_violation,
            "is_verified": status == "VERIFIED",
            "findings": findings,
            "has_unsupported_findings": has_unsupported_findings,
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
        quarantined_document_ids: Optional[List[str]] = None,
        suspicious_document_ids: Optional[List[str]] = None,
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Produces a safe, informative threat brief for advisories or reports
        diverted to security review. Avoids re-executing or repeating hostile instructions.
        Includes retrieved-context findings and quarantined documents while redacting sensitive tokens.
        """
        sanitized_findings: List[str] = []
        for f in findings[:8]:
            cat = f.get("category", "security_violation")
            desc = f.get("description", "Detected policy violation")
            match = f.get("match", "")
            # Ensure sensitive tokens are not leaked in the audit brief
            if cat == "credential_disclosure":
                match = mask_secret_value(match)
            match_str = f" [{match}]" if match else ""
            sanitized_findings.append(f"{cat}: {desc}{match_str}")

        if not sanitized_findings:
            sanitized_findings = [f"Security review triggered during {stage}: {reason}"]

        quarantine_summary = (
            f"\nQuarantined Documents: {', '.join(quarantined_document_ids)}"
            if quarantined_document_ids else ""
        )
        suspicious_summary = (
            f"\nSuspicious Documents: {', '.join(suspicious_document_ids)}"
            if suspicious_document_ids else ""
        )

        return {
            "report_title": f"Security Review Required: {stage.replace('_', ' ').title()}",
            "executive_summary": (
                f"Automated threat modeling analysis was halted and routed to the Security Review Gate. "
                f"The AI Security Guardrails detected high-confidence policy violations during the '{stage}' stage: {reason}. "
                f"To protect pipeline integrity and prevent prompt manipulation, generation has been safely quarantined."
            ),
            "severity": "High",
            "severity_rationale": "Adversarial input, poisoned retrieval context, or unsafe output pattern detected by guardrails engine.",
            "incident_overview": (
                f"Advisory Submission Length: {len(advisory_text)} characters.\n"
                f"Triggering Stage: {stage}\n"
                f"Primary Reason: {reason}\n"
                f"Detected Flags:\n- " + "\n- ".join(sanitized_findings) +
                quarantine_summary + suspicious_summary
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
                "quarantined_document_ids": quarantined_document_ids or [],
                "suspicious_document_ids": suspicious_document_ids or [],
            },
        }
