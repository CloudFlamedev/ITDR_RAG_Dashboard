import time
import re
import datetime
from typing import Dict, Any
from app.ai.state import ThreatAnalysisState

# Regex patterns for threat telemetry indicators
ACCOUNT_PATTERN = re.compile(r"\b(?:USER_[A-Z0-9_]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}|admin(?:istrator)?|svc_[a-zA-Z0-9_]+)\b", re.IGNORECASE)
HOST_PATTERN = re.compile(r"\b(?:DC-[A-Z0-9_-]+|WKSTN-[A-Z0-9_-]+|SRV-[A-Z0-9_-]+|[a-zA-Z0-9-]+\.(?:corp|internal|local|com))\b", re.IGNORECASE)
ATTACK_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
D3FEND_ID_PATTERN = re.compile(r"\b(D3(?:A)?-[A-Z0-9]+)\b", re.IGNORECASE)


def validate_input(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 1: Validates incoming advisory text and initializes trace timing.
    Ensures text contains meaningful technical description and rejects malformed payloads.
    """
    start = time.perf_counter()
    text = (state.get("advisory_text") or "").strip()

    trace_step = {
        "step_name": "validate_input",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "metadata": {"char_count": len(text), "word_count": len(text.split())},
        "error": None,
    }

    if not text:
        trace_step["status"] = "FAILED"
        trace_step["error"] = "Advisory text cannot be empty"
        trace_step["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "ERROR",
            "error": "Advisory text cannot be empty",
            "trace_steps": state.get("trace_steps", []) + [trace_step],
        }

    trace_step["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
    return {
        "status": "PROCESSING",
        "advisory_text": text,
        "trace_steps": state.get("trace_steps", []) + [trace_step],
    }


def extract_entities_and_indicators(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 2: Safely extracts explicit ATT&CK TTPs, D3FEND IDs, accounts, hostnames,
    and attack tool mentions without executing or interpreting hostile commands.
    """
    start = time.perf_counter()
    text = state["advisory_text"]

    attack_ids = sorted(list(set(ATTACK_ID_PATTERN.findall(text))))
    d3fend_ids = sorted(list(set(D3FEND_ID_PATTERN.findall(text))))
    accounts = sorted(list(set(ACCOUNT_PATTERN.findall(text))))[:10]
    hosts = sorted(list(set(HOST_PATTERN.findall(text))))[:10]

    # Detect known security keywords
    keywords = []
    for kw in ["lsass", "powershell", "mimikatz", "kerberoast", "dcsync", "mfa", "saml", "oauth", "token"]:
        if kw in text.lower():
            keywords.append(kw)

    indicators = {
        "attack_ids": attack_ids,
        "d3fend_ids": d3fend_ids,
        "accounts": accounts,
        "hosts": hosts,
        "security_keywords": keywords,
    }

    trace_step = {
        "step_name": "extract_entities_and_indicators",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {
            "attack_ids_found": len(attack_ids),
            "accounts_found": len(accounts),
            "hosts_found": len(hosts),
            "keywords": keywords,
        },
        "error": None,
    }

    return {
        "extracted_indicators": indicators,
        "trace_steps": state["trace_steps"] + [trace_step],
    }


def build_retrieval_query(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    Node 3: Constructs targeted semantic search queries augmenting the original advisory
    with extracted technical indicators for optimal vector recall.
    """
    start = time.perf_counter()
    text = state["advisory_text"]
    ind = state.get("extracted_indicators", {})

    query_parts = [text[:400]]
    if ind.get("attack_ids"):
        query_parts.append(" ".join(ind["attack_ids"]))
    if ind.get("security_keywords"):
        query_parts.append(" ".join(ind["security_keywords"]))

    augmented_query = " ".join(query_parts)

    trace_step = {
        "step_name": "build_retrieval_query",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "SUCCESS",
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "metadata": {"query_length": len(augmented_query)},
        "error": None,
    }

    return {
        "retrieval_query": augmented_query,
        "trace_steps": state["trace_steps"] + [trace_step],
    }
