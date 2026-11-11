import re
import logging
import datetime
from typing import Any, Dict, List, Optional, Union
from app.core.config import get_settings

logger = logging.getLogger("itdr-telemetry")
settings = get_settings()

# Sync environment variables for Langfuse SDK
import os
if settings.LANGFUSE_PUBLIC_KEY and "LANGFUSE_PUBLIC_KEY" not in os.environ:
    os.environ["LANGFUSE_PUBLIC_KEY"] = settings.LANGFUSE_PUBLIC_KEY
if settings.LANGFUSE_SECRET_KEY and "LANGFUSE_SECRET_KEY" not in os.environ:
    os.environ["LANGFUSE_SECRET_KEY"] = settings.LANGFUSE_SECRET_KEY
if settings.effective_langfuse_host and "LANGFUSE_BASE_URL" not in os.environ:
    os.environ["LANGFUSE_BASE_URL"] = settings.effective_langfuse_host
if settings.effective_langfuse_host and "LANGFUSE_HOST" not in os.environ:
    os.environ["LANGFUSE_HOST"] = settings.effective_langfuse_host

# Import Langfuse components
from langfuse import get_client, observe, propagate_attributes
from langfuse.langchain import CallbackHandler

# Initialize singleton client
langfuse_client = get_client()

# ==============================================================================
# Security & Privacy Guardrails: Data Masking & Hash Redaction
# ==============================================================================

SENSITIVE_PATTERNS = [
    # Argon2id password hashes
    (re.compile(r"\$argon2[a-z0-9$,=./+]+", re.IGNORECASE), "[REDACTED_ARGON2_HASH]"),
    # Bcrypt hashes
    (re.compile(r"\$2[aby]\$\d{2}\$[^\s,\"'\)]+", re.IGNORECASE), "[REDACTED_BCRYPT_HASH]"),
    # Kerberos tickets & hashes (krb5tgs / krb5asrep)
    (re.compile(r"\$krb5(?:tgs|asrep)\$[^\s,\"'\)]+", re.IGNORECASE), "[REDACTED_KERBEROS_HASH]"),
    # Active Directory NTLM / LM password hashes (32-hex characters or lm:ntlm pairs)
    (re.compile(r"(?i)(?:aad3b435b51404eeaad3b435b51404ee:)?[a-f0-9]{32}"), "[REDACTED_NTLM_HASH]"),
    # Clear-text passwords in key-value or query patterns
    (re.compile(r"(?i)(password|passwd|pwd)\s*([:=])\s*([^\s,;\"']+)"), r"\1\2[REDACTED_PASSWORD]"),
    # Bearer authorization tokens
    (re.compile(r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{16,})"), r"\1[REDACTED_TOKEN]"),
    # Session cookies & CSRF tokens
    (re.compile(r"(?i)(itdr_session|session_token|csrf_token)\s*([:=])\s*([a-zA-Z0-9_\-\.]{16,})"), r"\1\2[REDACTED_TOKEN]"),
    # API & Secret Keys
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|hf_token)\s*([:=])\s*([a-zA-Z0-9_\-\.]{16,})"), r"\1\2[REDACTED_SECRET]"),
]


def mask_sensitive_data(payload: Any) -> Any:
    """
    Recursively redacts plain-text session tokens, passwords, Active Directory
    hashes (NTLM, Kerberos), and authentication secrets before logging to Langfuse spans.
    """
    if isinstance(payload, str):
        masked = payload
        for pattern, replacement in SENSITIVE_PATTERNS:
            masked = pattern.sub(replacement, masked)
        return masked
    elif isinstance(payload, dict):
        return {k: mask_sensitive_data(v) for k, v in payload.items()}
    elif isinstance(payload, list):
        return [mask_sensitive_data(item) for item in payload]
    elif isinstance(payload, tuple):
        return tuple(mask_sensitive_data(item) for item in payload)
    return payload


# ==============================================================================
# Telemetry Lifecycle & Score Helpers
# ==============================================================================

def check_telemetry_auth() -> bool:
    """Run an authentication check against the Langfuse API endpoint."""
    if not settings.has_langfuse_credentials:
        logger.info("Langfuse credentials not configured; auth check skipped.")
        return False
    try:
        is_ok = bool(langfuse_client.auth_check())
        return is_ok
    except Exception as e:
        logger.warning(f"Langfuse auth check failed: {e}")
        return False


def flush_telemetry() -> None:
    """Flush pending buffered telemetry events to Langfuse before shutdown."""
    try:
        langfuse_client.flush()
        logger.debug("Langfuse telemetry buffer flushed.")
    except Exception as e:
        logger.warning(f"Error during Langfuse telemetry flush: {e}")


def get_current_trace_id() -> Optional[str]:
    """Retrieve the current active trace ID if running inside a Langfuse trace context."""
    try:
        return langfuse_client.get_current_trace_id()
    except Exception:
        return None


def log_threat_score(
    name: str,
    value: Union[float, str],
    trace_id: Optional[str] = None,
    comment: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Safely record an evaluation score on the active Langfuse trace.
    Supports threat_confidence (numeric 0.0-1.0) and threat_severity (categorical).
    """
    active_trace_id = trace_id or get_current_trace_id()
    if not active_trace_id:
        return False

    try:
        # Determine numeric vs categorical
        data_type = "NUMERIC" if isinstance(value, (int, float)) else "CATEGORICAL"
        langfuse_client.create_score(
            trace_id=active_trace_id,
            name=name,
            value=value,
            data_type=data_type,
            comment=comment or "Automated ITDR assessment",
            metadata=metadata or {},
        )
        return True
    except Exception as e:
        logger.debug(f"Langfuse score creation skipped ({name}): {e}")
        return False
