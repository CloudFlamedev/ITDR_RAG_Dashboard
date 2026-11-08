import base64
import hashlib
import hmac
import secrets
import time
from typing import Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from app.core.config import get_settings

settings = get_settings()

# Initialize Argon2id password hasher with secure defaults
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Constant-time comparison protected against timing attacks.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False


def generate_session_token() -> Tuple[str, str]:
    """
    Generate a cryptographically secure random session token and its SHA-256 hash.
    Returns:
        (raw_token, token_hash)
        - raw_token is sent to the client in an HttpOnly cookie.
        - token_hash is stored in the PostgreSQL user_sessions table.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)
    return raw_token, token_hash


def hash_session_token(raw_token: str) -> str:
    """Compute deterministic SHA-256 hash of a session token for storage and lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_csrf_token(session_id: str) -> str:
    """
    Generate an HMAC-SHA256 signed CSRF token tied to the user's session identifier.
    Format: timestamp.signature
    """
    ts = str(int(time.time()))
    payload = f"{session_id}:{ts}".encode("utf-8")
    sig = hmac.new(settings.SESSION_SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def verify_csrf_token(session_id: str, csrf_token: str, max_age_seconds: int = 86400) -> bool:
    """Verify validity, expiration, and signature of an incoming CSRF token."""
    if not csrf_token or "." not in csrf_token:
        return False

    parts = csrf_token.split(".", 1)
    if len(parts) != 2:
        return False

    ts_str, provided_sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return False

    # Check expiration (default 24h)
    if time.time() - ts > max_age_seconds:
        return False

    payload = f"{session_id}:{ts_str}".encode("utf-8")
    expected_sig = hmac.new(settings.SESSION_SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, provided_sig)


def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge using RFC 7636 S256.
    Returns (code_verifier, code_challenge).
    """
    # 32 bytes URL-safe string is 43 characters, satisfying 43 <= len <= 128
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def generate_oauth_state(provider: str) -> str:
    """
    Generate a tamper-proof signed state token for OAuth flows.
    Format: provider.nonce.timestamp.hmac
    """
    nonce = secrets.token_urlsafe(16)
    ts = str(int(time.time()))
    raw = f"{provider}:{nonce}:{ts}".encode("utf-8")
    sig = hmac.new(settings.SESSION_SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return f"{provider}.{nonce}.{ts}.{sig}"


def verify_oauth_state(provider: str, state: str, max_age_seconds: int = 600) -> bool:
    """Verify an incoming OAuth state string against expiration and signature."""
    if not state or "." not in state:
        return False

    parts = state.split(".")
    if len(parts) != 4:
        return False

    prov, nonce, ts_str, provided_sig = parts
    if prov != provider:
        return False

    try:
        ts = int(ts_str)
    except ValueError:
        return False

    if time.time() - ts > max_age_seconds:
        return False

    raw = f"{prov}:{nonce}:{ts_str}".encode("utf-8")
    expected_sig = hmac.new(settings.SESSION_SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, provided_sig)
