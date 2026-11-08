import datetime
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    generate_csrf_token,
    generate_pkce_pair,
    generate_oauth_state,
    verify_oauth_state,
)
from app.db.session import get_db
from app.models.auth import User, UserSession
from app.services.auth_service import AuthService
from app.services.oauth_service import oauth_service
from app.api.deps import get_current_user_and_session, get_current_user

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str


class UserSummary(BaseModel):
    id: int
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    roles: List[str]
    permissions: List[str]
    last_login_at: Optional[datetime.datetime] = None
    created_at: Optional[datetime.datetime] = None


class LoginResponse(BaseModel):
    user: UserSummary
    csrf_token: str
    token: Optional[str] = None
    message: str = "Authenticated successfully."


class StatusMessage(BaseModel):
    message: str


# ------------------------------------------------------------------------------
# Helper: Cookie Management
# ------------------------------------------------------------------------------

from urllib.parse import urlparse
import ipaddress


def get_allowed_hosts() -> set[str]:
    """
    Extract set of allowed hostnames (with optional port) from CORS origins and FRONTEND_URL.
    """
    allowed = set()
    for origin in settings.cors_origins:
        parsed = urlparse(origin)
        if parsed.netloc:
            allowed.add(parsed.netloc.lower())
    if settings.FRONTEND_URL:
        parsed = urlparse(settings.FRONTEND_URL)
        if parsed.netloc:
            allowed.add(parsed.netloc.lower())
    return allowed


def get_browser_facing_origin(request: Request) -> str:
    """
    Safely resolve the browser-facing origin.
    Only trusts X-Forwarded-Host or Host if they strictly match the explicit CORS/FRONTEND_URL allowlist.
    Prevents host header injection and open redirect attacks. Direct requests to backend cannot forge redirect.
    """
    allowed_hosts = get_allowed_hosts()

    # 1. Check X-Forwarded-Host against strict allowlist
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("X-Forwarded-Host")
    forwarded_proto = request.headers.get("x-forwarded-proto") or request.headers.get("X-Forwarded-Proto") or "https"

    if forwarded_host:
        candidate_host = forwarded_host.split(",")[0].strip().lower()
        if candidate_host in allowed_hosts:
            proto = "https"
            if forwarded_proto.lower() == "http" and ("localhost" in candidate_host or "127.0.0.1" in candidate_host) and not settings.is_production:
                proto = "http"
            return f"{proto}://{candidate_host}"
        else:
            logger.warning(
                f"Security warning: Rejected untrusted X-Forwarded-Host '{candidate_host}' "
                f"(not in allowed hosts: {allowed_hosts})"
            )

    # 2. Check direct Host header against strict allowlist
    host_header = request.headers.get("host", "").strip().lower()
    if host_header and host_header in allowed_hosts:
        proto = "https"
        if ("localhost" in host_header or "127.0.0.1" in host_header) and not settings.is_production:
            proto = "http"
        return f"{proto}://{host_header}"

    # 3. Safe fallback: environment-configured FRONTEND_URL or first HTTPS CORS origin
    if settings.FRONTEND_URL and settings.FRONTEND_URL.strip():
        return settings.FRONTEND_URL.strip().rstrip("/")

    for origin in settings.cors_origins:
        if origin.startswith("https://"):
            return origin.rstrip("/")

    if settings.cors_origins:
        return settings.cors_origins[0].rstrip("/")

    return "http://localhost:5173"


def set_auth_cookies(response: Response, raw_session_token: str, csrf_token: str):
    """Set secure session and CSRF cookies on the response."""
    max_age = settings.SESSION_EXPIRE_MINUTES * 60
    is_secure = settings.SESSION_COOKIE_SECURE or settings.is_production

    # Primary HttpOnly session cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_session_token,
        max_age=max_age,
        expires=max_age,
        path="/",
        secure=is_secure,
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )

    # CSRF cookie accessible to frontend JavaScript for header inclusion
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        expires=max_age,
        path="/",
        secure=is_secure,
        httponly=False,  # Frontend reads this to send in X-CSRF-Token header
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


def clear_auth_cookies(response: Response):
    """Clear session and CSRF cookies."""
    is_secure = settings.SESSION_COOKIE_SECURE or settings.is_production
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        secure=is_secure,
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        secure=is_secure,
        httponly=False,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except (ValueError, AttributeError):
        return False


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except (ValueError, AttributeError):
        return False


def get_client_ip(request: Request) -> str:
    """
    Extract verified client IP address handling reverse proxies (Vercel, Cloudflare, Nginx).
    Prioritizes X-Real-IP (injected by outermost edge proxy), then checks X-Forwarded-For,
    sanitizing and validating the IP format to prevent spoofing or injection.
    """
    # 1. X-Real-IP (trusted header set by edge reverse proxies such as Vercel)
    real_ip = request.headers.get("x-real-ip") or request.headers.get("X-Real-IP")
    if real_ip:
        clean_ip = real_ip.strip()
        if is_valid_ip(clean_ip):
            return clean_ip

    # 2. X-Forwarded-For (parse list, prioritize leftmost valid public IP)
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        for p in parts:
            if is_public_ip(p):
                return p
        for p in parts:
            if is_valid_ip(p):
                return p

    # 3. Direct socket peer host
    if request.client and request.client.host:
        clean_host = request.client.host.strip()
        if is_valid_ip(clean_host):
            return clean_host

    return "127.0.0.1"


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    include_token: bool = Query(default=False, description="Optionally include raw Bearer token in response body for CLI/API clients"),
):
    """
    Authenticate user using email and password (Argon2id).
    Enforces rate-limiting, rotates existing session identifiers,
    and issues a secure server-managed session in an HttpOnly cookie.
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    auth_svc = AuthService(db)

    # 1. Session Rotation: Revoke any existing active session before issuing a new one
    old_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if old_cookie:
        auth_svc.revoke_session(old_cookie)

    # 2. Authenticate credentials
    user = auth_svc.authenticate_user(
        email=payload.email,
        password=payload.password,
        ip_address=client_ip,
    )

    # 3. Create server session persisted in PostgreSQL
    raw_token, session = auth_svc.create_session(
        user=user,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    # 4. Generate HMAC CSRF token tied to session ID
    csrf_token = generate_csrf_token(str(session.id))
    set_auth_cookies(response, raw_token, csrf_token)

    return LoginResponse(
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            roles=user.role_names,
            permissions=user.permission_keys,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
        ),
        csrf_token=csrf_token,
        token=raw_token if include_token else None,
    )


@router.post("/logout", response_model=StatusMessage)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Revoke active session in PostgreSQL and delete session cookies.
    """
    raw_token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()

    if not raw_token:
        raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)

    if raw_token:
        auth_svc = AuthService(db)
        auth_svc.revoke_session(raw_token)

    clear_auth_cookies(response)
    return StatusMessage(message="Logged out successfully.")


@router.get("/me", response_model=LoginResponse)
def get_current_user_profile(
    response: Response,
    auth_data=Depends(get_current_user_and_session),
):
    """
    Retrieve authenticated user profile, roles, permissions, and active CSRF token.
    """
    user, session, _ = auth_data
    csrf_token = generate_csrf_token(str(session.id))

    # Keep CSRF cookie updated
    is_secure = settings.SESSION_COOKIE_SECURE or settings.is_production
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/",
        secure=is_secure,
        httponly=False,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )

    return LoginResponse(
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            roles=user.role_names,
            permissions=user.permission_keys,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
        ),
        csrf_token=csrf_token,
        token="",  # Not re-exposing raw token on profile checks
        message="Session active",
    )


@router.get("/csrf")
def get_csrf(
    response: Response,
    auth_data=Depends(get_current_user_and_session),
):
    """
    Obtain a fresh CSRF token tied to the current active session.
    """
    _, session, _ = auth_data
    csrf_token = generate_csrf_token(str(session.id))
    is_secure = settings.SESSION_COOKIE_SECURE or settings.is_production
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/",
        secure=is_secure,
        httponly=False,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    return {"csrf_token": csrf_token}


# ------------------------------------------------------------------------------
# Social Login / OAuth Endpoints
# ------------------------------------------------------------------------------

@router.get("/oauth/{provider}/login")
def oauth_login(
    provider: str,
    request: Request,
    response: Response,
):
    """
    Initiate third-party OAuth flow with CSRF state protection and PKCE (S256).
    """
    provider = provider.lower()
    if provider not in ("google", "github"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: '{provider}'. Supported providers: google, github",
        )

    state = generate_oauth_state(provider)
    is_secure = settings.SESSION_COOKIE_SECURE or settings.is_production
    origin = get_browser_facing_origin(request)
    env_redirect = getattr(settings, f"{provider.upper()}_REDIRECT_URI", None)
    if env_redirect and str(env_redirect).strip():
        redirect_uri = str(env_redirect).strip()
    else:
        redirect_uri = f"{origin}/api/auth/oauth/{provider}/callback"

    # Set state in a short-lived cookie for validation on callback
    redirect_resp: RedirectResponse

    if provider == "google":
        code_verifier, code_challenge = generate_pkce_pair()
        auth_url = oauth_service.get_google_auth_url(state=state, code_challenge=code_challenge, redirect_uri=redirect_uri)
        redirect_resp = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
        # Store code_verifier in secure cookie for token exchange
        redirect_resp.set_cookie(
            key="itdr_pkce_verifier",
            value=code_verifier,
            max_age=600,
            path="/",
            secure=is_secure,
            httponly=True,
            samesite="lax",
        )
    else:  # github
        auth_url = oauth_service.get_github_auth_url(state=state, redirect_uri=redirect_uri)
        redirect_resp = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)

    # Set state cookie
    redirect_resp.set_cookie(
        key="itdr_oauth_state",
        value=state,
        max_age=600,
        path="/",
        secure=is_secure,
        httponly=True,
        samesite="lax",
    )
    return redirect_resp


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    """
    Handle OAuth callback from Google or GitHub:
    - Verifies CSRF state token
    - Exchanges authorization code for verified identity
    - Links to existing user account (or provisions if allowed)
    - Establishes authenticated server session
    - Redirects to frontend application
    """
    provider = provider.lower()
    if provider not in ("google", "github"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: '{provider}'",
        )

    # Resolve frontend base URL from request host / reverse proxy / CORS whitelist
    frontend_origin = get_browser_facing_origin(request)
    env_redirect = getattr(settings, f"{provider.upper()}_REDIRECT_URI", None)
    if env_redirect and str(env_redirect).strip():
        redirect_uri = str(env_redirect).strip()
    else:
        redirect_uri = f"{frontend_origin}/api/auth/oauth/{provider}/callback"

    # 1. Handle error returned by OAuth provider (e.g., user clicked cancel)
    if error:
        err_msg = error_description or error or "OAuth authorization failed"
        logger.warning(f"OAuth error from {provider}: {err_msg}")
        return RedirectResponse(
            url=f"{frontend_origin}/login?error={err_msg}",
            status_code=status.HTTP_302_FOUND,
        )

    if not code or not state:
        return RedirectResponse(
            url=f"{frontend_origin}/login?error=Missing+OAuth+code+or+state",
            status_code=status.HTTP_302_FOUND,
        )

    # 2. Validate state token (anti-CSRF)
    state_cookie = request.cookies.get("itdr_oauth_state")
    if not verify_oauth_state(provider, state) or state != state_cookie:
        logger.warning(f"OAuth state mismatch or expired for {provider}")
        return RedirectResponse(
            url=f"{frontend_origin}/login?error=Invalid+or+expired+OAuth+session.+Please+try+again.",
            status_code=status.HTTP_302_FOUND,
        )

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # 3. Exchange code with provider
    try:
        if provider == "google":
            code_verifier = request.cookies.get("itdr_pkce_verifier")
            if not code_verifier:
                return RedirectResponse(
                    url=f"{frontend_origin}/login?error=Missing+PKCE+verifier.+Please+retry+login.",
                    status_code=status.HTTP_302_FOUND,
                )
            oauth_user = await oauth_service.exchange_google_code(code, code_verifier, redirect_uri=redirect_uri)
        else:  # github
            oauth_user = await oauth_service.exchange_github_code(code, redirect_uri=redirect_uri)

        # 4. Resolve / Link User in Database
        auth_svc = AuthService(db)
        user = auth_svc.handle_oauth_user(
            provider=oauth_user.provider,
            provider_user_id=oauth_user.provider_user_id,
            verified_email=oauth_user.email,
            full_name=oauth_user.full_name,
            ip_address=client_ip,
        )

        # 5. Create Server Session
        raw_token, session = auth_svc.create_session(
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        csrf_token = generate_csrf_token(str(session.id))

        # 6. Redirect to frontend with auth cookies set
        redirect_url = f"{frontend_origin}/auth/callback?status=success"
        response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
        set_auth_cookies(response, raw_token, csrf_token)

        # Clear temporary OAuth cookies
        response.delete_cookie("itdr_oauth_state", path="/")
        response.delete_cookie("itdr_pkce_verifier", path="/")

        return response

    except HTTPException as e:
        logger.warning(f"OAuth login failed for {provider}: {e.detail}")
        response = RedirectResponse(
            url=f"{frontend_origin}/login?error={e.detail}",
            status_code=status.HTTP_302_FOUND,
        )
        response.delete_cookie("itdr_oauth_state", path="/")
        response.delete_cookie("itdr_pkce_verifier", path="/")
        return response
    except Exception as e:
        logger.error(f"Unexpected error in OAuth callback for {provider}: {e}", exc_info=True)
        response = RedirectResponse(
            url=f"{frontend_origin}/login?error=Authentication+failed.+Please+contact+an+administrator.",
            status_code=status.HTTP_302_FOUND,
        )
        response.delete_cookie("itdr_oauth_state", path="/")
        response.delete_cookie("itdr_pkce_verifier", path="/")
        return response
