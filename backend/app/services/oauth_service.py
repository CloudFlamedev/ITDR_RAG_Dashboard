import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
from dataclasses import dataclass

import httpx
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, status

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@dataclass
class OAuthUserInfo:
    provider: str
    provider_user_id: str
    email: str
    email_verified: bool
    full_name: str
    avatar_url: Optional[str] = None


class OAuthService:
    """
    Handles OAuth 2.0 and OpenID Connect authorization code flows
    for Google (OIDC with PKCE S256) and GitHub.
    """

    def __init__(self):
        # Lazy cache JWK client for Google token verification
        self._google_jwk_client: Optional[PyJWKClient] = None

    @property
    def google_jwk_client(self) -> PyJWKClient:
        if self._google_jwk_client is None:
            self._google_jwk_client = PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True, max_cached_keys=10)
        return self._google_jwk_client

    # --------------------------------------------------------------------------
    # Google OIDC
    # --------------------------------------------------------------------------

    def get_google_auth_url(self, state: str, code_challenge: str, redirect_uri: Optional[str] = None) -> str:
        """
        Generate Google OAuth 2.0 authorization URL with PKCE (S256).
        """
        if not settings.GOOGLE_CLIENT_ID:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Google OAuth is not configured on this server (missing GOOGLE_CLIENT_ID).",
            )

        eff_redirect = redirect_uri or settings.GOOGLE_REDIRECT_URI
        if not eff_redirect:
            eff_redirect = f"{settings.FRONTEND_URL.rstrip('/')}/api/auth/oauth/google/callback"

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": eff_redirect,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "online",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    async def exchange_google_code(self, code: str, code_verifier: str, redirect_uri: Optional[str] = None) -> OAuthUserInfo:
        """
        Exchange authorization code with Google token endpoint and securely
        verify the OpenID Connect ID token using Google public JWKS.
        """
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Google OAuth is not configured on this server.",
            )

        eff_redirect = redirect_uri or settings.GOOGLE_REDIRECT_URI
        if not eff_redirect:
            eff_redirect = f"{settings.FRONTEND_URL.rstrip('/')}/api/auth/oauth/google/callback"

        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": eff_redirect,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(GOOGLE_TOKEN_URL, data=data)
            except Exception as e:
                logger.error(f"Google token request failed: {e}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to communicate with Google authentication service.",
                )

        if resp.status_code != 200:
            logger.warning(f"Google token exchange failed ({resp.status_code}): {resp.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code with Google.",
            )

        tokens = resp.json()
        id_token_raw = tokens.get("id_token")
        if not id_token_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google response did not contain an ID token.",
            )

        # Cryptographically verify the ID token using Google's public JWKS keys
        try:
            signing_key = self.google_jwk_client.get_signing_key_from_jwt(id_token_raw)
            payload = jwt.decode(
                id_token_raw,
                signing_key.key,
                algorithms=["RS256"],
                audience=settings.GOOGLE_CLIENT_ID,
                issuer=["https://accounts.google.com", "accounts.google.com"],
                options={"require": ["exp", "iss", "aud", "sub", "email"]},
            )
        except jwt.PyJWTError as e:
            logger.warning(f"Google ID token validation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Google ID token: {str(e)}",
            )

        # Ensure email is verified by Google
        email_verified = payload.get("email_verified", False)
        if not email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account email is not verified.",
            )

        email = payload.get("email", "").lower().strip()
        provider_user_id = str(payload.get("sub"))
        name = payload.get("name") or payload.get("given_name") or email.split("@")[0]
        picture = payload.get("picture")

        return OAuthUserInfo(
            provider="google",
            provider_user_id=provider_user_id,
            email=email,
            email_verified=True,
            full_name=name,
            avatar_url=picture,
        )

    # --------------------------------------------------------------------------
    # GitHub OAuth 2.0
    # --------------------------------------------------------------------------

    def get_github_auth_url(self, state: str, redirect_uri: Optional[str] = None) -> str:
        """
        Generate GitHub OAuth 2.0 authorization URL.
        """
        if not settings.GITHUB_CLIENT_ID:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="GitHub OAuth is not configured on this server (missing GITHUB_CLIENT_ID).",
            )

        eff_redirect = redirect_uri or settings.GITHUB_REDIRECT_URI
        if not eff_redirect:
            eff_redirect = f"{settings.FRONTEND_URL.rstrip('/')}/api/auth/oauth/github/callback"

        params = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": eff_redirect,
            "scope": "read:user user:email",
            "state": state,
            "allow_signup": "false",
        }
        return f"{GITHUB_AUTH_URL}?{urlencode(params)}"

    async def exchange_github_code(self, code: str, redirect_uri: Optional[str] = None) -> OAuthUserInfo:
        """
        Exchange authorization code with GitHub and retrieve user profile
        and verified primary email address.
        """
        if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="GitHub OAuth is not configured on this server.",
            )

        eff_redirect = redirect_uri or settings.GITHUB_REDIRECT_URI
        if not eff_redirect:
            eff_redirect = f"{settings.FRONTEND_URL.rstrip('/')}/api/auth/oauth/github/callback"

        data = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": eff_redirect,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(
                    GITHUB_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"},
                )
            except Exception as e:
                logger.error(f"GitHub token request failed: {e}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to communicate with GitHub authentication service.",
                )

            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange authorization code with GitHub.",
                )

            token_data = resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                err_desc = token_data.get("error_description", "Unknown error")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"GitHub authorization failed: {err_desc}",
                )

            # Fetch user profile
            user_resp = await client.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": "ITDR-Platform-Auth",
                },
            )
            if user_resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to fetch user profile from GitHub.",
                )
            user_data = user_resp.json()

            # Fetch emails to ensure we obtain a verified primary email
            emails_resp = await client.get(
                GITHUB_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": "ITDR-Platform-Auth",
                },
            )
            if emails_resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to fetch verified email list from GitHub.",
                )
            emails_data = emails_resp.json()

        # Find verified primary email
        verified_email: Optional[str] = None
        for email_item in emails_data:
            if email_item.get("verified") and email_item.get("primary"):
                verified_email = email_item.get("email")
                break

        # Fallback to any verified email if no primary was marked
        if not verified_email:
            for email_item in emails_data:
                if email_item.get("verified"):
                    verified_email = email_item.get("email")
                    break

        if not verified_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Your GitHub account does not have a verified email address. Please verify your email on GitHub.",
            )

        provider_user_id = str(user_data.get("id"))
        full_name = user_data.get("name") or user_data.get("login") or verified_email.split("@")[0]
        avatar_url = user_data.get("avatar_url")

        return OAuthUserInfo(
            provider="github",
            provider_user_id=provider_user_id,
            email=verified_email.lower().strip(),
            email_verified=True,
            full_name=full_name,
            avatar_url=avatar_url,
        )


oauth_service = OAuthService()
