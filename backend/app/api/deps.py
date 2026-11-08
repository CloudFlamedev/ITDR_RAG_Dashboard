import logging
from typing import Optional, Tuple
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import verify_csrf_token
from app.db.session import get_db
from app.models.auth import User, UserSession
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)
settings = get_settings()

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user_and_session(
    request: Request,
    db: Session = Depends(get_db),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Tuple[User, UserSession, str]:
    """
    Extract session token from HttpOnly cookie or Authorization Bearer header,
    validate against PostgreSQL with sliding inactivity window and expiration checks.
    Returns:
        (user, session, auth_method) where auth_method is 'cookie' or 'bearer'
    """
    raw_token = None
    auth_method = "bearer"

    # 1. Check Bearer token in Authorization header
    if bearer_creds and bearer_creds.credentials:
        raw_token = bearer_creds.credentials
        auth_method = "bearer"

    # 2. Check HttpOnly session cookie
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw_token and cookie_token:
        raw_token = cookie_token
        auth_method = "cookie"

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_service = AuthService(db)
    validation_result = auth_service.validate_session(raw_token)
    if not validation_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user, session = validation_result
    return user, session, auth_method


def get_current_user(
    auth_data: Tuple[User, UserSession, str] = Depends(get_current_user_and_session)
) -> User:
    """FastAPI dependency to retrieve the authenticated user."""
    user, _, _ = auth_data
    return user


def get_current_session(
    auth_data: Tuple[User, UserSession, str] = Depends(get_current_user_and_session)
) -> UserSession:
    """FastAPI dependency to retrieve the active UserSession."""
    _, session, _ = auth_data
    return session


def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[User]:
    """Optional dependency that returns User if authenticated, otherwise None."""
    try:
        user, _, _ = get_current_user_and_session(request, db, bearer_creds)
        return user
    except HTTPException:
        return None


def verify_csrf(
    request: Request,
    auth_data: Tuple[User, UserSession, str] = Depends(get_current_user_and_session),
) -> None:
    """
    CSRF verification dependency for state-changing requests authenticated via cookies.
    Requests using Bearer tokens in Authorization headers are exempt from CSRF checks.
    """
    _, session, auth_method = auth_data

    # CSRF protection is specifically needed for cookie-based authentication
    if auth_method == "cookie" and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing CSRF protection token (X-CSRF-Token).",
            )
        if not verify_csrf_token(str(session.id), csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired CSRF token.",
            )


def require_permission(permission_key: str):
    """
    Dependency factory to enforce fine-grained permissions.
    Admins bypass individual permission checks.
    """
    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if not user.has_permission(permission_key):
            logger.warning(
                f"User {user.email} (id={user.id}) denied access: missing permission '{permission_key}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: You do not have permission '{permission_key}' to perform this action.",
            )
        return user

    return dependency


def require_role(role_name: str):
    """
    Dependency factory to enforce required role membership.
    """
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_role(role_name):
            logger.warning(
                f"User {user.email} (id={user.id}) denied access: missing role '{role_name}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: '{role_name}' role is required for this resource.",
            )
        return user

    return dependency
