import datetime
import logging
from typing import Optional, Tuple, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import get_settings
from app.core.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_session_token,
)
from app.core.rate_limiter import login_rate_limiter
from app.models.auth import User, Role, UserSession, AuthIdentity, AuditLog

logger = logging.getLogger(__name__)
settings = get_settings()

# Dummy Argon2id hash for constant-time comparison when user does not exist
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=2,p=2$dummyhashfordummyuserdummyhash$dummyhashfordummyuserdummyhashdummyhashdummy"


class AuthService:
    """
    Core authentication, session lifecycle, OAuth identity resolution,
    and audit logging service.
    """

    def __init__(self, db: Session):
        self.db = db

    def authenticate_user(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Authenticate a user by email and password with Argon2id and rate limiting.
        """
        clean_email = (email or "").strip().lower()
        rate_limit_key = f"{ip_address or 'unknown'}:{clean_email}"

        # 1. Check Rate Limiter
        is_limited, retry_after = login_rate_limiter.is_rate_limited(rate_limit_key)
        if is_limited:
            self.log_audit_event(
                user_id=None,
                action="login_throttled",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email, "retry_after": retry_after},
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Please try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )

        # 2. Look up user by email
        user = self.db.query(User).filter(User.email == clean_email).first()

        # 3. Timing-attack resistant verification
        if not user or not user.password_hash:
            # Perform dummy hash verification to preserve constant-time response
            verify_password(password, DUMMY_PASSWORD_HASH)
            login_rate_limiter.record_failed_attempt(rate_limit_key)
            self.log_audit_event(
                user_id=None,
                action="login_failed_unknown_user",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        # 4. Check account active status
        if not user.is_active:
            login_rate_limiter.record_failed_attempt(rate_limit_key)
            self.log_audit_event(
                user_id=user.id,
                action="login_rejected_inactive_account",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been deactivated. Please contact an administrator.",
            )

        # 5. Verify password
        if not verify_password(password, user.password_hash):
            login_rate_limiter.record_failed_attempt(rate_limit_key)
            self.log_audit_event(
                user_id=user.id,
                action="login_failed_bad_password",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        # 6. Reset rate limits and record login timestamp
        login_rate_limiter.reset(rate_limit_key)
        now = datetime.datetime.now(datetime.timezone.utc)
        user.last_login_at = now
        self.db.commit()

        self.log_audit_event(
            user_id=user.id,
            action="login_success",
            resource="auth",
            ip_address=ip_address,
            metadata={"email": clean_email, "auth_method": "password"},
        )
        return user

    def create_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, UserSession]:
        """
        Generate a cryptographically secure session and persist its hash in PostgreSQL.
        Returns:
            (raw_session_token, UserSession)
        """
        raw_token, token_hash = generate_session_token()
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = now + datetime.timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)

        session = UserSession(
            user_id=user.id,
            session_token_hash=token_hash,
            expires_at=expires_at,
            created_at=now,
            last_activity_at=now,
            revoked_at=None,
            ip_address=ip_address[:45] if ip_address else None,
            user_agent=user_agent[:500] if user_agent else None,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        self.log_audit_event(
            user_id=user.id,
            action="session_created",
            resource="session",
            ip_address=ip_address,
            metadata={"session_id": session.id, "expires_at": expires_at.isoformat()},
        )
        return raw_token, session

    def validate_session(self, raw_session_token: str) -> Optional[Tuple[User, UserSession]]:
        """
        Validate incoming session token against PostgreSQL:
        - Checks hash existence
        - Validates expiration and revocation
        - Enforces sliding inactivity window
        - Ensures user is still active
        """
        if not raw_session_token:
            return None

        token_hash = hash_session_token(raw_session_token)
        session = (
            self.db.query(UserSession)
            .filter(UserSession.session_token_hash == token_hash)
            .first()
        )

        if not session or session.revoked_at is not None:
            return None

        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Absolute expiration check
        if session.expires_at <= now:
            session.revoked_at = now
            self.db.commit()
            return None

        # 2. Sliding inactivity timeout check
        inactivity_limit = datetime.timedelta(minutes=settings.SESSION_INACTIVITY_MINUTES)
        if (now - session.last_activity_at) > inactivity_limit:
            session.revoked_at = now
            self.db.commit()
            return None

        # 3. User active check
        user = session.user
        if not user or not user.is_active:
            session.revoked_at = now
            self.db.commit()
            return None

        # 4. Slide activity timestamp (only update if > 30s since last write to reduce DB chatter)
        if (now - session.last_activity_at).total_seconds() > 30:
            session.last_activity_at = now
            self.db.commit()

        return user, session

    def revoke_session(self, raw_session_token: str) -> bool:
        """Revoke a specific active session."""
        if not raw_session_token:
            return False

        token_hash = hash_session_token(raw_session_token)
        session = (
            self.db.query(UserSession)
            .filter(UserSession.session_token_hash == token_hash)
            .first()
        )
        if session and session.revoked_at is None:
            now = datetime.datetime.now(datetime.timezone.utc)
            session.revoked_at = now
            self.db.commit()
            self.log_audit_event(
                user_id=session.user_id,
                action="session_revoked",
                resource="session",
                metadata={"session_id": session.id},
            )
            return True
        return False

    def revoke_all_user_sessions(self, user_id: int) -> int:
        """Revoke all active sessions for a user (e.g. on deactivation or password change)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        count = (
            self.db.query(UserSession)
            .filter(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
            .update({"revoked_at": now})
        )
        self.db.commit()
        self.log_audit_event(
            user_id=user_id,
            action="all_sessions_revoked",
            resource="session",
            metadata={"revoked_count": count},
        )
        return count

    def handle_oauth_user(
        self,
        provider: str,
        provider_user_id: str,
        verified_email: str,
        full_name: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Securely resolve or link a third-party social login identity:
        1. Check if (provider, provider_user_id) identity is already linked.
        2. If not, link to an existing user with matching verified email.
        3. If no account exists and auto-registration is disabled, reject.
        """
        clean_email = verified_email.strip().lower()

        # Step 1: Look up existing identity
        identity = (
            self.db.query(AuthIdentity)
            .filter(
                AuthIdentity.provider == provider,
                AuthIdentity.provider_user_id == str(provider_user_id),
            )
            .first()
        )

        if identity:
            user = identity.user
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account has been deactivated. Please contact an administrator.",
                )
            now = datetime.datetime.now(datetime.timezone.utc)
            user.last_login_at = now
            self.db.commit()

            self.log_audit_event(
                user_id=user.id,
                action=f"{provider}_login_success",
                resource="auth",
                ip_address=ip_address,
                metadata={"provider": provider, "provider_user_id": provider_user_id},
            )
            return user

        # Step 2: Check for existing user with matching verified email
        user = self.db.query(User).filter(User.email == clean_email).first()

        if user:
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account has been deactivated. Please contact an administrator.",
                )

            # Link identity to existing provisioned user
            new_identity = AuthIdentity(
                user_id=user.id,
                provider=provider,
                provider_user_id=str(provider_user_id),
                provider_email=clean_email,
            )
            self.db.add(new_identity)
            user.is_verified = True  # Social provider verified email
            now = datetime.datetime.now(datetime.timezone.utc)
            user.last_login_at = now
            self.db.commit()

            self.log_audit_event(
                user_id=user.id,
                action=f"{provider}_account_linked",
                resource="auth",
                ip_address=ip_address,
                metadata={"provider": provider, "email": clean_email},
            )
            return user

        # Step 3: User does not exist
        if not settings.ALLOW_OAUTH_AUTO_REGISTRATION:
            self.log_audit_event(
                user_id=None,
                action=f"{provider}_login_rejected_unprovisioned",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email, "provider": provider},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not found. Please contact an ITDR Administrator to provision your account before signing in.",
            )

        # Optional auto-registration as Viewer if enabled
        viewer_role = self.db.query(Role).filter(Role.name == "Viewer").first()
        now = datetime.datetime.now(datetime.timezone.utc)
        new_user = User(
            email=clean_email,
            full_name=full_name or clean_email.split("@")[0],
            password_hash=None,
            is_active=True,
            is_verified=True,
            created_at=now,
            updated_at=now,
            last_login_at=now,
            roles=[viewer_role] if viewer_role else [],
        )
        self.db.add(new_user)
        self.db.flush()

        new_identity = AuthIdentity(
            user_id=new_user.id,
            provider=provider,
            provider_user_id=str(provider_user_id),
            provider_email=clean_email,
        )
        self.db.add(new_identity)
        self.db.commit()
        self.db.refresh(new_user)

        self.log_audit_event(
            user_id=new_user.id,
            action=f"{provider}_user_auto_provisioned",
            resource="auth",
            ip_address=ip_address,
            metadata={"email": clean_email, "role": "Viewer"},
        )
        return new_user

    def log_audit_event(
        self,
        user_id: Optional[int],
        action: str,
        resource: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Record an immutable security audit event."""
        log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            ip_address=ip_address[:45] if ip_address else None,
            metadata_json=metadata or {},
        )
        try:
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            logger.warning(f"Could not record audit log: {e}")
            self.db.rollback()
        return log
