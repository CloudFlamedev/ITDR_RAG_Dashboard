import datetime
import time
import logging
import threading
from typing import Optional, Tuple, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import text

from app.core.config import get_settings
from app.core.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_session_token,
    generate_verification_token,
    hash_verification_token,
)
from app.core.rate_limiter import login_rate_limiter
from app.models.auth import User, Role, Permission, UserSession, AuthIdentity, AuditLog, EmailVerificationToken
from app.services.email_service import email_service

logger = logging.getLogger(__name__)
settings = get_settings()

# In-memory store for verification resend cooldown
_resend_rate_limiter: Dict[str, float] = {}

# Thread-safe in-memory cache for validated sessions to eliminate Neon DB round-trips
_session_cache_lock = threading.Lock()
# Maps token_hash -> dict of primitive session and user attributes
_SESSION_CACHE: Dict[str, Dict[str, Any]] = {}
_SESSION_CACHE_TTL_SECONDS = 15.0

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
        - Checks in-memory fast cache first to avoid remote DB latency
        - Validates expiration and revocation
        - Enforces sliding inactivity window
        - Ensures user is still active
        """
        if not raw_session_token:
            return None

        token_hash = hash_session_token(raw_session_token)
        now_mono = time.monotonic()
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        inactivity_limit = datetime.timedelta(minutes=settings.SESSION_INACTIVITY_MINUTES)

        # 1. In-memory fast cache lookup using primitive values
        with _session_cache_lock:
            cached_data = _SESSION_CACHE.get(token_hash)
            if cached_data:
                cached_time = cached_data.get("cached_time", 0.0)
                if (now_mono - cached_time) < _SESSION_CACHE_TTL_SECONDS:
                    expires_at = cached_data["expires_at"]
                    last_activity_at = cached_data["last_activity_at"]
                    is_active = cached_data["is_active"]
                    revoked_at = cached_data["revoked_at"]

                    if (
                        expires_at > now_utc
                        and (now_utc - last_activity_at) <= inactivity_limit
                        and is_active
                        and revoked_at is None
                    ):
                        u = User(
                            id=cached_data["user_id"],
                            email=cached_data["email"],
                            full_name=cached_data["full_name"],
                            is_active=cached_data["is_active"],
                            is_verified=cached_data["is_verified"],
                            created_at=cached_data["user_created_at"],
                            updated_at=cached_data["user_updated_at"],
                            last_login_at=cached_data["user_last_login_at"],
                        )
                        roles = []
                        for role_id, role_name, perm_keys in cached_data["roles"]:
                            r = Role(id=role_id, name=role_name)
                            r.permissions = [Permission(permission_key=pk) for pk in perm_keys]
                            roles.append(r)
                        u.roles = roles

                        s = UserSession(
                            id=cached_data["session_id"],
                            user_id=cached_data["user_id"],
                            session_token_hash=cached_data["session_token_hash"],
                            expires_at=cached_data["expires_at"],
                            last_activity_at=cached_data["last_activity_at"],
                            revoked_at=cached_data["revoked_at"],
                            ip_address=cached_data["ip_address"],
                            user_agent=cached_data["user_agent"],
                            created_at=cached_data["session_created_at"],
                        )
                        s.user = u
                        return u, s
                    else:
                        _SESSION_CACHE.pop(token_hash, None)

        # 2. Query DB with eager relationships
        session = (
            self.db.query(UserSession)
            .options(
                joinedload(UserSession.user)
                .selectinload(User.roles)
                .selectinload(Role.permissions)
            )
            .filter(UserSession.session_token_hash == token_hash)
            .first()
        )

        if not session or session.revoked_at is not None:
            with _session_cache_lock:
                _SESSION_CACHE.pop(token_hash, None)
            return None

        # 3. Absolute expiration check
        if session.expires_at <= now_utc:
            session.revoked_at = now_utc
            self.db.commit()
            with _session_cache_lock:
                _SESSION_CACHE.pop(token_hash, None)
            return None

        # 4. Sliding inactivity timeout check
        if (now_utc - session.last_activity_at) > inactivity_limit:
            session.revoked_at = now_utc
            self.db.commit()
            with _session_cache_lock:
                _SESSION_CACHE.pop(token_hash, None)
            return None

        # 5. User active check
        user = session.user
        if not user or not user.is_active:
            session.revoked_at = now_utc
            self.db.commit()
            with _session_cache_lock:
                _SESSION_CACHE.pop(token_hash, None)
            return None

        # 6. Slide activity timestamp (only update if > 30s since last write to reduce DB chatter)
        if (now_utc - session.last_activity_at).total_seconds() > 30:
            session.last_activity_at = now_utc
            self.db.commit()

        # 7. Store valid session in in-memory cache as primitives
        roles_data = []
        for r in user.roles:
            perm_keys = [p.permission_key for p in r.permissions]
            roles_data.append((r.id, r.name, perm_keys))

        with _session_cache_lock:
            _SESSION_CACHE[token_hash] = {
                "user_id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "user_created_at": user.created_at,
                "user_updated_at": user.updated_at,
                "user_last_login_at": user.last_login_at,
                "roles": roles_data,
                "session_id": session.id,
                "session_token_hash": session.session_token_hash,
                "expires_at": session.expires_at,
                "last_activity_at": session.last_activity_at,
                "revoked_at": session.revoked_at,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "session_created_at": session.created_at,
                "cached_time": now_mono,
            }

        return user, session

    def revoke_session(self, raw_session_token: str) -> bool:
        """Revoke a specific active session."""
        if not raw_session_token:
            return False

        token_hash = hash_session_token(raw_session_token)
        with _session_cache_lock:
            _SESSION_CACHE.pop(token_hash, None)

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
        self.invalidate_cache_for_user(user_id)
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

    @classmethod
    def invalidate_cache_for_user(cls, user_id: int) -> None:
        """Invalidate cached session entries for a specific user ID."""
        with _session_cache_lock:
            to_remove = [
                th for th, entry in _SESSION_CACHE.items()
                if entry.get("user_id") == user_id
            ]
            for th in to_remove:
                _SESSION_CACHE.pop(th, None)

    @classmethod
    def clear_session_cache(cls) -> None:
        """Clear all in-memory session cache entries."""
        with _session_cache_lock:
            _SESSION_CACHE.clear()

    def handle_oauth_user(
        self,
        provider: str,
        provider_user_id: str,
        verified_email: str,
        full_name: str,
        email_verified: bool = True,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Securely resolve or link a third-party social login identity:
        1. Verify provider email verification before linking.
        2. Check if (provider, provider_user_id) identity is already linked.
        3. If not, link to an existing user with matching verified email.
        4. If no account exists and auto-registration is disabled, reject.
        """
        clean_email = verified_email.strip().lower()

        if not email_verified:
            self.log_audit_event(
                user_id=None,
                action=f"{provider}_login_rejected_unverified_email",
                resource="auth",
                ip_address=ip_address,
                metadata={"email": clean_email, "provider": provider},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot authenticate: {provider} account email is not verified by the provider.",
            )

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

        # Auto-registration as Demo Analyst (public portfolio mode)
        target_role_name = settings.DEFAULT_REGISTRATION_ROLE or "Demo Analyst"
        assigned_role = self.db.query(Role).filter(Role.name == target_role_name).first()
        if not assigned_role:
            assigned_role = self.db.query(Role).filter(Role.name == "Demo Analyst").first()
        if not assigned_role:
            assigned_role = self.db.query(Role).filter(Role.name == "Viewer").first()

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
            roles=[assigned_role] if assigned_role else [],
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
            metadata={"email": clean_email, "role": assigned_role.name if assigned_role else "None"},
        )
        return new_user

    def register_public_user(
        self,
        full_name: str,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Public self-registration for portfolio demo visitors:
        - Rejects registration if disabled in settings
        - Normalizes email
        - Prevents duplicate registration
        - Hashes password using Argon2id
        - Automatically assigns Demo Analyst role (prevents elevation)
        - Creates account with is_active=True, is_verified=False (not falsely marked as provider-verified)
        - Enables immediate login without mandatory email verification or SMTP dependency
        - Logs audit event
        """
        if not settings.PUBLIC_REGISTRATION_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Public registration is currently disabled.",
            )

        clean_email = (email or "").strip().lower()

        # Check existing user
        existing_user = self.db.query(User).filter(User.email == clean_email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists.",
            )

        # Hash password with Argon2id
        pwd_hash = hash_password(password)

        # Assign default registration role (Demo Analyst)
        target_role_name = settings.DEFAULT_REGISTRATION_ROLE or "Demo Analyst"
        assigned_role = self.db.query(Role).filter(Role.name == target_role_name).first()
        if not assigned_role:
            assigned_role = self.db.query(Role).filter(Role.name == "Demo Analyst").first()
        if not assigned_role:
            assigned_role = self.db.query(Role).filter(Role.name == "Viewer").first()

        now = datetime.datetime.now(datetime.timezone.utc)
        new_user = User(
            email=clean_email,
            full_name=full_name.strip(),
            password_hash=pwd_hash,
            is_active=True,
            is_verified=False,
            created_at=now,
            updated_at=now,
            roles=[assigned_role] if assigned_role else [],
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        self.log_audit_event(
            user_id=new_user.id,
            action="user_registered",
            resource="auth",
            ip_address=ip_address,
            metadata={"email": clean_email, "role": assigned_role.name if assigned_role else "None"},
        )

        return new_user

    def verify_email_token(
        self,
        raw_token: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Validates token hash against email_verification_tokens:
        - Ensures token exists
        - Ensures not previously used
        - Ensures not expired
        - Sets user.is_verified = True
        - Marks token used_at timestamp
        - Logs audit event
        """
        if not raw_token or len(raw_token.strip()) < 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token.",
            )

        clean_token = raw_token.strip()
        token_hash = hash_verification_token(clean_token)

        verif_record = (
            self.db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.token_hash == token_hash)
            .with_for_update()
            .first()
        )

        if not verif_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification link.",
            )

        if verif_record.used_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This verification token has already been used.",
            )

        now = datetime.datetime.now(datetime.timezone.utc)
        if verif_record.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification link has expired. Please request a new verification email.",
            )

        user = verif_record.user
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Associated user account not found.",
            )

        verif_record.used_at = now
        user.is_verified = True
        self.db.commit()
        self.db.refresh(user)

        self.log_audit_event(
            user_id=user.id,
            action="email_verified",
            resource="auth",
            ip_address=ip_address,
            metadata={"email": user.email},
        )

        return user

    def resend_verification_email(
        self,
        email: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """
        Generates a fresh verification token and dispatches email.
        Applies cooldown rate limiting per email.
        """
        clean_email = (email or "").strip().lower()
        now_ts = time.time()

        # Cooldown check: 60 seconds
        last_resend = _resend_rate_limiter.get(clean_email, 0.0)
        if (now_ts - last_resend) < 60:
            remaining = int(60 - (now_ts - last_resend))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {remaining} seconds before requesting another verification email.",
                headers={"Retry-After": str(remaining)},
            )

        user = self.db.query(User).filter(User.email == clean_email).first()
        if not user:
            # Prevent user enumeration: pretend success
            _resend_rate_limiter[clean_email] = now_ts
            return True

        if user.is_verified:
            # Already verified
            _resend_rate_limiter[clean_email] = now_ts
            return True

        now = datetime.datetime.now(datetime.timezone.utc)
        # Invalidate old unused tokens
        self.db.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
        ).update({"used_at": now})

        # Generate fresh token
        raw_token, token_hash = generate_verification_token()
        expires_at = now + datetime.timedelta(minutes=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES)

        verif_token = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            created_at=now,
            used_at=None,
        )
        self.db.add(verif_token)
        self.db.commit()

        _resend_rate_limiter[clean_email] = now_ts

        email_service.send_verification_email(
            to_email=clean_email,
            raw_token=raw_token,
            full_name=user.full_name,
        )

        self.log_audit_event(
            user_id=user.id,
            action="verification_email_resent",
            resource="auth",
            ip_address=ip_address,
            metadata={"email": clean_email},
        )

        return True

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
