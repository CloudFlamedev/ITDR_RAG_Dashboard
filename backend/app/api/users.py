import datetime
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.api.deps import require_permission, require_role, verify_csrf, get_current_user
from app.core.security import hash_password
from app.db.session import get_db
from app.models.auth import User, Role, Permission, UserSession, AuditLog
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["User Management"])


# ------------------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------------------

class RoleDetail(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    permissions: List[str]


class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str
    roles: List[str] = ["Viewer"]


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None


class UserRolesUpdate(BaseModel):
    roles: List[str]


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    roles: List[str]
    permissions: List[str]
    created_at: datetime.datetime
    updated_at: datetime.datetime
    last_login_at: Optional[datetime.datetime] = None


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    metadata: Dict[str, Any]
    timestamp: datetime.datetime


# ------------------------------------------------------------------------------
# User Management Endpoints (Admin Only: "users:manage")
# ------------------------------------------------------------------------------

@router.get("", response_model=List[UserResponse])
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    q: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
):
    """
    List all application users with their roles and permissions (Admin only).
    """
    query = db.query(User)
    if q:
        search_filter = f"%{q.strip().lower()}%"
        query = query.filter(
            (User.email.ilike(search_filter)) | (User.full_name.ilike(search_filter))
        )
    users = query.order_by(desc(User.created_at)).offset(skip).limit(limit).all()

    return [
        UserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            is_active=u.is_active,
            is_verified=u.is_verified,
            roles=u.role_names,
            permissions=u.permission_keys,
            created_at=u.created_at,
            updated_at=u.updated_at,
            last_login_at=u.last_login_at,
        )
        for u in users
    ]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
    _csrf: None = Depends(verify_csrf),
):
    """
    Admin-provisioned account creation.
    Hashes password with Argon2id and binds assigned roles.
    """
    clean_email = payload.email.strip().lower()

    # Check if email is already taken
    existing = db.query(User).filter(User.email == clean_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{clean_email}' already exists.",
        )

    # Validate password complexity
    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )

    # Resolve roles
    roles = []
    if payload.roles:
        roles = db.query(Role).filter(Role.name.in_(payload.roles)).all()
        if len(roles) != len(payload.roles):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more specified roles do not exist.",
            )
    else:
        default_role = db.query(Role).filter(Role.name == "Viewer").first()
        if default_role:
            roles.append(default_role)

    pwd_hash = hash_password(payload.password)
    now = datetime.datetime.now(datetime.timezone.utc)

    user = User(
        email=clean_email,
        full_name=payload.full_name.strip(),
        password_hash=pwd_hash,
        is_active=True,
        is_verified=True,
        created_at=now,
        updated_at=now,
        roles=roles,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    auth_svc = AuthService(db)
    auth_svc.log_audit_event(
        user_id=current_user.id,
        action="user_created",
        resource="user_management",
        metadata={"created_user_id": user.id, "email": user.email, "roles": user.role_names},
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        roles=user.role_names,
        permissions=user.permission_keys,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
    )


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
):
    """
    Get user details by ID (Admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        roles=user.role_names,
        permissions=user.permission_keys,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
    )


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
    _csrf: None = Depends(verify_csrf),
):
    """
    Update user profile, status, or password.
    Deactivating a user instantly revokes all of their active sessions.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    auth_svc = AuthService(db)

    # Protect against self-deactivation of the active Admin
    if payload.is_active is False and user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own administrative account.",
        )

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()

    if payload.password is not None:
        if len(payload.password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long.",
            )
        user.password_hash = hash_password(payload.password)
        # Revoke sessions on password reset
        auth_svc.revoke_all_user_sessions(user.id)

    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            # Revoke all sessions immediately upon deactivation
            auth_svc.revoke_all_user_sessions(user.id)

    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)

    auth_svc.log_audit_event(
        user_id=current_user.id,
        action="user_updated",
        resource="user_management",
        metadata={
            "target_user_id": user.id,
            "is_active": user.is_active,
            "password_changed": payload.password is not None,
        },
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        roles=user.role_names,
        permissions=user.permission_keys,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
    )


@router.patch("/{user_id}/roles", response_model=UserResponse)
def update_user_roles(
    user_id: int,
    payload: UserRolesUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
    _csrf: None = Depends(verify_csrf),
):
    """
    Update assigned roles for a user.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Guard: prevent removing Admin role from yourself
    if user.id == current_user.id and "Admin" not in payload.roles and "Admin" in user.role_names:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove the Admin role from your own account.",
        )

    roles = db.query(Role).filter(Role.name.in_(payload.roles)).all()
    if len(roles) != len(payload.roles):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more specified roles do not exist.",
        )

    user.roles = roles
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)

    auth_svc = AuthService(db)
    auth_svc.log_audit_event(
        user_id=current_user.id,
        action="user_roles_updated",
        resource="user_management",
        metadata={"target_user_id": user.id, "new_roles": [r.name for r in roles]},
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        roles=user.role_names,
        permissions=user.permission_keys,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
    )


@router.delete("/{user_id}", response_model=UserResponse)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
    _csrf: None = Depends(verify_csrf),
):
    """
    Deactivate a user and revoke all active sessions (Admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    user.is_active = False
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    auth_svc = AuthService(db)
    auth_svc.revoke_all_user_sessions(user.id)
    auth_svc.log_audit_event(
        user_id=current_user.id,
        action="user_deactivated",
        resource="user_management",
        metadata={"target_user_id": user.id, "email": user.email},
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        roles=user.role_names,
        permissions=user.permission_keys,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
    )


# ------------------------------------------------------------------------------
# System Roles & Audit Logs (Admin Only)
# ------------------------------------------------------------------------------

@router.get("/roles/all", response_model=List[RoleDetail])
def list_all_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
):
    """
    List all defined roles and their permissions.
    """
    roles = db.query(Role).all()
    return [
        RoleDetail(
            id=r.id,
            name=r.name,
            description=r.description,
            permissions=[p.permission_key for p in r.permissions],
        )
        for r in roles
    ]


@router.get("/audit/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    action: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users:manage")),
):
    """
    Retrieve security audit logs (Admin only).
    """
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)

    logs = query.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()

    return [
        AuditLogResponse(
            id=l.id,
            user_id=l.user_id,
            action=l.action,
            resource=l.resource,
            ip_address=l.ip_address,
            metadata=l.metadata_json or {},
            timestamp=l.timestamp,
        )
        for l in logs
    ]
