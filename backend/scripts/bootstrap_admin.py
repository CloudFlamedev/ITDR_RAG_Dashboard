#!/usr/bin/env python3
"""
Admin Bootstrap Utility for ITDR RAG Platform.
Securely provisions or promotes an initial Administrator user with Argon2id password hashing.

Usage:
    python backend/scripts/bootstrap_admin.py --email admin@cybersec.corp --name 'SOC Lead'
Or fully interactive:
    python backend/scripts/bootstrap_admin.py
Or headless (CI / container init):
    ADMIN_INITIAL_PASSWORD='StrongSecret123!' python backend/scripts/bootstrap_admin.py --email admin@cybersec.corp
"""

import sys
import os
import argparse
import getpass
import datetime

# Ensure backend package root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.session import SessionLocal
from app.models.auth import User, Role, AuditLog
from app.core.security import hash_password


def bootstrap_admin(email: str, password: str, full_name: str) -> None:
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        print(f"[-] Invalid email address: {email}")
        sys.exit(1)

    if len(password) < 8:
        print("[-] Password must be at least 8 characters long.")
        sys.exit(1)

    db = SessionLocal()
    try:
        # Retrieve Admin role
        admin_role = db.query(Role).filter(Role.name == "Admin").first()
        if not admin_role:
            print("[-] Error: 'Admin' role not found in database. Run alembic upgrade head first.")
            sys.exit(1)

        # Check if user already exists
        user = db.query(User).filter(User.email == clean_email).first()
        now = datetime.datetime.now(datetime.timezone.utc)
        pwd_hash = hash_password(password)

        if user:
            print(f"[*] User '{clean_email}' already exists. Promoting to Admin & updating password...")
            user.password_hash = pwd_hash
            user.is_active = True
            user.is_verified = True
            user.updated_at = now
            if full_name:
                user.full_name = full_name.strip()
            if admin_role not in user.roles:
                user.roles.append(admin_role)
            action_name = "admin_promoted"
        else:
            print(f"[*] Creating new Administrator account: '{clean_email}'...")
            user = User(
                email=clean_email,
                full_name=full_name.strip() if full_name else clean_email.split("@")[0].title(),
                password_hash=pwd_hash,
                is_active=True,
                is_verified=True,
                created_at=now,
                updated_at=now,
                roles=[admin_role],
            )
            db.add(user)
            action_name = "admin_bootstrapped"

        db.flush()

        # Audit log entry
        audit = AuditLog(
            user_id=user.id,
            action=action_name,
            resource="bootstrap_cli",
            metadata_json={"email": clean_email, "role": "Admin", "timestamp": now.isoformat()},
        )
        db.add(audit)
        db.commit()

        print(f"[+] SUCCESS: Administrator '{clean_email}' has been successfully provisioned!")
        print(f"    User ID: {user.id}")
        print(f"    Roles: {[r.name for r in user.roles]}")
        print(f"    Permissions: {len(user.permission_keys)} granular permissions active.")

    except Exception as e:
        db.rollback()
        print(f"[-] Failed to bootstrap admin: {e}")
        sys.exit(1)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap initial ITDR Administrator account (Argon2id). Passwords are securely prompted via masked input."
    )
    parser.add_argument("--email", "-e", type=str, help="Administrator email address")
    parser.add_argument("--name", "-n", type=str, default="ITDR SOC Admin", help="Administrator full name")

    args = parser.parse_args()

    email = args.email
    if not email:
        email = input("Enter Admin Email: ").strip()

    # Passwords must NEVER be passed as CLI arguments to prevent exposure in process tables and shell history.
    # Check for secure environment variable (headless / CI environments) or prompt interactively.
    env_pwd = os.environ.get("ADMIN_INITIAL_PASSWORD")
    if env_pwd and env_pwd.strip():
        password = env_pwd.strip()
    else:
        try:
            password = getpass.getpass("Enter Admin Password (min 8 characters): ")
            password_confirm = getpass.getpass("Confirm Admin Password: ")
            if password != password_confirm:
                print("[-] Error: Passwords do not match.")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\n[-] Bootstrap aborted by user.")
            sys.exit(1)

    bootstrap_admin(email, password, args.name)


if __name__ == "__main__":
    main()
