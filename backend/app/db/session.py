import datetime
import logging
import time
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Detect database type using configured DATABASE_URL
db_url = settings.normalized_database_url
is_sqlite = db_url.startswith("sqlite")

if is_sqlite:
    # SQLite configuration (CI testing & in-memory execution)
    # Do not pass pool_size or max_overflow; use check_same_thread=False
    engine_kwargs: Dict[str, Any] = {
        "connect_args": {"check_same_thread": False},
        "future": True,
    }
    # Use StaticPool for in-memory SQLite database so connection is shared across threads
    if ":memory:" in db_url or db_url in ("sqlite://", "sqlite:///"):
        engine_kwargs["poolclass"] = StaticPool

    engine = create_engine(db_url, **engine_kwargs)
else:
    # PostgreSQL (production, staging, dev): preserve pool_pre_ping, pool_size, and max_overflow
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)

if is_sqlite:
    try:
        import app.models  # register all models with Base.metadata
        from app.db.base import Base
        Base.metadata.create_all(bind=engine)

        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'AuditLog records are append-only. Modification and deletion of audit records is prohibited.');
            END;
            """))
            conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'AuditLog records are append-only. Modification and deletion of audit records is prohibited.');
            END;
            """))
            conn.commit()

        # Seed essential baseline taxonomy, RBAC permissions, and roles for SQLite testing
        from sqlalchemy.orm import Session as _SqliteSession
        with _SqliteSession(engine) as _init_session:
            from app.models.auth import Permission, Role
            perm_defs = [
                (1, "users:manage", "Create, edit, assign roles, and deactivate users"),
                (2, "threats:analyze", "Execute LangGraph threat modeling and RAG workflow"),
                (3, "threats:read", "View threat samples and historical analysis reports"),
                (4, "feeds:ingest", "Ingest and process external CTI threat advisories"),
                (5, "feeds:read", "View threat intelligence feeds and bulletins"),
                (6, "rag:search", "Execute standalone RAG knowledge base search queries"),
                (7, "rag:read", "View RAG knowledge index and telemetry diagnostics"),
                (8, "system:status", "View sensitive infrastructure and model subsystem status"),
                (9, "dashboard:read", "View executive resilience KPIs and threat posture"),
                (10, "matrix:read", "View ITDR coverage matrix and technique details"),
            ]
            perms_by_id = {}
            for pid, pkey, pdesc in perm_defs:
                p = _init_session.query(Permission).filter(Permission.permission_key == pkey).first()
                if not p:
                    p = Permission(id=pid, permission_key=pkey, description=pdesc)
                    _init_session.add(p)
                    _init_session.flush()
                perms_by_id[pid] = p

            role_defs = [
                (1, "Admin", "Full administrative access to all features, telemetry, and user management", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                (2, "Security Analyst", "Operational access to threat modeling, feed ingestion, and RAG search", [2, 3, 4, 5, 6, 7, 9, 10]),
                (3, "Viewer", "Read-only access to dashboards, threat feeds, and completed reports", [3, 5, 7, 9, 10]),
                (4, "Demo Analyst", "Public portfolio demo analyst with bounded threat modeling capabilities", [2, 3, 5, 6, 7, 9, 10]),
            ]
            roles_by_name = {}
            for rid, rname, rdesc, pids in role_defs:
                r = _init_session.query(Role).filter(Role.name == rname).first()
                role_perms = [perms_by_id[p] for p in pids if p in perms_by_id]
                if not r:
                    r = Role(id=rid, name=rname, description=rdesc, permissions=role_perms)
                    _init_session.add(r)
                else:
                    r.permissions = role_perms
                roles_by_name[rname] = r
            _init_session.flush()

            from app.models.auth import User
            from app.core.security import hash_password
            now = datetime.datetime.now(datetime.timezone.utc)
            users_seed = [
                ("admin@itdr.local", "Test Admin", "AdminPass123!", [roles_by_name["Admin"]], True),
                ("analyst@itdr.local", "Test Analyst", "AnalystPass123!", [roles_by_name["Security Analyst"]], True),
                ("viewer@itdr.local", "Test Viewer", "ViewerPass123!", [roles_by_name["Viewer"]], True),
                ("inactive@itdr.local", "Test Inactive", "InactivePass123!", [roles_by_name["Viewer"]], False),
            ]
            for email, name, pwd, r_list, active in users_seed:
                if not _init_session.query(User).filter(User.email == email).first():
                    u = User(
                        email=email,
                        full_name=name,
                        password_hash=hash_password(pwd),
                        is_active=active,
                        is_verified=True,
                        created_at=now,
                        updated_at=now,
                        roles=r_list,
                    )
                    _init_session.add(u)

            from app.models.attack import AttackTechnique, AttackTactic
            if not _init_session.query(AttackTechnique).filter(AttackTechnique.technique_id == "T1078").first():
                tac = AttackTactic(
                    stix_id="x-mitre-tactic--init",
                    external_id="TA0001",
                    short_name="initial-access",
                    name="Initial Access",
                )
                _init_session.add(tac)
                t1078 = AttackTechnique(
                    stix_id="attack-pattern--t1078",
                    technique_id="T1078",
                    name="Valid Accounts",
                    description="Adversaries may obtain and abuse credentials.",
                    url="https://attack.mitre.org/techniques/T1078",
                    is_subtechnique=False,
                    is_identity_relevant=True,
                    tactics=[tac],
                )
                t1078_004 = AttackTechnique(
                    stix_id="attack-pattern--t1078-004",
                    technique_id="T1078.004",
                    name="Valid Accounts: Cloud Accounts",
                    description="Adversaries may obtain and abuse credentials of cloud accounts.",
                    url="https://attack.mitre.org/techniques/T1078/004/",
                    is_subtechnique=True,
                    parent_technique_id="T1078",
                    is_identity_relevant=True,
                    tactics=[tac],
                )
                t1003 = AttackTechnique(
                    stix_id="attack-pattern--t1003",
                    technique_id="T1003",
                    name="OS Credential Dumping",
                    description="Dumping credentials.",
                    url="https://attack.mitre.org/techniques/T1003",
                    is_subtechnique=False,
                    is_identity_relevant=True,
                    tactics=[tac],
                )
                t1003_001 = AttackTechnique(
                    stix_id="attack-pattern--t1003-001",
                    technique_id="T1003.001",
                    name="OS Credential Dumping: LSASS Memory",
                    description="Dumping credentials from LSASS.",
                    url="https://attack.mitre.org/techniques/T1003/001/",
                    is_subtechnique=True,
                    parent_technique_id="T1003",
                    is_identity_relevant=True,
                    tactics=[tac],
                )
                _init_session.add_all([t1078, t1078_004, t1003, t1003_001])

            from app.models.d3fend import D3fendTechnique
            if not _init_session.query(D3fendTechnique).filter(D3fendTechnique.d3fend_id == "D3-MFA").first():
                d3f_mfa = D3fendTechnique(
                    d3fend_id="D3-MFA",
                    name="Multi-Factor Authentication",
                    definition="Multi-factor authentication countermeasure.",
                    url="https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication",
                )
                _init_session.add(d3f_mfa)

            from app.models.rag import RagDocument
            if not _init_session.query(RagDocument).filter(RagDocument.chunk_id == "chunk-test-t1078").first():
                rag_doc = RagDocument(
                    chunk_id="chunk-test-t1078",
                    source_kind="attack",
                    document_type="technique",
                    source_object_id="attack-pattern--t1078",
                    external_id="T1078",
                    title="Valid Accounts",
                    content="Adversaries may obtain and abuse credentials of existing accounts.",
                    url="https://attack.mitre.org/techniques/T1078",
                    version="1.0",
                    metadata_json={},
                    content_hash="test-hash-1234",
                    embedding_model="offline-bge-384",
                    embedding=[0.1] * 384,
                )
                _init_session.add(rag_doc)

            _init_session.commit()

        # Seed demo data for tests requiring detection rules, threat feeds, and scenarios
        try:
            from scripts.seed_demo_data import seed as _seed_demo
            _seed_demo()
        except Exception as _e:
            logger.warning(f"Could not seed demo data in SQLite: {_e}")
    except Exception as exc:
        logger.warning(f"Could not auto-create SQLite schema: {exc}")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to provide a transactional database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_health() -> Dict[str, Any]:
    """
    Verify database connectivity and check whether the pgvector extension is enabled.
    Returns diagnostic telemetry for system health indicators.
    """
    start = time.perf_counter()
    status = {
        "connected": False,
        "database_type": "SQLite" if is_sqlite else "PostgreSQL",
        "is_neon": settings.is_neon if not is_sqlite else False,
        "pgvector_enabled": False,
        "latency_ms": 0.0,
        "version": None,
        "error": None,
    }

    try:
        with engine.connect() as conn:
            if is_sqlite:
                ver_res = conn.execute(text("SELECT sqlite_version();")).scalar()
                status["version"] = f"SQLite {ver_res}"
                status["connected"] = True
                status["pgvector_enabled"] = False
            else:
                # Query database version
                ver_res = conn.execute(text("SELECT version();")).scalar()
                status["version"] = ver_res
                status["connected"] = True

                # Query pgvector extension
                vec_res = conn.execute(
                    text("SELECT 1 FROM pg_extension WHERE extname = 'vector';")
                ).scalar()
                status["pgvector_enabled"] = bool(vec_res)

        status["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        status["error"] = str(exc)
        status["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)

    return status
