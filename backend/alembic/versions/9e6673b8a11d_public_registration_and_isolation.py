"""Public registration, email verification, multi-tenant report isolation, and Demo Analyst role

Revision ID: 9e6673b8a11d
Revises: 8d5562a6f00c
Create Date: 2026-11-08 05:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column


# revision identifiers, used by Alembic.
revision: str = '9e6673b8a11d'
down_revision: Union[str, None] = '8d5562a6f00c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create email_verification_tokens table
    op.create_table(
        'email_verification_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_verification_tokens_expires_at'), 'email_verification_tokens', ['expires_at'], unique=False)
    op.create_index(op.f('ix_email_verification_tokens_token_hash'), 'email_verification_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_email_verification_tokens_user_id'), 'email_verification_tokens', ['user_id'], unique=False)

    # 2. Add created_by_user_id to threat_analysis_reports
    op.add_column(
        'threat_analysis_reports',
        sa.Column('created_by_user_id', sa.Integer(), nullable=True)
    )
    op.create_foreign_key(
        'fk_threat_analysis_reports_created_by_user_id',
        'threat_analysis_reports', 'users',
        ['created_by_user_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index(
        op.f('ix_threat_analysis_reports_created_by_user_id'),
        'threat_analysis_reports',
        ['created_by_user_id'],
        unique=False
    )

    # 3. Add created_by_user_id to threat_feeds
    op.add_column(
        'threat_feeds',
        sa.Column('created_by_user_id', sa.Integer(), nullable=True)
    )
    op.create_foreign_key(
        'fk_threat_feeds_created_by_user_id',
        'threat_feeds', 'users',
        ['created_by_user_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index(
        op.f('ix_threat_feeds_created_by_user_id'),
        'threat_feeds',
        ['created_by_user_id'],
        unique=False
    )

    # 4. Seed Demo Analyst Role (id=4)
    roles_table = table(
        'roles',
        column('id', sa.Integer),
        column('name', sa.String),
        column('description', sa.String),
    )
    role_permissions_table = table(
        'role_permissions',
        column('role_id', sa.Integer),
        column('permission_id', sa.Integer),
    )

    op.execute("""
        INSERT INTO roles (id, name, description)
        VALUES (4, 'Demo Analyst', 'Public portfolio demo analyst with bounded threat modeling capabilities')
        ON CONFLICT (name) DO NOTHING;
    """)

    # Grant Demo Analyst permissions:
    # 2: threats:analyze, 3: threats:read, 5: feeds:read, 6: rag:search, 7: rag:read, 9: dashboard:read, 10: matrix:read
    # Excludes: 1 (users:manage), 4 (feeds:ingest), 8 (system:status)
    op.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT 4, p.id FROM permissions p
        WHERE p.id IN (2, 3, 5, 6, 7, 9, 10)
        ON CONFLICT DO NOTHING;
    """)


def downgrade() -> None:
    # Remove Demo Analyst role permissions and role
    op.execute("DELETE FROM role_permissions WHERE role_id = 4;")
    op.execute("DELETE FROM roles WHERE id = 4 OR name = 'Demo Analyst';")

    # Drop created_by_user_id from threat_feeds
    op.drop_index(op.f('ix_threat_feeds_created_by_user_id'), table_name='threat_feeds')
    op.drop_constraint('fk_threat_feeds_created_by_user_id', 'threat_feeds', type_='foreignkey')
    op.drop_column('threat_feeds', 'created_by_user_id')

    # Drop created_by_user_id from threat_analysis_reports
    op.drop_index(op.f('ix_threat_analysis_reports_created_by_user_id'), table_name='threat_analysis_reports')
    op.drop_constraint('fk_threat_analysis_reports_created_by_user_id', 'threat_analysis_reports', type_='foreignkey')
    op.drop_column('threat_analysis_reports', 'created_by_user_id')

    # Drop email_verification_tokens table
    op.drop_index(op.f('ix_email_verification_tokens_user_id'), table_name='email_verification_tokens')
    op.drop_index(op.f('ix_email_verification_tokens_token_hash'), table_name='email_verification_tokens')
    op.drop_index(op.f('ix_email_verification_tokens_expires_at'), table_name='email_verification_tokens')
    op.drop_table('email_verification_tokens')
