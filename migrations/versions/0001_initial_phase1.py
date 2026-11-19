"""initial phase1 policy packs

Revision ID: 0001_initial_phase1
Revises: 
Create Date: 2026-11-19 23:30:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_phase1"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "policy_packs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="draft"),
        sa.Column("yaml_dsl", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "pack_id", "version", name="uq_tenant_pack_version"),
    )
    op.create_index("ix_policy_packs_tenant_id", "policy_packs", ["tenant_id"])
    op.create_index("ix_policy_packs_workspace_id", "policy_packs", ["workspace_id"])
    op.create_index("ix_policy_packs_pack_id", "policy_packs", ["pack_id"])
    op.create_index("ix_policy_packs_status", "policy_packs", ["status"])


def downgrade() -> None:
    op.drop_table("policy_packs")

