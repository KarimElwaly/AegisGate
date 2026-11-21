"""phase10 discovered_assets table for Shadow AI auto-discovery

Revision ID: 0006_phase10_shadow_discovery
Revises: 0005_phase8_mcp_and_taints
Create Date: 2026-11-21 21:30:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006_phase10_shadow_discovery"
down_revision: Union[str, None] = "0005_phase8_mcp_and_taints"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "discovered_assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("risk_level", sa.String(length=16), nullable=False, server_default="medium"),
        sa.Column("governance_status", sa.String(length=32), nullable=False, server_default="shadow_unapproved"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "workspace_id", "asset_type", "name", name="uq_discovered_asset"),
    )
    op.create_index("ix_discovered_assets_tenant_id", "discovered_assets", ["tenant_id"])
    op.create_index("ix_discovered_assets_workspace_id", "discovered_assets", ["workspace_id"])
    op.create_index("ix_discovered_assets_asset_type", "discovered_assets", ["asset_type"])
    op.create_index("ix_discovered_assets_name", "discovered_assets", ["name"])


def downgrade() -> None:
    op.drop_table("discovered_assets")

