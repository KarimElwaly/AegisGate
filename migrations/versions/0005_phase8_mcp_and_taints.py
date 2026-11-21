"""phase8 upstream_mcp_servers and mcp_tool_pins tables

Revision ID: 0005_phase8_mcp_and_taints
Revises: 0004_phase7_tenants_virtual_keys_plugins
Create Date: 2026-11-21 21:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0005_phase8_mcp_and_taints"
down_revision: Union[str, None] = "0004_phase7_tenants_virtual_keys_plugins"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. upstream_mcp_servers table
    op.create_table(
        "upstream_mcp_servers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("server_url", sa.String(length=512), nullable=False),
        sa.Column("auth_headers_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "workspace_id", "name", name="uq_tenant_mcp_server_name"),
    )
    op.create_index("ix_upstream_mcp_servers_tenant_id", "upstream_mcp_servers", ["tenant_id"])
    op.create_index("ix_upstream_mcp_servers_workspace_id", "upstream_mcp_servers", ["workspace_id"])

    # 2. mcp_tool_pins table
    op.create_table(
        "mcp_tool_pins",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("server_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("schema_hash", sa.String(length=64), nullable=False),
        sa.Column("description_hash", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("input_schema_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_quarantined", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "workspace_id", "tool_name", name="uq_tenant_mcp_tool_pin"),
    )
    op.create_index("ix_mcp_tool_pins_tenant_id", "mcp_tool_pins", ["tenant_id"])
    op.create_index("ix_mcp_tool_pins_workspace_id", "mcp_tool_pins", ["workspace_id"])
    op.create_index("ix_mcp_tool_pins_tool_name", "mcp_tool_pins", ["tool_name"])


def downgrade() -> None:
    op.drop_table("mcp_tool_pins")
    op.drop_table("upstream_mcp_servers")

