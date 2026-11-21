"""phase7 tenants, workspaces, virtual_api_keys, plugin_configs tables

Revision ID: 0004_phase7_tenants_virtual_keys_plugins
Revises: 0003_phase6_auth_users
Create Date: 2026-11-21 20:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0004_phase7_tenants_virtual_keys_plugins"
down_revision: Union[str, None] = "0003_phase6_auth_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. tenants table
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )

    # 2. workspaces table
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="dev"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_tenant_workspace_name"),
    )
    op.create_index("ix_workspaces_tenant_id", "workspaces", ["tenant_id"])

    # 3. virtual_api_keys table
    op.create_table(
        "virtual_api_keys",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="Auditor"),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="dev"),
        sa.Column("default_policy_pack_id", sa.String(length=64), nullable=False, server_default="base-enterprise"),
        sa.Column("allowed_models", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("budget_cap_usd", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("rate_limit_rpm", sa.Integer(), nullable=False, server_default="600"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_virtual_api_keys_tenant_id", "virtual_api_keys", ["tenant_id"])
    op.create_index("ix_virtual_api_keys_workspace_id", "virtual_api_keys", ["workspace_id"])
    op.create_index("ix_virtual_api_keys_key_prefix", "virtual_api_keys", ["key_prefix"])
    op.create_index("ix_virtual_api_keys_key_hash", "virtual_api_keys", ["key_hash"])

    # 4. plugin_configs table
    op.create_table(
        "plugin_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("plugin_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("is_instance", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "workspace_id", "name", name="uq_tenant_plugin_name"),
    )
    op.create_index("ix_plugin_configs_tenant_id", "plugin_configs", ["tenant_id"])
    op.create_index("ix_plugin_configs_workspace_id", "plugin_configs", ["workspace_id"])
    op.create_index("ix_plugin_configs_name", "plugin_configs", ["name"])


def downgrade() -> None:
    op.drop_table("plugin_configs")
    op.drop_table("virtual_api_keys")
    op.drop_table("workspaces")
    op.drop_table("tenants")
